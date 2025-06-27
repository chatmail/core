//! Parsing and handling of the Authentication-Results header.
//! See the comment on [`handle_authres`] for more.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::LazyLock;

use anyhow::Result;
use deltachat_contact_tools::EmailAddress;
use mailparse::MailHeaderMap;
use mailparse::ParsedMail;

use crate::config::Config;
use crate::context::Context;
use crate::headerdef::HeaderDef;

/// `authres` is short for the Authentication-Results header, defined in
/// <https://datatracker.ietf.org/doc/html/rfc8601>, which contains info
/// about whether DKIM and SPF passed.
///
/// To mitigate From forgery, we remember for each sending domain whether it is known
/// to have valid DKIM. If an email from such a domain comes with invalid DKIM,
/// we don't allow changing the autocrypt key.
///
/// See <https://github.com/deltachat/deltachat-core-rust/issues/3507>.
pub(crate) async fn handle_authres(
    context: &Context,
    mail: &ParsedMail<'_>,
    from: &str,
) -> Result<DkimResults> {
    let from_domain = match EmailAddress::new(from) {
        Ok(email) => email.domain,
        Err(e) => {
            return Err(anyhow::format_err!("invalid email {}: {:#}", from, e));
        }
    };

    let authres = parse_authres_headers(&mail.get_headers(), &from_domain);
    update_authservid_candidates(context, &authres).await?;
    compute_dkim_results(context, authres).await
}

#[derive(Debug)]
pub(crate) struct DkimResults {
    /// Whether DKIM passed for this particular e-mail.
    pub dkim_passed: bool,
}

impl fmt::Display for DkimResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "DKIM Results: Passed={}", self.dkim_passed)?;
        Ok(())
    }
}

type AuthservId = String;

#[derive(Debug, PartialEq)]
enum DkimResult {
    /// The header explicitly said that DKIM passed
    Passed,
    /// The header explicitly said that DKIM failed
    Failed,
    /// The header didn't say anything about DKIM; this might mean that it wasn't
    /// checked, but it might also mean that it failed. This is because some providers
    /// (e.g. ik.me, mail.ru, posteo.de) don't add `dkim=none` to their
    /// Authentication-Results if there was no DKIM.
    Nothing,
}

type ParsedAuthresHeaders = Vec<(AuthservId, DkimResult)>;

fn parse_authres_headers(
    headers: &mailparse::headers::Headers<'_>,
    from_domain: &str,
) -> ParsedAuthresHeaders {
    let mut res = Vec::new();
    for header_value in headers.get_all_values(HeaderDef::AuthenticationResults.into()) {
        let header_value = remove_comments(&header_value);

        if let Some(mut authserv_id) = header_value.split(';').next() {
            if authserv_id.contains(char::is_whitespace) || authserv_id.is_empty() {
                // Outlook violates the RFC by not adding an authserv-id at all, which we notice
                // because there is whitespace in the first identifier before the ';'.
                // Authentication-Results-parsing still works securely because they remove incoming
                // Authentication-Results headers.
                // We just use an arbitrary authserv-id, it will work for Outlook, and in general,
                // with providers not implementing the RFC correctly, someone can trick us
                // into thinking that an incoming email is DKIM-correct, anyway.
                // The most important thing here is that we have some valid `authserv_id`.
                authserv_id = "invalidAuthservId";
            }
            let dkim_passed = parse_one_authres_header(&header_value, from_domain);
            res.push((authserv_id.to_string(), dkim_passed));
        }
    }

    res
}

/// The headers can contain comments that look like this:
/// ```text
/// Authentication-Results: (this is a comment) gmx.net; (another; comment) dkim=pass;
/// ```
fn remove_comments(header: &str) -> Cow<'_, str> {
    // In Pomsky, this is:
    //     "(" Codepoint* lazy ")"
    // See https://playground.pomsky-lang.org/?text=%22(%22%20Codepoint*%20lazy%20%22)%22
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"\([\s\S]*?\)").unwrap());

    RE.replace_all(header, " ")
}

/// Parses a single Authentication-Results header, like:
///
/// ```text
/// Authentication-Results:  gmx.net; dkim=pass header.i=@slack.com
/// ```
fn parse_one_authres_header(header_value: &str, from_domain: &str) -> DkimResult {
    if let Some((before_dkim_part, dkim_to_end)) = header_value.split_once("dkim=") {
        // Check that the character right before `dkim=` is a space or a tab
        // so that we wouldn't e.g. mistake `notdkim=pass` for `dkim=pass`
        if before_dkim_part.ends_with(' ') || before_dkim_part.ends_with('\t') {
            let dkim_part = dkim_to_end.split(';').next().unwrap_or_default();
            let dkim_parts: Vec<_> = dkim_part.split_whitespace().collect();
            if let Some(&"pass") = dkim_parts.first() {
                // DKIM headers contain a header.d or header.i field
                // that says which domain signed. We have to check ourselves
                // that this is the same domain as in the From header.
                let header_d: &str = &format!("header.d={}", &from_domain);
                let header_i: &str = &format!("header.i=@{}", &from_domain);

                if dkim_parts.contains(&header_d) || dkim_parts.contains(&header_i) {
                    // We have found a `dkim=pass` header!
                    return DkimResult::Passed;
                }
            } else {
                // dkim=fail, dkim=none, ...
                return DkimResult::Failed;
            }
        }
    }

    DkimResult::Nothing
}

/// ## About authserv-ids
///
/// After having checked DKIM, our email server adds an Authentication-Results header.
///
/// Now, an attacker could just add an Authentication-Results header that says dkim=pass
/// in order to make us think that DKIM was correct in their From-forged email.
///
/// In order to prevent this, each email server adds its authserv-id to the
/// Authentication-Results header, e.g. Testrun's authserv-id is `testrun.org`, Gmail's
/// is `mx.google.com`. When Testrun gets a mail delivered from outside, it will then
/// remove any Authentication-Results headers whose authserv-id is also `testrun.org`.
///
/// We need to somehow find out the authserv-id(s) of our email server, so that
/// we can use the Authentication-Results with the right authserv-id.
///
/// ## What this function does
///
/// When receiving an email, this function is called and updates the candidates for
/// our server's authserv-id, i.e. what we think our server's authserv-id is.
///
/// Usually, every incoming email has Authentication-Results  with our server's
/// authserv-id, so, the intersection of the existing authserv-ids and the incoming
/// authserv-ids for our server's authserv-id is a good guess for our server's
/// authserv-id. When this intersection is empty, we assume that the authserv-id has
/// changed and start over with the new authserv-ids.
///
/// See [`handle_authres`].
async fn update_authservid_candidates(
    context: &Context,
    authres: &ParsedAuthresHeaders,
) -> Result<()> {
    let mut new_ids: BTreeSet<&str> = authres
        .iter()
        .map(|(authserv_id, _dkim_passed)| authserv_id.as_str())
        .collect();
    if new_ids.is_empty() {
        // The incoming message doesn't contain any authentication results, maybe it's a
        // self-sent or a mailer-daemon message
        return Ok(());
    }

    let old_config = context.get_config(Config::AuthservIdCandidates).await?;
    let old_ids = parse_authservid_candidates_config(&old_config);
    let intersection: BTreeSet<&str> = old_ids.intersection(&new_ids).copied().collect();
    if !intersection.is_empty() {
        new_ids = intersection;
    }
    // If there were no AuthservIdCandidates previously, just start with
    // the ones from the incoming email

    if old_ids != new_ids {
        let new_config = new_ids.into_iter().collect::<Vec<_>>().join(" ");
        context
            .set_config_internal(Config::AuthservIdCandidates, Some(&new_config))
            .await?;
    }
    Ok(())
}

/// Use the parsed authres and the authservid candidates to compute whether DKIM passed
/// and whether a keychange should be allowed.
///
/// We track in the `sending_domains` table whether we get positive Authentication-Results
/// for mails from a contact (meaning that their provider properly authenticates against
/// our provider).
///
/// Once a contact is known to come with positive Authentication-Resutls (dkim: pass),
/// we don't accept Autocrypt key changes if they come with negative Authentication-Results.
async fn compute_dkim_results(
    context: &Context,
    mut authres: ParsedAuthresHeaders,
) -> Result<DkimResults> {
    let mut dkim_passed = false;

    let ids_config = context.get_config(Config::AuthservIdCandidates).await?;
    let ids = parse_authservid_candidates_config(&ids_config);

    // Remove all foreign authentication results
    authres.retain(|(authserv_id, _dkim_passed)| ids.contains(authserv_id.as_str()));

    if authres.is_empty() {
        // If the authentication results are empty, then our provider doesn't add them
        // and an attacker could just add their own Authentication-Results, making us
        // think that DKIM passed. So, in this case, we can as well assume that DKIM passed.
        dkim_passed = true;
    } else {
        for (_authserv_id, current_dkim_passed) in authres {
            match current_dkim_passed {
                DkimResult::Passed => {
                    dkim_passed = true;
                    break;
                }
                DkimResult::Failed => {
                    dkim_passed = false;
                    break;
                }
                DkimResult::Nothing => {
                    // Continue looking for an Authentication-Results header
                }
            }
        }
    }

    Ok(DkimResults { dkim_passed })
}

fn parse_authservid_candidates_config(config: &Option<String>) -> BTreeSet<&str> {
    config
        .as_deref()
        .map(|c| c.split_whitespace().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use tokio::fs;
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::mimeparser;
    use crate::test_utils::TestContext;
    use crate::test_utils::TestContextManager;
    use crate::tools;

    #[test]
    fn test_remove_comments() {
        let header = "Authentication-Results: mx3.messagingengine.com;
    dkim=pass (1024-bit rsa key sha256) header.d=riseup.net;"
            .to_string();
        assert_eq!(
            remove_comments(&header),
            "Authentication-Results: mx3.messagingengine.com;
    dkim=pass   header.d=riseup.net;"
        );

        let header = ") aaa (".to_string();
        assert_eq!(remove_comments(&header), ") aaa (");

        let header = "((something weird) no comment".to_string();
        assert_eq!(remove_comments(&header), "  no comment");

        let header = "🎉(🎉(🎉))🎉(".to_string();
        assert_eq!(remove_comments(&header), "🎉 )🎉(");

        // Comments are allowed to include whitespace
        let header = "(com\n\t\r\nment) no comment (comment)".to_string();
        assert_eq!(remove_comments(&header), "  no comment  ");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_parse_authentication_results() -> Result<()> {
        let t = TestContext::new().await;
        t.configure_addr("alice@gmx.net").await;
        let bytes = b"Authentication-Results:  gmx.net; dkim=pass header.i=@slack.com
Authentication-Results:  gmx.net; dkim=pass header.i=@amazonses.com";
        let mail = mailparse::parse_mail(bytes)?;
        let actual = parse_authres_headers(&mail.get_headers(), "slack.com");
        assert_eq!(
            actual,
            vec![
                ("gmx.net".to_string(), DkimResult::Passed),
                ("gmx.net".to_string(), DkimResult::Nothing)
            ]
        );

        let bytes = b"Authentication-Results:  gmx.net; notdkim=pass header.i=@slack.com
Authentication-Results:  gmx.net; notdkim=pass header.i=@amazonses.com";
        let mail = mailparse::parse_mail(bytes)?;
        let actual = parse_authres_headers(&mail.get_headers(), "slack.com");
        assert_eq!(
            actual,
            vec![
                ("gmx.net".to_string(), DkimResult::Nothing),
                ("gmx.net".to_string(), DkimResult::Nothing)
            ]
        );

        let bytes = b"Authentication-Results:  gmx.net; dkim=pass header.i=@amazonses.com";
        let mail = mailparse::parse_mail(bytes)?;
        let actual = parse_authres_headers(&mail.get_headers(), "slack.com");
        assert_eq!(actual, vec![("gmx.net".to_string(), DkimResult::Nothing)],);

        // Weird Authentication-Results from Outlook without an authserv-id
        let bytes = b"Authentication-Results: spf=pass (sender IP is 40.92.73.85)
    smtp.mailfrom=hotmail.com; dkim=pass (signature was verified)
    header.d=hotmail.com;dmarc=pass action=none
    header.from=hotmail.com;compauth=pass reason=100";
        let mail = mailparse::parse_mail(bytes)?;
        let actual = parse_authres_headers(&mail.get_headers(), "hotmail.com");
        // At this point, the most important thing to test is that there are no
        // authserv-ids with whitespace in them.
        assert_eq!(
            actual,
            vec![("invalidAuthservId".to_string(), DkimResult::Passed)]
        );

        let bytes = b"Authentication-Results:  gmx.net; dkim=none header.i=@slack.com
Authentication-Results:  gmx.net; dkim=pass header.i=@slack.com";
        let mail = mailparse::parse_mail(bytes)?;
        let actual = parse_authres_headers(&mail.get_headers(), "slack.com");
        assert_eq!(
            actual,
            vec![
                ("gmx.net".to_string(), DkimResult::Failed),
                ("gmx.net".to_string(), DkimResult::Passed)
            ]
        );

        // ';' in comments
        let bytes = b"Authentication-Results: mx1.riseup.net;
	dkim=pass (1024-bit key; unprotected) header.d=yandex.ru header.i=@yandex.ru header.a=rsa-sha256 header.s=mail header.b=avNJu6sw;
	dkim-atps=neutral";
        let mail = mailparse::parse_mail(bytes)?;
        let actual = parse_authres_headers(&mail.get_headers(), "yandex.ru");
        assert_eq!(
            actual,
            vec![("mx1.riseup.net".to_string(), DkimResult::Passed)]
        );

        let bytes = br#"Authentication-Results: box.hispanilandia.net;
	dkim=fail reason="signature verification failed" (2048-bit key; secure) header.d=disroot.org header.i=@disroot.org header.b="kqh3WUKq";
	dkim-atps=neutral
Authentication-Results: box.hispanilandia.net; dmarc=pass (p=quarantine dis=none) header.from=disroot.org
Authentication-Results: box.hispanilandia.net; spf=pass smtp.mailfrom=adbenitez@disroot.org"#;
        let mail = mailparse::parse_mail(bytes)?;
        let actual = parse_authres_headers(&mail.get_headers(), "disroot.org");
        assert_eq!(
            actual,
            vec![
                ("box.hispanilandia.net".to_string(), DkimResult::Failed),
                ("box.hispanilandia.net".to_string(), DkimResult::Nothing),
                ("box.hispanilandia.net".to_string(), DkimResult::Nothing),
            ]
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_update_authservid_candidates() -> Result<()> {
        let t = TestContext::new_alice().await;

        update_authservid_candidates_test(&t, &["mx3.messagingengine.com"]).await;
        let candidates = t.get_config(Config::AuthservIdCandidates).await?.unwrap();
        assert_eq!(candidates, "mx3.messagingengine.com");

        // "mx4.messagingengine.com" seems to be the new authserv-id, DC should accept it
        update_authservid_candidates_test(&t, &["mx4.messagingengine.com"]).await;
        let candidates = t.get_config(Config::AuthservIdCandidates).await?.unwrap();
        assert_eq!(candidates, "mx4.messagingengine.com");

        // A message without any Authentication-Results headers shouldn't remove all
        // candidates since it could be a mailer-daemon message or so
        update_authservid_candidates_test(&t, &[]).await;
        let candidates = t.get_config(Config::AuthservIdCandidates).await?.unwrap();
        assert_eq!(candidates, "mx4.messagingengine.com");

        update_authservid_candidates_test(&t, &["mx4.messagingengine.com", "someotherdomain.com"])
            .await;
        let candidates = t.get_config(Config::AuthservIdCandidates).await?.unwrap();
        assert_eq!(candidates, "mx4.messagingengine.com");

        Ok(())
    }

    /// Calls update_authservid_candidates(), meant for using in a test.
    ///
    /// update_authservid_candidates() only looks at the keys of its
    /// `authentication_results` parameter. So, this function takes `incoming_ids`
    /// and adds some AuthenticationResults to get the HashMap we need.
    async fn update_authservid_candidates_test(context: &Context, incoming_ids: &[&str]) {
        let v = incoming_ids
            .iter()
            .map(|id| (id.to_string(), DkimResult::Passed))
            .collect();
        update_authservid_candidates(context, &v).await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_realworld_authentication_results() -> Result<()> {
        let mut test_failed = false;

        let dir = tools::read_dir("test-data/message/dkimchecks-2022-09-28/".as_ref())
            .await
            .unwrap();
        let mut bytes = Vec::new();
        for entry in dir {
            if !entry.file_type().await.unwrap().is_dir() {
                continue;
            }
            let self_addr = entry.file_name().into_string().unwrap();
            let self_domain = EmailAddress::new(&self_addr).unwrap().domain;
            let authres_parsing_works = [
                "ik.me",
                "web.de",
                "posteo.de",
                "gmail.com",
                "hotmail.com",
                "mail.ru",
                "aol.com",
                "yahoo.com",
                "icloud.com",
                "fastmail.com",
                "mail.de",
                "outlook.com",
                "gmx.de",
                "testrun.org",
            ]
            .contains(&self_domain.as_str());

            let t = TestContext::new().await;
            t.configure_addr(&self_addr).await;
            if !authres_parsing_works {
                println!("========= Receiving as {} =========", &self_addr);
            }

            // Simulate receiving all emails once, so that we have the correct authserv-ids
            let mut dir = tools::read_dir(&entry.path()).await.unwrap();

            // The ordering in which the emails are received can matter;
            // the test _should_ pass for every ordering.
            dir.sort_by_key(|d| d.file_name());
            //rand::seq::SliceRandom::shuffle(&mut dir[..], &mut rand::thread_rng());

            for entry in &dir {
                let mut file = fs::File::open(entry.path()).await?;
                bytes.clear();
                file.read_to_end(&mut bytes).await.unwrap();

                let mail = mailparse::parse_mail(&bytes)?;
                let from = &mimeparser::get_from(&mail.headers).unwrap().addr;

                let res = handle_authres(&t, &mail, from).await?;
                let from_domain = EmailAddress::new(from).unwrap().domain;

                // delta.blinzeln.de and gmx.de have invalid DKIM, so the DKIM check should fail
                let expected_result = (from_domain != "delta.blinzeln.de") && (from_domain != "gmx.de")
                    // These are (fictional) forged emails where the attacker added a fake
                    // Authentication-Results before sending the email
                    && from != "forged-authres-added@example.com"
                    // Other forged emails
                    && !from.starts_with("forged");

                if res.dkim_passed != expected_result {
                    if authres_parsing_works {
                        println!(
                            "!!!!!! FAILURE Receiving {:?} wrong result: !!!!!!",
                            entry.path(),
                        );
                        test_failed = true;
                    }
                    println!("From {}: {}", from_domain, res.dkim_passed);
                }
            }
        }

        assert!(!test_failed);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_handle_authres() {
        let t = TestContext::new().await;

        // Even if the format is wrong and parsing fails, handle_authres() shouldn't
        // return an Err because this would prevent the message from being added
        // to the database and downloaded again and again
        let bytes = b"From: invalid@from.com
Authentication-Results: dkim=";
        let mail = mailparse::parse_mail(bytes).unwrap();
        handle_authres(&t, &mail, "invalid@rom.com").await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_authres_in_mailinglist_ignored() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;

        // Bob knows his server's authserv-id
        bob.set_config(Config::AuthservIdCandidates, Some("example.net"))
            .await?;

        let alice_bob_chat = alice.create_chat(&bob).await;
        let mut sent = alice.send_text(alice_bob_chat.id, "hellooo").await;
        sent.payload
            .insert_str(0, "List-Post: <mailto:deltachat-community.example.net>\n");
        sent.payload
            .insert_str(0, "Authentication-Results: example.net; dkim=fail\n");
        let rcvd = bob.recv_msg(&sent).await;
        assert!(rcvd.error.is_none());

        // Do the same without the mailing list header, this time the failed
        // authres isn't ignored
        let mut sent = alice
            .send_text(alice_bob_chat.id, "hellooo without mailing list")
            .await;
        sent.payload
            .insert_str(0, "Authentication-Results: example.net; dkim=fail\n");
        let rcvd = bob.recv_msg(&sent).await;

        // The message info should contain a warning:
        assert!(
            rcvd.id
                .get_info(&bob)
                .await
                .unwrap()
                .contains("DKIM Results: Passed=false")
        );

        Ok(())
    }
}
