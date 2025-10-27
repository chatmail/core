use super::*;
use crate::chat::create_group;
use crate::config::Config;
use crate::login_param::EnteredCertificateChecks;
use crate::provider::Socket;
use crate::securejoin::get_securejoin_qr;
use crate::test_utils::{TestContext, TestContextManager, sync};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_http() -> Result<()> {
    let ctx = TestContext::new().await;

    let qr = check_qr(&ctx.ctx, "http://www.hello.com:80").await?;
    assert_eq!(
        qr,
        Qr::Proxy {
            url: "http://www.hello.com:80".to_string(),
            host: "www.hello.com".to_string(),
            port: 80
        }
    );

    // If it has no explicit port, then it is not a proxy.
    let qr = check_qr(&ctx.ctx, "http://www.hello.com").await?;
    assert_eq!(
        qr,
        Qr::Url {
            url: "http://www.hello.com".to_string(),
        }
    );

    // If it has a path, then it is not a proxy.
    let qr = check_qr(&ctx.ctx, "http://www.hello.com/").await?;
    assert_eq!(
        qr,
        Qr::Url {
            url: "http://www.hello.com/".to_string(),
        }
    );
    let qr = check_qr(&ctx.ctx, "http://www.hello.com/hello").await?;
    assert_eq!(
        qr,
        Qr::Url {
            url: "http://www.hello.com/hello".to_string(),
        }
    );

    // Test that QR code whitespace is stripped.
    // Users can copy-paste QR code contents and "scan"
    // from the clipboard.
    let qr = check_qr(&ctx.ctx, "  \thttp://www.hello.com/hello  \n\t \r\n ").await?;
    assert_eq!(
        qr,
        Qr::Url {
            url: "http://www.hello.com/hello".to_string(),
        }
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_https() -> Result<()> {
    let ctx = TestContext::new().await;

    let qr = check_qr(&ctx.ctx, "https://www.hello.com:443").await?;
    assert_eq!(
        qr,
        Qr::Proxy {
            url: "https://www.hello.com:443".to_string(),
            host: "www.hello.com".to_string(),
            port: 443
        }
    );

    // If it has no explicit port, then it is not a proxy.
    let qr = check_qr(&ctx.ctx, "https://www.hello.com").await?;
    assert_eq!(
        qr,
        Qr::Url {
            url: "https://www.hello.com".to_string(),
        }
    );

    // If it has a path, then it is not a proxy.
    let qr = check_qr(&ctx.ctx, "https://www.hello.com/").await?;
    assert_eq!(
        qr,
        Qr::Url {
            url: "https://www.hello.com/".to_string(),
        }
    );
    let qr = check_qr(&ctx.ctx, "https://www.hello.com/hello").await?;
    assert_eq!(
        qr,
        Qr::Url {
            url: "https://www.hello.com/hello".to_string(),
        }
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_text() -> Result<()> {
    let ctx = TestContext::new().await;

    let qr = check_qr(&ctx.ctx, "I am so cool").await?;
    assert_eq!(
        qr,
        Qr::Text {
            text: "I am so cool".to_string()
        }
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_vcard() -> Result<()> {
    let ctx = TestContext::new().await;

    let qr = check_qr(
        &ctx.ctx,
        "BEGIN:VCARD\nVERSION:3.0\nN:Last;First\nEMAIL;TYPE=INTERNET:stress@test.local\nEND:VCARD",
    )
    .await?;

    if let Qr::Addr { contact_id, draft } = qr {
        let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
        assert_eq!(contact.get_addr(), "stress@test.local");
        assert_eq!(contact.get_name(), "First Last");
        assert_eq!(contact.get_authname(), "");
        assert_eq!(contact.get_display_name(), "First Last");
        assert!(draft.is_none());
    } else {
        bail!("Wrong QR code type");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_matmsg() -> Result<()> {
    let ctx = TestContext::new().await;

    let qr = check_qr(
        &ctx.ctx,
        "MATMSG:TO:\n\nstress@test.local ; \n\nSUB:\n\nSubject here\n\nBODY:\n\nhelloworld\n;;",
    )
    .await?;

    if let Qr::Addr { contact_id, draft } = qr {
        let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
        assert_eq!(contact.get_addr(), "stress@test.local");
        assert!(draft.is_none());
    } else {
        bail!("Wrong QR code type");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_mailto() -> Result<()> {
    let ctx = TestContext::new().await;

    let qr = check_qr(
        &ctx.ctx,
        "mailto:stress@test.local?subject=hello&body=beautiful+world",
    )
    .await?;
    if let Qr::Addr { contact_id, draft } = qr {
        let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
        assert_eq!(contact.get_addr(), "stress@test.local");
        assert_eq!(draft.unwrap(), "hello\nbeautiful world");
    } else {
        bail!("Wrong QR code type");
    }

    let res = check_qr(&ctx.ctx, "mailto:no-questionmark@example.org").await?;
    if let Qr::Addr { contact_id, draft } = res {
        let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
        assert_eq!(contact.get_addr(), "no-questionmark@example.org");
        assert!(draft.is_none());
    } else {
        bail!("Wrong QR code type");
    }

    let res = check_qr(&ctx.ctx, "mailto:no-addr").await;
    assert!(res.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_smtp() -> Result<()> {
    let ctx = TestContext::new().await;

    if let Qr::Addr { contact_id, draft } =
        check_qr(&ctx.ctx, "SMTP:stress@test.local:subjecthello:bodyworld").await?
    {
        let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
        assert_eq!(contact.get_addr(), "stress@test.local");
        assert!(draft.is_none());
    } else {
        bail!("Wrong QR code type");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_ideltachat_link() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let ctx_configured = &tcm.alice().await;

    // Explicitly test that scanning QR codes works
    // with unconfigured accounts.
    // This is needed for the flow where
    // user scans a QR code or follows invite link
    // and then creates a profile and e.g. joins a group
    // at the same time.
    let ctx_unconfigured = &tcm.unconfigured().await;

    for ctx in &[ctx_configured, ctx_unconfigured] {
        let qr = check_qr(
            ctx,
            "https://i.delta.chat/#79252762C34C5096AF57958F4FC3D21A81B0F0A7&a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL9cxRL"
        ).await?;
        assert!(matches!(qr, Qr::AskVerifyGroup { .. }));

        let qr = check_qr(
            ctx,
            "https://i.delta.chat#79252762C34C5096AF57958F4FC3D21A81B0F0A7&a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL9cxRL"
        ).await?;
        assert!(matches!(qr, Qr::AskVerifyGroup { .. }));
    }

    Ok(())
}

// macOS and iOS sometimes replace the # with %23 (uri encode it), we should be able to parse this wrong format too.
// see issue https://github.com/deltachat/deltachat-core-rust/issues/1969 for more info
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_openpgp_tolerance_for_issue_1969() -> Result<()> {
    let ctx = TestContext::new_alice().await;

    let qr = check_qr(
        &ctx.ctx,
        "OPENPGP4FPR:79252762C34C5096AF57958F4FC3D21A81B0F0A7%23a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL9cxRL"
    ).await?;

    assert!(matches!(qr, Qr::AskVerifyGroup { .. }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_openpgp_group() -> Result<()> {
    let ctx = TestContext::new_alice().await;
    let qr = check_qr(
        &ctx.ctx,
        "OPENPGP4FPR:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL9cxRL"
    ).await?;
    if let Qr::AskVerifyGroup {
        contact_id,
        grpname,
        ..
    } = qr
    {
        assert_ne!(contact_id, ContactId::UNDEFINED);
        assert_eq!(grpname, "test ? test !");
    } else {
        bail!("Wrong QR code type");
    }

    // Test it again with lowercased "openpgp4fpr:" uri scheme
    let ctx = TestContext::new_alice().await;
    let qr = check_qr(
        &ctx.ctx,
        "openpgp4fpr:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL9cxRL"
    ).await?;
    if let Qr::AskVerifyGroup {
        contact_id,
        grpname,
        ..
    } = qr
    {
        assert_ne!(contact_id, ContactId::UNDEFINED);
        assert_eq!(grpname, "test ? test !");

        let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
        assert_eq!(contact.get_addr(), "cli@deltachat.de");
    } else {
        bail!("Wrong QR code type");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_openpgp_invalid_token() -> Result<()> {
    let ctx = TestContext::new_alice().await;

    // Token cannot contain "/"
    let qr = check_qr(
        &ctx.ctx,
        "OPENPGP4FPR:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL/cxRL"
    ).await?;

    assert!(matches!(qr, Qr::FprMismatch { .. }));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_openpgp_secure_join() -> Result<()> {
    let ctx = TestContext::new_alice().await;

    let qr = check_qr(
        &ctx.ctx,
        "OPENPGP4FPR:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&n=J%C3%B6rn%20P.+P.&i=TbnwJ6lSvD5&s=0ejvbdFSQxB"
    ).await?;

    if let Qr::AskVerifyContact { contact_id, .. } = qr {
        assert_ne!(contact_id, ContactId::UNDEFINED);
    } else {
        bail!("Wrong QR code type");
    }

    // Test it again with lowercased "openpgp4fpr:" uri scheme
    let qr = check_qr(
        &ctx.ctx,
        "openpgp4fpr:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&n=J%C3%B6rn%20P.+P.&i=TbnwJ6lSvD5&s=0ejvbdFSQxB"
    ).await?;

    if let Qr::AskVerifyContact { contact_id, .. } = qr {
        let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
        assert_eq!(contact.get_addr(), "cli@deltachat.de");
        assert_eq!(contact.get_authname(), "Jörn P. P.");
        assert_eq!(contact.get_name(), "");
    } else {
        bail!("Wrong QR code type");
    }

    // Regression test
    let ctx = TestContext::new_alice().await;
    let qr = check_qr(
        &ctx.ctx,
        "openpgp4fpr:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&n=&i=TbnwJ6lSvD5&s=0ejvbdFSQxB"
    ).await?;

    if let Qr::AskVerifyContact { contact_id, .. } = qr {
        let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
        assert_eq!(contact.get_addr(), "cli@deltachat.de");
        assert_eq!(contact.get_authname(), "");
        assert_eq!(contact.get_name(), "");
    } else {
        bail!("Wrong QR code type");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_openpgp_fingerprint() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let bob = &tcm.bob().await;
    let alice = &tcm.alice().await;

    let alice_contact = bob.add_or_lookup_contact(alice).await;
    let alice_contact_id = alice_contact.id;

    let qr = check_qr(
        bob,
        "OPENPGP4FPR:1234567890123456789012345678901234567890#a=alice@example.org",
    )
    .await?;
    if let Qr::FprMismatch { contact_id, .. } = qr {
        assert_ne!(contact_id.unwrap(), alice_contact_id);
    } else {
        bail!("Wrong QR code type");
    }

    let qr = check_qr(
        bob,
        &format!(
            "OPENPGP4FPR:{}#a=alice@example.org",
            alice_contact.fingerprint().unwrap()
        ),
    )
    .await?;
    if let Qr::FprOk { contact_id, .. } = qr {
        assert_eq!(contact_id, alice_contact_id);
    } else {
        bail!("Wrong QR code type");
    }

    assert!(matches!(
        check_qr(
            bob,
            "OPENPGP4FPR:1234567890123456789012345678901234567890#a=bob@example.org",
        )
        .await?,
        Qr::FprMismatch { .. }
    ));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_openpgp_without_addr() -> Result<()> {
    let ctx = TestContext::new().await;

    let qr = check_qr(
        &ctx.ctx,
        "OPENPGP4FPR:1234567890123456789012345678901234567890",
    )
    .await?;
    assert_eq!(
        qr,
        Qr::FprWithoutAddr {
            fingerprint: "1234 5678 9012 3456 7890\n1234 5678 9012 3456 7890".to_string()
        }
    );

    // Test it again with lowercased "openpgp4fpr:" uri scheme

    let qr = check_qr(
        &ctx.ctx,
        "openpgp4fpr:1234567890123456789012345678901234567890",
    )
    .await?;
    assert_eq!(
        qr,
        Qr::FprWithoutAddr {
            fingerprint: "1234 5678 9012 3456 7890\n1234 5678 9012 3456 7890".to_string()
        }
    );

    let res = check_qr(&ctx.ctx, "OPENPGP4FPR:12345678901234567890").await;
    assert!(res.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_withdraw_verifycontact() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let qr = get_securejoin_qr(&alice, None).await?;

    // scanning own verify-contact code offers withdrawing
    assert!(matches!(
        check_qr(&alice, &qr).await?,
        Qr::WithdrawVerifyContact { .. }
    ));
    set_config_from_qr(&alice, &qr).await?;

    // scanning withdrawn verify-contact code offers reviving
    assert!(matches!(
        check_qr(&alice, &qr).await?,
        Qr::ReviveVerifyContact { .. }
    ));
    set_config_from_qr(&alice, &qr).await?;
    assert!(matches!(
        check_qr(&alice, &qr).await?,
        Qr::WithdrawVerifyContact { .. }
    ));

    // someone else always scans as ask-verify-contact
    let bob = TestContext::new_bob().await;
    assert!(matches!(
        check_qr(&bob, &qr).await?,
        Qr::AskVerifyContact { .. }
    ));
    assert!(set_config_from_qr(&bob, &qr).await.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_withdraw_verifygroup() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let chat_id = create_group(&alice, "foo").await?;
    let qr = get_securejoin_qr(&alice, Some(chat_id)).await?;

    // scanning own verify-group code offers withdrawing
    if let Qr::WithdrawVerifyGroup { grpname, .. } = check_qr(&alice, &qr).await? {
        assert_eq!(grpname, "foo");
    } else {
        bail!("Wrong QR type, expected WithdrawVerifyGroup");
    }
    set_config_from_qr(&alice, &qr).await?;

    // scanning withdrawn verify-group code offers reviving
    if let Qr::ReviveVerifyGroup { grpname, .. } = check_qr(&alice, &qr).await? {
        assert_eq!(grpname, "foo");
    } else {
        bail!("Wrong QR type, expected ReviveVerifyGroup");
    }

    // someone else always scans as ask-verify-group
    let bob = TestContext::new_bob().await;
    if let Qr::AskVerifyGroup { grpname, .. } = check_qr(&bob, &qr).await? {
        assert_eq!(grpname, "foo");
    } else {
        bail!("Wrong QR type, expected AskVerifyGroup");
    }
    assert!(set_config_from_qr(&bob, &qr).await.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_withdraw_multidevice() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice2 = &tcm.alice().await;

    alice.set_config_bool(Config::SyncMsgs, true).await?;
    alice2.set_config_bool(Config::SyncMsgs, true).await?;

    // Alice creates two QR codes on the first device:
    // group QR code and contact QR code.
    let chat_id = create_group(alice, "Group").await?;
    let chat2_id = create_group(alice, "Group 2").await?;
    let contact_qr = get_securejoin_qr(alice, None).await?;
    let group_qr = get_securejoin_qr(alice, Some(chat_id)).await?;
    let group2_qr = get_securejoin_qr(alice, Some(chat2_id)).await?;

    assert!(matches!(
        check_qr(alice, &contact_qr).await?,
        Qr::WithdrawVerifyContact { .. }
    ));
    assert!(matches!(
        check_qr(alice, &group_qr).await?,
        Qr::WithdrawVerifyGroup { .. }
    ));

    // Sync group QR codes.
    sync(alice, alice2).await;
    assert!(matches!(
        check_qr(alice2, &group_qr).await?,
        Qr::WithdrawVerifyGroup { .. }
    ));
    assert!(matches!(
        check_qr(alice2, &group2_qr).await?,
        Qr::WithdrawVerifyGroup { .. }
    ));

    // Alice creates a contact QR code on second device
    // and withdraws it.
    let contact_qr2 = get_securejoin_qr(alice2, None).await?;
    set_config_from_qr(alice2, &contact_qr2).await?;
    assert!(matches!(
        check_qr(alice2, &contact_qr2).await?,
        Qr::ReviveVerifyContact { .. }
    ));

    // Alice also withdraws second group QR code on second device.
    set_config_from_qr(alice2, &group2_qr).await?;

    // Sync messages are sent from Alice's second device to first device.
    sync(alice2, alice).await;

    // Now first device has reset all contact QR codes
    // and second group QR code,
    // but first group QR code is still valid.
    assert!(matches!(
        check_qr(alice, &contact_qr2).await?,
        Qr::ReviveVerifyContact { .. }
    ));
    assert!(matches!(
        check_qr(alice, &group_qr).await?,
        Qr::WithdrawVerifyGroup { .. }
    ));
    assert!(matches!(
        check_qr(alice, &group2_qr).await?,
        Qr::ReviveVerifyGroup { .. }
    ));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_dclogin() -> Result<()> {
    let ctx = &TestContext::new().await;

    let Qr::Login { address, options } =
        check_qr(ctx, "dclogin:username+extension@host?p=1234&v=1").await?
    else {
        unreachable!();
    };

    assert_eq!(address, "username+extension@host".to_owned());

    if let LoginOptions::V1 { ref mail_pw, .. } = options {
        assert_eq!(mail_pw, "1234");
    } else {
        bail!("wrong type")
    }

    let param = login_param_from_login_qr(&address, options)?;
    assert_eq!(param.addr, "username+extension@host");
    assert_eq!(param.imap.password, "1234");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_dclogin_advanced_options() -> Result<()> {
    let ctx = &TestContext::new().await;

    let Qr::Login { address, options } = check_qr(ctx, "dclogin:username+extension@host?p=1234&spw=4321&sh=send.host&sp=7273&su=SendUser&ih=host.tld&ip=4343&iu=user&ipw=password&is=ssl&ic=1&sc=3&ss=plain&v=1").await? else {
        unreachable!();
    };

    assert_eq!(address, "username+extension@host");

    let param = login_param_from_login_qr(&address, options)?;
    assert_eq!(param.imap.server, "host.tld");
    assert_eq!(param.imap.port, 4343);
    assert_eq!(param.imap.user, "user");

    // `p=1234` is ignored, because `ipw=password` is set
    assert_eq!(param.imap.password, "password");
    assert_eq!(param.imap.security, Socket::Ssl);

    assert_eq!(param.smtp.password, "4321");
    assert_eq!(param.smtp.server, "send.host");
    assert_eq!(param.smtp.port, 7273);
    assert_eq!(param.smtp.user, "SendUser");
    assert_eq!(param.smtp.security, Socket::Plain);

    // `sc` option is actually ignored and `ic` is used instead
    // because `smtp_certificate_checks` is deprecated.
    assert_eq!(param.certificate_checks, EnteredCertificateChecks::Strict);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_account() -> Result<()> {
    let ctx = TestContext::new().await;

    for text in [
        "DCACCOUNT:example.org",
        "dcaccount:example.org",
        "DCACCOUNT:https://example.org/new_email?t=1w_7wDjgjelxeX884x96v3",
        "dcaccount:https://example.org/new_email?t=1w_7wDjgjelxeX884x96v3",
    ] {
        let qr = check_qr(&ctx.ctx, text).await?;
        assert_eq!(
            qr,
            Qr::Account {
                domain: "example.org".to_string()
            }
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_tg_socks_proxy() -> Result<()> {
    let t = TestContext::new().await;

    let qr = check_qr(&t, "https://t.me/socks?server=84.53.239.95&port=4145").await?;
    assert_eq!(
        qr,
        Qr::Proxy {
            url: "socks5://84.53.239.95:4145".to_string(),
            host: "84.53.239.95".to_string(),
            port: 4145,
        }
    );

    let qr = check_qr(&t, "https://t.me/socks?server=foo.bar&port=123").await?;
    assert_eq!(
        qr,
        Qr::Proxy {
            url: "socks5://foo.bar:123".to_string(),
            host: "foo.bar".to_string(),
            port: 123,
        }
    );

    let qr = check_qr(&t, "https://t.me/socks?server=foo.baz").await?;
    assert_eq!(
        qr,
        Qr::Proxy {
            url: "socks5://foo.baz:1080".to_string(),
            host: "foo.baz".to_string(),
            port: 1080,
        }
    );

    let qr = check_qr(
        &t,
        "https://t.me/socks?server=foo.baz&port=12345&user=ada&pass=ms%21%2F%24",
    )
    .await?;
    assert_eq!(
        qr,
        Qr::Proxy {
            url: "socks5://ada:ms%21%2F%24@foo.baz:12345".to_string(),
            host: "foo.baz".to_string(),
            port: 12345,
        }
    );

    // wrong domain results in Qr:Url instead of Qr::Socks5Proxy
    let qr = check_qr(&t, "https://not.me/socks?noserver=84.53.239.95&port=4145").await?;
    assert_eq!(
        qr,
        Qr::Url {
            url: "https://not.me/socks?noserver=84.53.239.95&port=4145".to_string()
        }
    );

    let qr = check_qr(&t, "https://t.me/socks?noserver=84.53.239.95&port=4145").await;
    assert!(qr.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_proxy_config_from_qr() -> Result<()> {
    let t = TestContext::new().await;

    assert_eq!(t.get_config_bool(Config::ProxyEnabled).await?, false);

    let res = set_config_from_qr(&t, "https://t.me/socks?server=foo&port=666").await;
    assert!(res.is_ok());
    assert_eq!(t.get_config_bool(Config::ProxyEnabled).await?, true);
    assert_eq!(
        t.get_config(Config::ProxyUrl).await?,
        Some("socks5://foo:666".to_string())
    );

    // Test URL without port.
    //
    // Also check that whitespace is trimmed.
    let res = set_config_from_qr(&t, " https://t.me/socks?server=1.2.3.4\n").await;
    assert!(res.is_ok());
    assert_eq!(t.get_config_bool(Config::ProxyEnabled).await?, true);
    assert_eq!(
        t.get_config(Config::ProxyUrl).await?,
        Some("socks5://1.2.3.4:1080\nsocks5://foo:666".to_string())
    );

    // make sure, user&password are set when specified in the URL
    // Password is an URL-encoded "x&%$X".
    let res =
        set_config_from_qr(&t, "https://t.me/socks?server=jau&user=Da&pass=x%26%25%24X").await;
    assert!(res.is_ok());
    assert_eq!(
        t.get_config(Config::ProxyUrl).await?,
        Some(
            "socks5://Da:x%26%25%24X@jau:1080\nsocks5://1.2.3.4:1080\nsocks5://foo:666".to_string()
        )
    );

    // Scanning existing proxy brings it to the top in the list.
    let res = set_config_from_qr(&t, "https://t.me/socks?server=foo&port=666").await;
    assert!(res.is_ok());
    assert_eq!(t.get_config_bool(Config::ProxyEnabled).await?, true);
    assert_eq!(
        t.get_config(Config::ProxyUrl).await?,
        Some(
            "socks5://foo:666\nsocks5://Da:x%26%25%24X@jau:1080\nsocks5://1.2.3.4:1080".to_string()
        )
    );

    set_config_from_qr(
        &t,
        "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1",
    )
    .await?;
    assert_eq!(
        t.get_config(Config::ProxyUrl).await?,
        Some(
            "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1\nsocks5://foo:666\nsocks5://Da:x%26%25%24X@jau:1080\nsocks5://1.2.3.4:1080"
                .to_string()
        )
    );

    // SOCKS5 config does not have port 1080 explicitly specified,
    // but should bring `socks5://1.2.3.4:1080` to the top instead of creating another entry.
    set_config_from_qr(&t, "socks5://1.2.3.4").await?;
    assert_eq!(
        t.get_config(Config::ProxyUrl).await?,
        Some(
            "socks5://1.2.3.4:1080\nss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1\nsocks5://foo:666\nsocks5://Da:x%26%25%24X@jau:1080"
                .to_string()
        )
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_shadowsocks() -> Result<()> {
    let ctx = TestContext::new().await;

    let qr = check_qr(
        &ctx.ctx,
        "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1",
    )
    .await?;
    assert_eq!(
        qr,
        Qr::Proxy {
            url: "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1".to_string(),
            host: "192.168.100.1".to_string(),
            port: 8888,
        }
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_socks5() -> Result<()> {
    let ctx = TestContext::new().await;

    let qr = check_qr(&ctx.ctx, "socks5://127.0.0.1:9050").await?;
    assert_eq!(
        qr,
        Qr::Proxy {
            url: "socks5://127.0.0.1:9050".to_string(),
            host: "127.0.0.1".to_string(),
            port: 9050,
        }
    );

    Ok(())
}

/// Ensure that `DCBACKUP2` QR code does not fail to deserialize
/// because iroh changes the format of `NodeAddr`
/// as happened between iroh 0.29 and iroh 0.30 before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decode_backup() -> Result<()> {
    let ctx = TestContext::new().await;

    let qr = check_qr(&ctx, r#"DCBACKUP2:TWSv6ZjDPa5eoxkocj7xMi8r&{"node_id":"9afc1ea5b4f543e5cdd7b7a21cd26aee7c0b1e1c2af26790896fbd8932a06e1e","relay_url":null,"direct_addresses":["192.168.1.10:12345"]}"#).await?;
    assert!(matches!(qr, Qr::Backup2 { .. }));

    let qr = check_qr(&ctx, r#"DCBACKUP2:AIvFjRFBt_aMiisSZ8P33JqY&{"node_id":"buzkyd4x76w66qtanjk5fm6ikeuo4quletajowsl3a3p7l6j23pa","info":{"relay_url":null,"direct_addresses":["192.168.1.5:12345"]}}"#).await?;
    assert!(matches!(qr, Qr::Backup2 { .. }));

    let qr = check_qr(&ctx, r#"DCBACKUP9:from-the-future"#).await?;
    assert!(matches!(qr, Qr::BackupTooNew { .. }));

    let qr = check_qr(&ctx, r#"DCBACKUP99:far-from-the-future"#).await?;
    assert!(matches!(qr, Qr::BackupTooNew { .. }));

    Ok(())
}
