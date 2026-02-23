//! OAuth 2 module.

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;

use crate::context::Context;
use crate::log::warn;
use crate::net::http::post_form;
use crate::net::read_url_blob;
use crate::provider;
use crate::provider::Oauth2Authorizer;
use crate::tools::time;

const OAUTH2_YANDEX: Oauth2 = Oauth2 {
    // see <https://tech.yandex.com/oauth/doc/dg/reference/auto-code-client-docpage/>
    client_id: "c4d0b6735fc8420a816d7e1303469341",
    get_code: "https://oauth.yandex.com/authorize?client_id=$CLIENT_ID&response_type=code&scope=mail%3Aimap_full%20mail%3Asmtp&force_confirm=true",
    init_token: "https://oauth.yandex.com/token?grant_type=authorization_code&code=$CODE&client_id=$CLIENT_ID&client_secret=58b8c6e94cf44fbe952da8511955dacf",
    refresh_token: "https://oauth.yandex.com/token?grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_id=$CLIENT_ID&client_secret=58b8c6e94cf44fbe952da8511955dacf",
    get_userinfo: None,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Oauth2 {
    client_id: &'static str,
    get_code: &'static str,
    init_token: &'static str,
    refresh_token: &'static str,
    get_userinfo: Option<&'static str>,
}

/// OAuth 2 Access Token Response
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Response {
    // Should always be there according to: <https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/>
    // but previous code handled its abscense.
    access_token: Option<String>,
    token_type: String,
    /// Duration of time the token is granted for, in seconds
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

/// Returns URL that should be opened in the browser
/// if OAuth 2 is supported for this address.
pub async fn get_oauth2_url(
    context: &Context,
    addr: &str,
    redirect_uri: &str,
) -> Result<Option<String>> {
    if let Some(oauth2) = Oauth2::from_address(addr) {
        context
            .sql
            .set_raw_config("oauth2_pending_redirect_uri", Some(redirect_uri))
            .await?;
        let oauth2_url = replace_in_uri(oauth2.get_code, "$CLIENT_ID", oauth2.client_id);
        let oauth2_url = replace_in_uri(&oauth2_url, "$REDIRECT_URI", redirect_uri);

        Ok(Some(oauth2_url))
    } else {
        Ok(None)
    }
}

#[expect(clippy::arithmetic_side_effects)]
pub(crate) async fn get_oauth2_access_token(
    context: &Context,
    addr: &str,
    code: &str,
    regenerate: bool,
) -> Result<Option<String>> {
    if let Some(oauth2) = Oauth2::from_address(addr) {
        let lock = context.oauth2_mutex.lock().await;

        // read generated token
        if !regenerate && !is_expired(context).await? {
            let access_token = context.sql.get_raw_config("oauth2_access_token").await?;
            if access_token.is_some() {
                // success
                return Ok(access_token);
            }
        }

        // generate new token: build & call auth url
        let refresh_token = context.sql.get_raw_config("oauth2_refresh_token").await?;
        let refresh_token_for = context
            .sql
            .get_raw_config("oauth2_refresh_token_for")
            .await?
            .unwrap_or_else(|| "unset".into());

        let (redirect_uri, token_url, update_redirect_uri_on_success) =
            if refresh_token.is_none() || refresh_token_for != code {
                info!(context, "Generate OAuth2 refresh_token and access_token...",);
                (
                    context
                        .sql
                        .get_raw_config("oauth2_pending_redirect_uri")
                        .await?
                        .unwrap_or_else(|| "unset".into()),
                    oauth2.init_token,
                    true,
                )
            } else {
                info!(
                    context,
                    "Regenerate OAuth2 access_token by refresh_token...",
                );
                (
                    context
                        .sql
                        .get_raw_config("oauth2_redirect_uri")
                        .await?
                        .unwrap_or_else(|| "unset".into()),
                    oauth2.refresh_token,
                    false,
                )
            };

        // to allow easier specification of different configurations,
        // token_url is in GET-method-format, sth. as <https://domain?param1=val1&param2=val2> -
        // convert this to POST-format ...
        let mut parts = token_url.splitn(2, '?');
        let post_url = parts.next().unwrap_or_default();
        let post_args = parts.next().unwrap_or_default();
        let mut post_param = HashMap::new();
        for key_value_pair in post_args.split('&') {
            let mut parts = key_value_pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let mut value = parts.next().unwrap_or_default();

            if value == "$CLIENT_ID" {
                value = oauth2.client_id;
            } else if value == "$REDIRECT_URI" {
                value = &redirect_uri;
            } else if value == "$CODE" {
                value = code;
            } else if value == "$REFRESH_TOKEN"
                && let Some(refresh_token) = refresh_token.as_ref()
            {
                value = refresh_token;
            }

            post_param.insert(key, value);
        }

        // ... and POST

        let response: Response = match post_form(context, post_url, &post_param).await {
            Ok(resp) => match serde_json::from_slice(&resp) {
                Ok(response) => response,
                Err(err) => {
                    warn!(
                        context,
                        "Failed to parse OAuth2 JSON response from {token_url}: {err:#}."
                    );
                    return Ok(None);
                }
            },
            Err(err) => {
                warn!(context, "Error calling OAuth2 at {token_url}: {err:#}.");
                return Ok(None);
            }
        };

        // update refresh_token if given, typically on the first round, but we update it later as well.
        if let Some(ref token) = response.refresh_token {
            context
                .sql
                .set_raw_config("oauth2_refresh_token", Some(token))
                .await?;
            context
                .sql
                .set_raw_config("oauth2_refresh_token_for", Some(code))
                .await?;
        }

        // after that, save the access token.
        // if it's unset, we may get it in the next round as we have the refresh_token now.
        if let Some(ref token) = response.access_token {
            context
                .sql
                .set_raw_config("oauth2_access_token", Some(token))
                .await?;
            let expires_in = response
                .expires_in
                // refresh a bit before
                .map(|t| time() + t as i64 - 5)
                .unwrap_or_else(|| 0);
            context
                .sql
                .set_raw_config_int64("oauth2_timestamp_expires", expires_in)
                .await?;

            if update_redirect_uri_on_success {
                context
                    .sql
                    .set_raw_config("oauth2_redirect_uri", Some(redirect_uri.as_ref()))
                    .await?;
            }
        } else {
            warn!(context, "Failed to find OAuth2 access token");
        }

        drop(lock);

        Ok(response.access_token)
    } else {
        warn!(context, "Internal OAuth2 error: 2");

        Ok(None)
    }
}

pub(crate) async fn get_oauth2_addr(
    context: &Context,
    addr: &str,
    code: &str,
) -> Result<Option<String>> {
    let oauth2 = match Oauth2::from_address(addr) {
        Some(o) => o,
        None => return Ok(None),
    };
    if oauth2.get_userinfo.is_none() {
        return Ok(None);
    }

    if let Some(access_token) = get_oauth2_access_token(context, addr, code, false).await? {
        let addr_out = match oauth2.get_addr(context, &access_token).await {
            Ok(addr) => addr,
            Err(err) => {
                warn!(context, "Error getting addr: {err:#}.");
                None
            }
        };
        if addr_out.is_none() {
            // regenerate
            if let Some(access_token) = get_oauth2_access_token(context, addr, code, true).await? {
                Ok(oauth2
                    .get_addr(context, &access_token)
                    .await
                    .unwrap_or_default())
            } else {
                Ok(None)
            }
        } else {
            Ok(addr_out)
        }
    } else {
        Ok(None)
    }
}

impl Oauth2 {
    #[expect(clippy::arithmetic_side_effects)]
    fn from_address(addr: &str) -> Option<Self> {
        let addr_normalized = normalize_addr(addr);
        if let Some(domain) = addr_normalized
            .find('@')
            .map(|index| addr_normalized.split_at(index + 1).1)
            && let Some(oauth2_authorizer) = provider::get_provider_info(domain)
                .and_then(|provider| provider.oauth2_authorizer.as_ref())
        {
            return Some(match oauth2_authorizer {
                Oauth2Authorizer::Yandex => OAUTH2_YANDEX,
            });
        }
        None
    }

    async fn get_addr(&self, context: &Context, access_token: &str) -> Result<Option<String>> {
        let userinfo_url = self.get_userinfo.unwrap_or("");
        let userinfo_url = replace_in_uri(userinfo_url, "$ACCESS_TOKEN", access_token);

        // should returns sth. as
        // {
        //   "id": "100000000831024152393",
        //   "email": "NAME@gmail.com",
        //   "verified_email": true,
        //   "picture": "https://lh4.googleusercontent.com/-Gj5jh_9R0BY/AAAAAAAAAAI/AAAAAAAAAAA/IAjtjfjtjNA/photo.jpg"
        // }

        let response = read_url_blob(context, &userinfo_url).await?;
        let parsed: HashMap<String, serde_json::Value> =
            serde_json::from_slice(&response.blob).context("Error getting userinfo")?;
        // CAVE: serde_json::Value.as_str() removes the quotes of json-strings
        // but serde_json::Value.to_string() does not!
        if let Some(addr) = parsed.get("email") {
            if let Some(s) = addr.as_str() {
                Ok(Some(s.to_string()))
            } else {
                warn!(context, "E-mail in userinfo is not a string: {}", addr);
                Ok(None)
            }
        } else {
            warn!(context, "E-mail missing in userinfo.");
            Ok(None)
        }
    }
}

async fn is_expired(context: &Context) -> Result<bool> {
    let expire_timestamp = context
        .sql
        .get_raw_config_int64("oauth2_timestamp_expires")
        .await?
        .unwrap_or_default();

    if expire_timestamp <= 0 {
        return Ok(false);
    }
    if expire_timestamp > time() {
        return Ok(false);
    }

    Ok(true)
}

fn replace_in_uri(uri: &str, key: &str, value: &str) -> String {
    let value_urlencoded = utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
    uri.replace(key, &value_urlencoded)
}

fn normalize_addr(addr: &str) -> &str {
    let normalized = addr.trim();
    normalized.trim_start_matches("mailto:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestContext;

    #[test]
    fn test_normalize_addr() {
        assert_eq!(normalize_addr(" hello@mail.de  "), "hello@mail.de");
        assert_eq!(normalize_addr("mailto:hello@mail.de  "), "hello@mail.de");
    }

    #[test]
    fn test_replace_in_uri() {
        assert_eq!(
            replace_in_uri("helloworld", "world", "a-b c"),
            "helloa%2Db%20c"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_oauth_from_address() {
        // Delta Chat does not have working Gmail client ID anymore.
        assert_eq!(Oauth2::from_address("hello@gmail.com"), None);
        assert_eq!(Oauth2::from_address("hello@googlemail.com"), None);

        assert_eq!(
            Oauth2::from_address("hello@yandex.com"),
            Some(OAUTH2_YANDEX)
        );
        assert_eq!(Oauth2::from_address("hello@yandex.ru"), Some(OAUTH2_YANDEX));
        assert_eq!(Oauth2::from_address("hello@web.de"), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_oauth2_addr() {
        let ctx = TestContext::new().await;
        let addr = "dignifiedquire@gmail.com";
        let code = "fail";
        let res = get_oauth2_addr(&ctx.ctx, addr, code).await.unwrap();
        // this should fail as it is an invalid password
        assert_eq!(res, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_oauth2_url() {
        let ctx = TestContext::new().await;
        let addr = "example@yandex.com";
        let redirect_uri = "chat.delta:/com.b44t.messenger";
        let res = get_oauth2_url(&ctx.ctx, addr, redirect_uri).await.unwrap();

        assert_eq!(res, Some("https://oauth.yandex.com/authorize?client_id=c4d0b6735fc8420a816d7e1303469341&response_type=code&scope=mail%3Aimap_full%20mail%3Asmtp&force_confirm=true".into()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_oauth2_token() {
        let ctx = TestContext::new().await;
        let addr = "dignifiedquire@gmail.com";
        let code = "fail";
        let res = get_oauth2_access_token(&ctx.ctx, addr, code, false)
            .await
            .unwrap();
        // this should fail as it is an invalid password
        assert_eq!(res, None);
    }
}
