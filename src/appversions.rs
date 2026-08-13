//! Get version information of clients.
//!
//! Used by clients to inform about updates.
//! The version information comes in via IMAP METADATA,
//! (as JSON) and is parsed to `AppVersionInfo`.
use crate::accounts::Accounts;
use crate::log::warn;
use anyhow::Result;
use serde::Deserialize;

/// Version information of clients as used on the wire.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AppVersionInfo {
    /// Array of clients with version information.
    clients: Vec<AppClient>,
}

/// Version information of a single client, eg. "deltachat" or "ubuntutouch".
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AppClient {
    /// ID how the client identifies itself, eg. "deltachat" or "ubuntutouch"
    client_id: String,

    /// Array of sources for that client.
    sources: Vec<AppSource>,
}

/// Version information of a single source of a client, eg. "gplay" or "fdroid".
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSource {
    /// ID how the client identifies a source, eg. "gplay" or "fdroid"
    source_id: String,

    /// Always increasing version number.
    pub version_integer: u32,

    /// Any version string.
    pub version_string: String,

    /// Where to download that version.
    pub download_url: String,
}

/// Sanitize version string for safe display/use by UIs.
///
/// Replaces untypical characters by `-`
/// and truncates to at most 16 characters.
/// This is to avoid to inject unexpected content or long texts.
///
/// Note, that UI should still take care to not linkify versions numbers -
/// they may still look like phone numbers or IP-addresses.
fn sanitize_version_string(version_string: &str) -> String {
    version_string
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if matches!(c, 'a'..='z' | '0'..='9' | '.' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(16)
        .collect()
}

/// Get version information of a specific client and source.
///
/// Iterates over all accounts and all transports,
/// checking version information set by IMAP METADATA,
/// and returns the source with the highest `version_integer`.
///
/// If no matching version information is available at all, `None` is returned.
pub async fn get_app_version(
    accounts: &Accounts,
    client_id: &str,
    source_id: &str,
) -> Result<Option<AppSource>> {
    let mut best: Option<AppSource> = None;

    for account_id in accounts.get_all() {
        let Some(context) = accounts.get_account(account_id) else {
            continue;
        };
        for metadata in context.metadata.read().await.values() {
            let Some(json) = &metadata.app_versions else {
                continue;
            };
            let app_versions: AppVersionInfo = match serde_json::from_str(json) {
                Ok(app_versions) => app_versions,
                Err(err) => {
                    warn!(context, "Failed to parse appversions: {err:#}.");
                    continue;
                }
            };
            let candidate = app_versions
                .clients
                .into_iter()
                .find(|c| c.client_id == client_id)
                .and_then(|c| c.sources.into_iter().find(|s| s.source_id == source_id));

            if let Some(mut candidate) = candidate
                && best
                    .as_ref()
                    .is_none_or(|b| candidate.version_integer > b.version_integer)
            {
                candidate.version_string = sanitize_version_string(&candidate.version_string);
                if candidate.version_string.is_empty() {
                    warn!(context, "version_string missing.");
                    continue;
                }
                best = Some(candidate);
            }
        }
    }

    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_sanitize_version_string() {
        assert_eq!(sanitize_version_string(""), "");
        assert_eq!(sanitize_version_string("\n"), "");
        assert_eq!(sanitize_version_string("2.57.0"), "2.57.0");
        assert_eq!(
            sanitize_version_string("2.57.0 whatever"),
            "2.57.0-whatever"
        );
        assert_eq!(sanitize_version_string("2.57.0-RC1"), "2.57.0-rc1");
        assert_eq!(sanitize_version_string(" 23.0 "), "23.0");

        assert_eq!(
            sanitize_version_string("666.999 tap https://evil.com"),
            "666.999-tap-http"
        );
        assert_eq!(sanitize_version_string("2.0<br>bla"), "2.0-br-bla");
        assert_eq!(
            sanitize_version_string("1.0\nand now let me tell the following: bar baz foo"),
            "1.0-and-now-let-"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_app_version_info_deserialize() -> Result<()> {
        let json = r##"{
            "clients": [
              {
                "clientId": "deltachat",
                "sources": [
                  {
                    "sourceId": "gplay",
                    "versionInteger": 754,
                    "versionString": "2.57.0",
                    "downloadUrl": "https://github.com/deltachat/deltachat-android/releases/download/v2.57.0/deltachat-gplay-release-2.57.0.apk"
                  }
                ]
              }
            ]
          }"##;
        let versions: AppVersionInfo = serde_json::from_str(json)?;
        assert_eq!(versions.clients.len(), 1);
        assert_eq!(versions.clients[0].client_id, "deltachat");
        assert_eq!(versions.clients[0].sources.len(), 1);
        assert_eq!(versions.clients[0].sources[0].source_id, "gplay");
        assert_eq!(versions.clients[0].sources[0].version_integer, 754);
        assert_eq!(versions.clients[0].sources[0].version_string, "2.57.0");
        assert_eq!(
            versions.clients[0].sources[0].download_url,
            "https://github.com/deltachat/deltachat-android/releases/download/v2.57.0/deltachat-gplay-release-2.57.0.apk"
        );

        // missing fields are set to defaults, additional fields are ignored, errors are errors
        let json = r##"{
            "clients": [
              {
                "clientId": "deltachat",
                "xsource": "bang"
              }
            ],
            "foo": "bar"
          }"##;
        let versions: AppVersionInfo = serde_json::from_str(json)?;
        assert_eq!(versions.clients.len(), 1);
        assert_eq!(versions.clients[0].client_id, "deltachat");
        assert_eq!(versions.clients[0].sources.len(), 0);

        let json = "{}";
        let versions: AppVersionInfo = serde_json::from_str(json)?;
        assert_eq!(versions.clients.len(), 0);

        let json = "";
        assert!(serde_json::from_str::<AppVersionInfo>(json).is_err());

        let json = "bad json";
        assert!(serde_json::from_str::<AppVersionInfo>(json).is_err());

        Ok(())
    }

    async fn mockup_app_versions(
        accounts: &Accounts,
        account_id: u32,
        transport_id: u32,
        json: &str,
    ) {
        let context = accounts.get_account(account_id).expect("account exists");
        let mut metadata = context.metadata.write().await;
        metadata.entry(transport_id).or_default().app_versions = Some(json.to_string());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_app_versions() -> Result<()> {
        let dir = tempfile::tempdir().unwrap();
        let p: PathBuf = dir.path().join("accounts");
        let writable = true;
        let mut accounts = Accounts::new(p.clone(), writable).await.unwrap();

        // no accounts configured, means no versions are reported
        let version = get_app_version(&accounts, "non-", "existant").await?;
        assert!(version.is_none());

        // first account reports two clients, with one and two sources
        let account_id1 = accounts.add_account().await?;
        let json = r##"{
            "clients": [
              {
                "clientId": "basta",
                "sources": [
                  {
                    "sourceId": "web",
                    "versionInteger": 754,
                    "versionString": "2.57.0",
                    "downloadUrl": "https://example.org/basta-2.57.0.apk"
                  }
                ]
              },
              {
                "clientId": "foo",
                "sources": [
                  {
                    "sourceId": "bar",
                    "versionInteger": 42,
                    "versionString": "42.0",
                    "downloadUrl": "https://foo.bar/42.0.prg"
                  },
                  {
                    "sourceId": "baz",
                    "versionInteger": 1337,
                    "versionString": " 13.37 ",
                    "downloadUrl": "https://dl.org/1337.acc"
                  }
                ]
              }
            ]
          }"##;
        mockup_app_versions(&accounts, account_id1, 1, json).await;

        let version = get_app_version(&accounts, "basta", "web").await?.unwrap();
        assert_eq!(version.version_integer, 754);
        assert_eq!(version.version_string, "2.57.0");
        assert_eq!(version.download_url, "https://example.org/basta-2.57.0.apk");

        let version = get_app_version(&accounts, "foo", "bar").await?.unwrap();
        assert_eq!(version.version_integer, 42);
        assert_eq!(version.version_string, "42.0");
        assert_eq!(version.download_url, "https://foo.bar/42.0.prg");

        let version = get_app_version(&accounts, "foo", "baz").await?.unwrap();
        assert_eq!(version.version_integer, 1337);
        assert_eq!(version.version_string, "13.37"); // spaces are removed by sanizize_version_string()
        assert_eq!(version.download_url, "https://dl.org/1337.acc");

        let version = get_app_version(&accounts, "non-", "existant").await?;
        assert!(version.is_none());

        // a second account reports a newer version for "bar"
        let account_id2 = accounts.add_account().await?;
        let json = r##"{
            "clients": [
              {
                "clientId": "foo",
                "sources": [
                  {
                    "sourceId": "bar",
                    "versionInteger": 43,
                    "versionString": "43.0",
                    "downloadUrl": "https://foo.bar/43.0-is-newer.prg"
                  }
                ]
              }
            ]
          }"##;
        mockup_app_versions(&accounts, account_id2, 1, json).await;

        let version = get_app_version(&accounts, "basta", "web").await?.unwrap();
        assert_eq!(version.version_integer, 754);
        assert_eq!(version.version_string, "2.57.0");
        assert_eq!(version.download_url, "https://example.org/basta-2.57.0.apk");

        let version = get_app_version(&accounts, "foo", "bar").await?.unwrap();
        assert_eq!(version.version_integer, 43);
        assert_eq!(version.version_string, "43.0");
        assert_eq!(version.download_url, "https://foo.bar/43.0-is-newer.prg");

        let version = get_app_version(&accounts, "foo", "baz").await?.unwrap();
        assert_eq!(version.version_integer, 1337);
        assert_eq!(version.version_string, "13.37");
        assert_eq!(version.download_url, "https://dl.org/1337.acc");

        let version = get_app_version(&accounts, "non-", "existant").await?;
        assert!(version.is_none());

        // a third account reports a older version for "bar", that is ignored
        let account_id3 = accounts.add_account().await?;
        let json = r##"{
            "clients": [
              {
                "clientId": "foo",
                "sources": [
                  {
                    "sourceId": "bar",
                    "versionInteger": 39,
                    "versionString": "39.0",
                    "downloadUrl": "https://foo.bar/39.0-is-too-old.prg"
                  }
                ]
              }
            ]
          }"##;
        mockup_app_versions(&accounts, account_id3, 1, json).await;

        let version = get_app_version(&accounts, "basta", "web").await?.unwrap();
        assert_eq!(version.version_integer, 754);
        assert_eq!(version.version_string, "2.57.0");
        assert_eq!(version.download_url, "https://example.org/basta-2.57.0.apk");

        let version = get_app_version(&accounts, "foo", "bar").await?.unwrap();
        assert_eq!(version.version_integer, 43);
        assert_eq!(version.version_string, "43.0");
        assert_eq!(version.download_url, "https://foo.bar/43.0-is-newer.prg");

        let version = get_app_version(&accounts, "foo", "baz").await?.unwrap();
        assert_eq!(version.version_integer, 1337);
        assert_eq!(version.version_string, "13.37");
        assert_eq!(version.download_url, "https://dl.org/1337.acc");

        let version = get_app_version(&accounts, "non-", "existant").await?;
        assert!(version.is_none());

        // second account returns an invalid json, that account is skipped, but app versionss are still gathered from the other
        let json = r"bad json!";
        mockup_app_versions(&accounts, account_id2, 1, json).await;

        let version = get_app_version(&accounts, "foo", "bar").await?.unwrap();
        assert_eq!(version.version_integer, 42);
        assert_eq!(version.version_string, "42.0");
        assert_eq!(version.download_url, "https://foo.bar/42.0.prg");

        // second account now has two transports, returning different version information in different orders
        let json = r##"{
            "clients": [
              { "clientId": "a", "sources": [{"sourceId": "a", "versionInteger": 1, "versionString": "1.0", "downloadUrl": "https://a/1.prg"}] },
              { "clientId": "b", "sources": [{"sourceId": "b", "versionInteger": 2, "versionString": "2.0", "downloadUrl": "https://b/2.prg"}] },
              { "clientId": "c", "sources": [{"sourceId": "c", "versionInteger": 2, "versionString": "2.0", "downloadUrl": "https://c/2.prg"}] }
            ]
          }"##;
        mockup_app_versions(&accounts, account_id2, 1, json).await;
        let json = r##"{
            "clients": [
              { "clientId": "a", "sources": [{"sourceId": "a", "versionInteger": 2, "versionString": "2.0", "downloadUrl": "https://a/2.prg"}] },
              { "clientId": "b", "sources": [{"sourceId": "b", "versionInteger": 1, "versionString": "1.0", "downloadUrl": "https://b/1.prg"}] },
              { "clientId": "d", "sources": [{"sourceId": "d", "versionInteger": 2, "versionString": "2.0", "downloadUrl": "https://d/2.prg"}] }
            ]
          }"##;
        mockup_app_versions(&accounts, account_id2, 2, json).await;
        let version = get_app_version(&accounts, "a", "a").await?.unwrap();
        assert_eq!(version.version_integer, 2);
        let version = get_app_version(&accounts, "b", "b").await?.unwrap();
        assert_eq!(version.version_integer, 2);
        let version = get_app_version(&accounts, "c", "c").await?.unwrap();
        assert_eq!(version.version_integer, 2);
        let version = get_app_version(&accounts, "d", "d").await?.unwrap();
        assert_eq!(version.version_integer, 2);

        Ok(())
    }
}
