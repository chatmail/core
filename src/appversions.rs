//! Get version information of clients.
//!
//! Used by clients to inform about updates.
//! The version information comes in via IMAP METADATA,
//! (as JSON) and is parsed to `AppVersionInfo`.
use crate::context::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Version information of clients as used on the wire.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AppVersionInfo {
    /// Array clients with version information.
    clients: Vec<AppClient>,
}

/// Version infomation of a single client, eg. "deltachat" or "ubuntutouch".
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AppClient {
    /// ID how the client identifies itself, eg. "deltachat" or "ubuntutouch"
    client_id: String,

    /// Array of sources for that client.
    sources: Vec<AppSource>,
}

/// Version information of a single source of a client, eg. "gplay" or "fdroid".
#[derive(Debug, Default, Serialize, Deserialize)]
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

/// Get version information of a specific client and source.
///
/// If no matching version information are available, `None` is returned.
pub async fn get_app_version(
    context: &Context,
    client_id: &str,
    source_id: &str,
) -> Result<Option<AppSource>> {
    if let Some(metadata) = context.metadata.read().await.values().next()
        && let Some(json) = &metadata.app_versions
    {
        let app_versions: AppVersionInfo = serde_json::from_str(json)?;
        let app_version = app_versions
            .clients
            .into_iter()
            .find(|c| c.client_id == client_id)
            .and_then(|c| c.sources.into_iter().find(|s| s.source_id == source_id));
        return Ok(app_version);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestContextManager;

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_app_versions() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;

        let version = get_app_version(alice, "deltachat", "gplay").await?;
        assert!(version.is_none());

        Ok(())
    }
}
