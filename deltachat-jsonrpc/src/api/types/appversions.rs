use anyhow::Result;
use deltachat::appversions::AppVersionInfo;
use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef;

/// Version information of clients.
#[derive(Serialize, Deserialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "AppVersionInfo", rename_all = "camelCase")]
pub struct JsonrpcAppVersionInfo {
    /// Array of clients with version information.
    pub clients: Vec<JsonrpcAppClient>,
}

/// Version information of a single client, eg. "deltachat" or "ubuntutouch".
#[derive(Serialize, Deserialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "AppClient", rename_all = "camelCase")]
pub struct JsonrpcAppClient {
    /// ID how the client identifies itself, eg. "deltachat" or "ubuntutouch".
    pub client_id: String,

    /// Array of sources for that client.
    pub sources: Vec<JsonrpcAppSource>,
}

/// Version information of a single source of a client, eg. "gplay" or "fdroid".
#[derive(Serialize, Deserialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "AppSource", rename_all = "camelCase")]
pub struct JsonrpcAppSource {
    /// ID how the client identifies a source, eg. "gplay" or "fdroid".
    pub app_id: String,

    /// Always increasing version number.
    pub version_integer: u32,

    /// Any version string.
    pub version_string: String,

    /// Where to download that version.
    pub download_url: String,
}

impl JsonrpcAppVersionInfo {
    pub fn from_core_type(info: AppVersionInfo) -> Result<Self> {
        let value = serde_json::to_value(info)?;
        Ok(serde_json::from_value(value)?)
    }
}
