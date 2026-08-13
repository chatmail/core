use deltachat::appversions::AppSource;
use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef;

/// Version information of a single source of a client, eg. "gplay" or "fdroid".
#[derive(Serialize, Deserialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "AppSource", rename_all = "camelCase")]
pub struct JsonrpcAppSource {
    /// Always increasing version number.
    pub version_integer: u32,

    /// Any version string.
    pub version_string: String,

    /// Where to download that version.
    /// Security note: consumers need to verify themselves
    /// that downloaded app files are valid before installing them.
    pub download_url: String,
}

impl JsonrpcAppSource {
    pub fn from_core_type(source: AppSource) -> Self {
        JsonrpcAppSource {
            version_integer: source.version_integer,
            version_string: source.version_string,
            download_url: source.download_url,
        }
    }
}
