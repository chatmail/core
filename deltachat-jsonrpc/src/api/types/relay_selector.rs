use serde::Serialize;
use typescript_type_def::TypeDef;

/// The relay selector script and its persistent state.
#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RelaySelector {
    /// Source code of the relay selector script, if one is installed.
    pub script: Option<String>,

    /// Persistent state of the relay selector script, as a JSON string.
    pub state: String,
}
