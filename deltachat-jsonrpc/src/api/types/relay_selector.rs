use serde::Serialize;
use typescript_type_def::TypeDef;

/// The relay selector script and its persistent state.
#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RelaySelector {
    /// Source code of the installed selector script.
    ///
    /// This is the built-in default script when `isDefault` is `true`.
    pub script: String,

    /// Whether the built-in default script is active.
    pub is_default: bool,

    /// Persistent state of the selector script, as a JSON string.
    pub state: String,
}
