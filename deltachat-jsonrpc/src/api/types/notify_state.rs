use deltachat::push::NotifyState;
use serde::Serialize;
use typescript_type_def::TypeDef;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "NotifyState")]
pub enum JsonrpcNotifyState {
    /// Not subscribed to push notifications.
    NotConnected,

    /// Subscribed to heartbeat push notifications.
    Heartbeat,

    /// Subscribed to push notifications for new messages.
    Connected,
}

impl From<NotifyState> for JsonrpcNotifyState {
    fn from(state: NotifyState) -> Self {
        match state {
            NotifyState::NotConnected => Self::NotConnected,
            NotifyState::Heartbeat => Self::Heartbeat,
            NotifyState::Connected => Self::Connected,
        }
    }
}
