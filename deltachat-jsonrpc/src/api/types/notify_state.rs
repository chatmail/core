use deltachat::push::NotifyState;
use serde::Serialize;
use typescript_type_def::TypeDef;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "NotifyState")]
pub enum JsonrpcNotifyState {
    /// Not subscribed to push notifications.
    NotConnected = 0,

    /// Subscribed to heartbeat push notifications.
    Heartbeat = 1,

    /// Subscribed to push notifications for new messages.
    Connected = 2,
}

impl From<NotifyState> for JsonrpcNotifyState {
    fn from(state: NotifyState) -> Self {
        match state {
            NotifyState::NotConnected => JsonrpcNotifyState::NotConnected,
            NotifyState::Heartbeat => JsonrpcNotifyState::Heartbeat,
            NotifyState::Connected => JsonrpcNotifyState::Connected,
        }
    }
}
