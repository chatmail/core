//! # Push notifications module.
//!
//! This module is responsible for Apple Push Notification Service
//! and Firebase Cloud Messaging push notifications.
//!
//! It provides [`PushSubscriber`] type
//! which holds push notification token for the device,
//! shared by all accounts.
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use base64::Engine as _;
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use rand::thread_rng;
use tokio::sync::RwLock;

use crate::context::Context;
use crate::key::DcKey;

/// Manages subscription to Apple Push Notification services.
///
/// This structure is created by account manager and is shared between accounts.
/// To enable notifications, application should request the device token as described in
/// <https://developer.apple.com/documentation/usernotifications/registering-your-app-with-apns>
/// and give it to the account manager, which will forward the token in this structure.
///
/// Each account (context) can then retrieve device token
/// from this structure and give it to the email server.
/// If email server does not support push notifications,
/// account can call `subscribe` method
/// to register device token with the heartbeat
/// notification provider server as a fallback.
#[derive(Debug, Clone, Default)]
pub struct PushSubscriber {
    inner: Arc<RwLock<PushSubscriberState>>,
}

/// The key was generated with
/// `rsop generate-key --profile rfc9580`
/// and public key was extracted with `rsop extract-cert`.
const NOTIFIERS_PUBLIC_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGZ03cdhsAAAAg6PasQQylEuWAp9N5PXN93rqjZdqOqN3s9RJEU/K8FZzCsAYf
GwoAAABBBQJnTdx2AhsDAh4JCAsJCAcKDQwLBRUKCQgLAhYCIiEGiJJktnCmEtXa
qsSIGRJtupMnxycz/yT0xZK9ez+YkmIAAAAAUfgg/sg0sR2mytzADFBpNAaY0Hyu
aru8ics3eUkeNn2ziL4ZsIMx+4mcM5POvD0PG9LtH8Rz/y9iItD0c2aoRBab7iri
/gDm6aQuj3xXgtAiXdaN9s+QPxR9gY/zG1t9iXgBzioGZ03cdhkAAAAgwJ0wQFsk
MGH4jklfK1fFhYoQZMjEFCRBIk+r1S+WaSDClQYYGwgAAAAsBQJnTdx2AhsMIiEG
iJJktnCmEtXaqsSIGRJtupMnxycz/yT0xZK9ez+YkmIAAAAKCRCIkmS2cKYS1WdP
EFerccH2BoIPNbrxi6hwvxxy7G1mHg//ofD90fqmeY9xTfKMYl16bqQh4R1PiYd5
LMc5VqgXHgioqTYKbltlOtWC+HDt/PrymQsN4q/aEmsM
=5jvt
-----END PGP PUBLIC KEY BLOCK-----";

/// Pads the token with spaces.
///
/// This makes it impossible to tell
/// if the user is an Apple user with shorter tokens
/// or FCM user with longer tokens by the length of ciphertext.
fn pad_device_token(s: &str) -> String {
    // 512 is larger than any token, tokens seen so far have not been larger than 200 bytes.
    let expected_len: usize = 512;
    let payload_len = s.len();
    let padding_len = expected_len.saturating_sub(payload_len);
    let padding = " ".repeat(padding_len);
    let res = format!("{s}{padding}");
    debug_assert_eq!(res.len(), expected_len);
    res
}

/// Encrypts device token with OpenPGP.
///
/// The result is base64-encoded and not ASCII armored to avoid dealing with newlines.
pub(crate) fn encrypt_device_token(device_token: &str) -> Result<String> {
    let public_key = pgp::composed::SignedPublicKey::from_asc(NOTIFIERS_PUBLIC_KEY)?.0;
    let encryption_subkey = public_key
        .public_subkeys
        .first()
        .context("No encryption subkey found")?;
    let padded_device_token = pad_device_token(device_token);
    let mut rng = thread_rng();

    let mut msg = pgp::composed::MessageBuilder::from_bytes("", padded_device_token).seipd_v2(
        &mut rng,
        SymmetricKeyAlgorithm::AES128,
        AeadAlgorithm::Ocb,
        ChunkSize::C8KiB,
    );
    msg.encrypt_to_key(&mut rng, &encryption_subkey)?;
    let encoded_message = msg.to_vec(&mut rng)?;

    Ok(format!(
        "openpgp:{}",
        base64::engine::general_purpose::STANDARD.encode(encoded_message)
    ))
}

impl PushSubscriber {
    /// Creates new push notification subscriber.
    pub(crate) fn new() -> Self {
        Default::default()
    }

    /// Sets device token for Apple Push Notification service
    /// or Firebase Cloud Messaging.
    pub(crate) async fn set_device_token(&self, token: &str) {
        self.inner.write().await.device_token = Some(token.to_string());
    }

    /// Retrieves device token.
    ///
    /// The token is encrypted with OpenPGP.
    ///
    /// Token may be not available if application is not running on Apple platform,
    /// does not have Google Play services,
    /// failed to register for remote notifications or is in the process of registering.
    ///
    /// IMAP loop should periodically check if device token is available
    /// and send the token to the email server if it supports push notifications.
    pub(crate) async fn device_token(&self) -> Option<String> {
        self.inner.read().await.device_token.clone()
    }

    /// Subscribes for heartbeat notifications with previously set device token.
    #[cfg(target_os = "ios")]
    pub(crate) async fn subscribe(&self, context: &Context) -> Result<()> {
        use crate::net::http;

        let mut state = self.inner.write().await;

        if state.heartbeat_subscribed {
            return Ok(());
        }

        let Some(ref token) = state.device_token else {
            return Ok(());
        };

        if http::post_string(
            context,
            "https://notifications.delta.chat/register",
            format!("{{\"token\":\"{token}\"}}"),
        )
        .await?
        {
            state.heartbeat_subscribed = true;
        }
        Ok(())
    }

    /// Placeholder to skip subscribing to heartbeat notifications outside iOS.
    #[cfg(not(target_os = "ios"))]
    pub(crate) async fn subscribe(&self, _context: &Context) -> Result<()> {
        let mut state = self.inner.write().await;
        state.heartbeat_subscribed = true;
        Ok(())
    }

    pub(crate) async fn heartbeat_subscribed(&self) -> bool {
        self.inner.read().await.heartbeat_subscribed
    }
}

#[derive(Debug, Default)]
pub(crate) struct PushSubscriberState {
    /// Device token.
    device_token: Option<String>,

    /// If subscribed to heartbeat push notifications.
    heartbeat_subscribed: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(i8)]
pub enum NotifyState {
    /// Not subscribed to push notifications.
    #[default]
    NotConnected = 0,

    /// Subscribed to heartbeat push notifications.
    Heartbeat = 1,

    /// Subscribed to push notifications for new messages.
    Connected = 2,
}

impl Context {
    /// Returns push notification subscriber state.
    pub async fn push_state(&self) -> NotifyState {
        if self.push_subscribed.load(Ordering::Relaxed) {
            NotifyState::Connected
        } else if self.push_subscriber.heartbeat_subscribed().await {
            NotifyState::Heartbeat
        } else {
            NotifyState::NotConnected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_set_device_token() {
        let push_subscriber = PushSubscriber::new();
        assert_eq!(push_subscriber.device_token().await, None);

        push_subscriber.set_device_token("some-token").await;
        let device_token = push_subscriber.device_token().await.unwrap();
        assert_eq!(device_token, "some-token");
    }

    #[test]
    fn test_pad_device_token() {
        let apple_token = "0155b93b7eb867a0d8b7328b978bb15bf22f70867e39e168d03f199af9496894";
        assert_eq!(pad_device_token(apple_token).trim(), apple_token);
    }

    #[test]
    fn test_encrypt_device_token() {
        let fcm_token = encrypt_device_token("fcm-chat.delta:c67DVcpVQN2rJHiSszKNDW:APA91bErcJV2b8qG0IT4aiuCqw6Al0_SbydSuz3V0CHBR1X7Fp8YzyvlpxNZIOGYVDFKejZGE1YiGSaqxmkr9ds0DuALmZNDwqIhuZWGKKrs3r7DTSkQ9MQ").unwrap();
        let fcm_beta_token = encrypt_device_token("fcm-chat.delta.beta:chu-GhZCTLyzq1XseJp3na:APA91bFlsfDawdszWTyOLbxBy7KeRCrYM-SBFqutebF5ix0EZKMuCFUT_Y7R7Ex_eTQG_LbOu3Ky_z5UlTMJtI7ufpIp5wEvsFmVzQcOo3YhrUpbiSVGIlk").unwrap();
        let apple_token = encrypt_device_token(
            "0155b93b7eb867a0d8b7328b978bb15bf22f70867e39e168d03f199af9496894",
        )
        .unwrap();

        assert_eq!(fcm_token.len(), fcm_beta_token.len());
        assert_eq!(apple_token.len(), fcm_token.len());
    }
}
