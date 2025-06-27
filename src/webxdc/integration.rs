use std::path::Path;

use crate::chat::{ChatId, send_msg};
use crate::config::Config;
use crate::contact::ContactId;
use crate::context::Context;
use crate::message::{Message, MsgId, Viewtype};
use crate::param::Param;
use crate::webxdc::{StatusUpdateItem, StatusUpdateSerial, maps_integration};
use anyhow::Result;

impl Context {
    /// Sets Webxdc file as integration.
    /// `file` is the .xdc to use as Webxdc integration.
    pub async fn set_webxdc_integration(&self, file: &str) -> Result<()> {
        let chat_id = ChatId::create_for_contact(self, ContactId::SELF).await?;
        let mut msg = Message::new(Viewtype::Webxdc);
        msg.set_file_and_deduplicate(self, Path::new(&file), None, None)?;
        msg.hidden = true;
        msg.param.set_int(Param::WebxdcIntegration, 1);
        msg.param.set_int(Param::GuaranteeE2ee, 1); // needed to pass `internet_access` requirements
        send_msg(self, chat_id, &mut msg).await?;
        Ok(())
    }

    /// Returns Webxdc instance used for optional integrations.
    /// UI can open the Webxdc as usual.
    /// Returns `None` if there is no integration; the caller can add one using `set_webxdc_integration` then.
    /// `integrate_for` is the chat to get the integration for.
    pub async fn init_webxdc_integration(
        &self,
        integrate_for: Option<ChatId>,
    ) -> Result<Option<MsgId>> {
        let Some(instance_id) = self
            .get_config_parsed::<u32>(Config::WebxdcIntegration)
            .await?
        else {
            return Ok(None);
        };

        let Some(mut instance) =
            Message::load_from_db_optional(self, MsgId::new(instance_id)).await?
        else {
            return Ok(None);
        };

        if instance.viewtype != Viewtype::Webxdc {
            return Ok(None);
        }

        let integrate_for = integrate_for.unwrap_or_default().to_u32() as i32;
        if instance.param.get_int(Param::WebxdcIntegrateFor) != Some(integrate_for) {
            instance
                .param
                .set_int(Param::WebxdcIntegrateFor, integrate_for);
            instance.update_param(self).await?;
        }
        Ok(Some(instance.id))
    }

    // Check if a Webxdc shall be used as an integration and remember that.
    pub(crate) async fn update_webxdc_integration_database(
        &self,
        msg: &mut Message,
        context: &Context,
    ) -> Result<()> {
        if msg.viewtype == Viewtype::Webxdc {
            let is_integration = if msg.param.get_int(Param::WebxdcIntegration).is_some() {
                true
            } else if msg.chat_id.is_self_talk(context).await? {
                let info = msg.get_webxdc_info(context).await?;
                if info.request_integration == "map" {
                    msg.param.set_int(Param::WebxdcIntegration, 1);
                    msg.update_param(context).await?;
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if is_integration {
                self.set_config_internal(
                    Config::WebxdcIntegration,
                    Some(&msg.id.to_u32().to_string()),
                )
                .await?;
            }
        }
        Ok(())
    }

    // Intercepts sending updates from Webxdc to core.
    pub(crate) async fn intercept_send_webxdc_status_update(
        &self,
        instance: Message,
        status_update: StatusUpdateItem,
    ) -> Result<()> {
        let chat_id = instance.webxdc_integrated_for();
        maps_integration::intercept_send_update(self, chat_id, status_update).await
    }

    // Intercepts Webxdc requesting updates from core.
    pub(crate) async fn intercept_get_webxdc_status_updates(
        &self,
        instance: Message,
        last_known_serial: StatusUpdateSerial,
    ) -> Result<String> {
        let chat_id = instance.webxdc_integrated_for();
        maps_integration::intercept_get_updates(self, chat_id, last_known_serial).await
    }
}

impl Message {
    // Get chat the Webxdc is integrated for.
    // This is the chat given to `init_webxdc_integration()`.
    fn webxdc_integrated_for(&self) -> Option<ChatId> {
        let raw_id = self.param.get_int(Param::WebxdcIntegrateFor).unwrap_or(0) as u32;
        if raw_id > 0 {
            Some(ChatId::new(raw_id))
        } else {
            None
        }
    }

    // Check if the message is an actually used as Webxdc integration.
    pub(crate) async fn is_set_as_webxdc_integration(&self, context: &Context) -> Result<bool> {
        if let Some(integration_id) = context
            .get_config_parsed::<u32>(Config::WebxdcIntegration)
            .await?
        {
            Ok(integration_id == self.id.to_u32())
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::context::Context;
    use crate::message;
    use crate::message::{Message, Viewtype};
    use crate::test_utils::TestContext;
    use anyhow::Result;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_default_integrations_are_single_device() -> Result<()> {
        let t = TestContext::new_alice().await;
        t.set_config_bool(Config::BccSelf, false).await?;

        let bytes = include_bytes!("../../test-data/webxdc/minimal.xdc");
        let file = t.get_blobdir().join("maps.xdc");
        tokio::fs::write(&file, bytes).await.unwrap();
        t.set_webxdc_integration(file.to_str().unwrap()).await?;

        // default integrations are shipped with the apps and should not be sent over the wire
        let sent = t.pop_sent_msg_opt(Duration::from_secs(1)).await;
        assert!(sent.is_none());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_overwrite_default_integration() -> Result<()> {
        let t = TestContext::new_alice().await;
        let self_chat = &t.get_self_chat().await;
        assert!(t.init_webxdc_integration(None).await?.is_none());

        async fn assert_integration(t: &Context, name: &str) -> Result<()> {
            let integration_id = t.init_webxdc_integration(None).await?.unwrap();
            let integration = Message::load_from_db(t, integration_id).await?;
            let integration_info = integration.get_webxdc_info(t).await?;
            assert_eq!(integration_info.name, name);
            Ok(())
        }

        // set default integration
        let bytes = include_bytes!("../../test-data/webxdc/with-manifest-and-png-icon.xdc");
        let file = t.get_blobdir().join("maps.xdc");
        tokio::fs::write(&file, bytes).await.unwrap();
        t.set_webxdc_integration(file.to_str().unwrap()).await?;
        assert_integration(&t, "with some icon").await?;

        // send a maps.xdc with insufficient manifest
        let mut msg = Message::new(Viewtype::Webxdc);
        msg.set_file_from_bytes(
            &t,
            "mapstest.xdc",
            include_bytes!("../../test-data/webxdc/mapstest-integration-unset.xdc"),
            None,
        )?;
        t.send_msg(self_chat.id, &mut msg).await;
        assert_integration(&t, "with some icon").await?; // still the default integration

        // send a maps.xdc with manifest including the line `request_integration = "map"`
        let mut msg = Message::new(Viewtype::Webxdc);
        msg.set_file_from_bytes(
            &t,
            "mapstest.xdc",
            include_bytes!("../../test-data/webxdc/mapstest-integration-set.xdc"),
            None,
        )?;
        let sent = t.send_msg(self_chat.id, &mut msg).await;
        let info = msg.get_webxdc_info(&t).await?;
        assert!(info.summary.contains("Used as map"));
        assert_integration(&t, "Maps Test 2").await?;

        // when maps.xdc is received on another device, the integration is not accepted (needs to be forwarded again)
        let t2 = TestContext::new_alice().await;
        let msg2 = t2.recv_msg(&sent).await;
        let info = msg2.get_webxdc_info(&t2).await?;
        assert!(info.summary.contains("To use as map,"));
        assert!(t2.init_webxdc_integration(None).await?.is_none());

        // deleting maps.xdc removes the user's integration - the UI will go back to default calling set_webxdc_integration() then
        message::delete_msgs(&t, &[msg.id]).await?;
        assert!(t.init_webxdc_integration(None).await?.is_none());

        Ok(())
    }
}
