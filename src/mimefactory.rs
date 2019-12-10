use chrono::TimeZone;
use lettre_email::{mime, Address, Header, MimeMultipartType, PartBuilder};

use crate::chat::{self, Chat};
use crate::config::Config;
use crate::constants::*;
use crate::contact::*;
use crate::context::{get_version_str, Context};
use crate::dc_tools::*;
use crate::e2ee::*;
use crate::error::Error;
use crate::location;
use crate::message::MsgId;
use crate::message::{self, Message};
use crate::mimeparser::SystemMessage;
use crate::param::*;
use crate::peerstate::{Peerstate, PeerstateVerifiedStatus};
use crate::stock::StockMessage;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Loaded {
    Message,
    MDN,
}

/// Helper to construct mime messages.
#[derive(Clone)]
pub struct MimeFactory<'a, 'b> {
    pub from_addr: String,
    pub from_displayname: String,
    pub selfstatus: String,
    pub recipients_names: Vec<String>,
    pub recipients_addr: Vec<String>,
    pub timestamp: i64,
    pub loaded: Loaded,
    pub msg: &'b Message,
    pub chat: Option<Chat>,
    pub increation: bool,
    pub in_reply_to: String,
    pub references: String,
    pub req_mdn: bool,
    pub context: &'a Context,
    last_added_location_id: u32,
}

/// Result of rendering a message, ready to be submitted to a send job.
#[derive(Debug, Clone)]
pub struct RenderedEmail {
    pub message: Vec<u8>,
    // pub envelope: Envelope,
    pub is_encrypted: bool,
    pub is_gossiped: bool,
    pub last_added_location_id: u32,
    /// None for MDN, the message id otherwise
    pub foreign_id: Option<MsgId>,

    pub from: String,
    pub recipients: Vec<String>,

    /// Message ID (Message in the sense of Email)
    pub rfc724_mid: String,
}

impl<'a, 'b> MimeFactory<'a, 'b> {
    pub fn from_msg(context: &'a Context, msg: &'b Message) -> Result<MimeFactory<'a, 'b>, Error> {
        let chat = Chat::load_from_db(context, msg.chat_id)?;

        let mut factory = MimeFactory {
            from_addr: context
                .get_config(Config::ConfiguredAddr)
                .unwrap_or_default(),
            from_displayname: context.get_config(Config::Displayname).unwrap_or_default(),
            selfstatus: context
                .get_config(Config::Selfstatus)
                .unwrap_or_else(|| context.stock_str(StockMessage::StatusLine).to_string()),
            recipients_names: Vec::with_capacity(5),
            recipients_addr: Vec::with_capacity(5),
            timestamp: msg.timestamp_sort,
            loaded: Loaded::Message,
            msg,
            chat: Some(chat),
            increation: msg.is_increation(),
            in_reply_to: String::default(),
            references: String::default(),
            req_mdn: false,
            last_added_location_id: 0,
            context,
        };

        // just set the chat above
        let chat = factory.chat.as_ref().unwrap();

        if chat.is_self_talk() {
            factory
                .recipients_names
                .push(factory.from_displayname.to_string());
            factory.recipients_addr.push(factory.from_addr.to_string());
        } else {
            context.sql.query_map(
                "SELECT c.authname, c.addr  \
                 FROM chats_contacts cc  \
                 LEFT JOIN contacts c ON cc.contact_id=c.id  \
                 WHERE cc.chat_id=? AND cc.contact_id>9;",
                params![factory.msg.chat_id as i32],
                |row| {
                    let authname: String = row.get(0)?;
                    let addr: String = row.get(1)?;
                    Ok((authname, addr))
                },
                |rows| {
                    for row in rows {
                        let (authname, addr) = row?;
                        if !vec_contains_lowercase(&factory.recipients_addr, &addr) {
                            factory.recipients_addr.push(addr);
                            factory.recipients_names.push(authname);
                        }
                    }
                    Ok(())
                },
            )?;

            let command = factory.msg.param.get_cmd();
            let msg = &factory.msg;

            /* for added members, the list is just fine */
            if command == SystemMessage::MemberRemovedFromGroup {
                let email_to_remove = msg.param.get(Param::Arg).unwrap_or_default();

                let self_addr = context
                    .get_config(Config::ConfiguredAddr)
                    .unwrap_or_default();

                if !email_to_remove.is_empty()
                    && !addr_cmp(email_to_remove, self_addr)
                    && !vec_contains_lowercase(&factory.recipients_addr, &email_to_remove)
                {
                    factory.recipients_names.push("".to_string());
                    factory.recipients_addr.push(email_to_remove.to_string());
                }
            }
            if command != SystemMessage::AutocryptSetupMessage
                && command != SystemMessage::SecurejoinMessage
                && context.get_config_bool(Config::MdnsEnabled)
            {
                factory.req_mdn = true;
            }
        }
        let row = context.sql.query_row(
            "SELECT mime_in_reply_to, mime_references FROM msgs WHERE id=?",
            params![msg.id],
            |row| {
                let in_reply_to: String = row.get(0)?;
                let references: String = row.get(1)?;

                Ok((in_reply_to, references))
            },
        );

        match row {
            Ok((in_reply_to, references)) => {
                factory.in_reply_to = in_reply_to;
                factory.references = references;
            }
            Err(err) => {
                error!(
                    context,
                    "mimefactory: failed to load mime_in_reply_to: {:?}", err
                );
            }
        }

        Ok(factory)
    }

    pub fn from_mdn(context: &'a Context, msg: &'b Message) -> Result<Self, Error> {
        // MDNs not enabled - check this is late, in the job. the
        // user may have changed its choice while offline ...
        ensure!(
            context.get_config_bool(Config::MdnsEnabled),
            "MDNs meanwhile disabled"
        );

        let contact = Contact::load_from_db(context, msg.from_id)?;

        // Do not send MDNs trash etc.; chats.blocked is already checked by the caller
        // in dc_markseen_msgs()
        ensure!(!contact.is_blocked(), "Contact blocked");
        ensure!(msg.chat_id > DC_CHAT_ID_LAST_SPECIAL, "Invalid chat id");

        Ok(MimeFactory {
            context,
            from_addr: context
                .get_config(Config::ConfiguredAddr)
                .unwrap_or_default(),
            from_displayname: context.get_config(Config::Displayname).unwrap_or_default(),
            selfstatus: context
                .get_config(Config::Selfstatus)
                .unwrap_or_else(|| context.stock_str(StockMessage::StatusLine).to_string()),
            recipients_names: vec![contact.get_authname().to_string()],
            recipients_addr: vec![contact.get_addr().to_string()],
            timestamp: dc_create_smeared_timestamp(context),
            loaded: Loaded::MDN,
            msg,
            chat: None,
            increation: false,
            in_reply_to: String::default(),
            references: String::default(),
            req_mdn: false,
            last_added_location_id: 0,
        })
    }

    fn peerstates_for_recipients(&self) -> Result<Vec<(Option<Peerstate>, &str)>, Error> {
        let self_addr = self
            .context
            .get_config(Config::ConfiguredAddr)
            .ok_or_else(|| format_err!("Not configured"))?;

        Ok(self
            .recipients_addr
            .iter()
            .filter(|addr| *addr != &self_addr)
            .map(|addr| {
                (
                    Peerstate::from_addr(self.context, &self.context.sql, addr),
                    addr.as_str(),
                )
            })
            .collect())
    }

    fn is_e2ee_guranteed(&self) -> bool {
        match self.loaded {
            Loaded::Message => {
                if self.chat.as_ref().unwrap().typ == Chattype::VerifiedGroup {
                    return true;
                }

                let force_plaintext = self
                    .msg
                    .param
                    .get_int(Param::ForcePlaintext)
                    .unwrap_or_default();

                if force_plaintext == 0 {
                    return self
                        .msg
                        .param
                        .get_int(Param::GuaranteeE2ee)
                        .unwrap_or_default()
                        != 0;
                }

                false
            }
            Loaded::MDN => false,
        }
    }

    fn min_verified(&self) -> PeerstateVerifiedStatus {
        match self.loaded {
            Loaded::Message => {
                let chat = self.chat.as_ref().unwrap();
                if chat.typ == Chattype::VerifiedGroup {
                    PeerstateVerifiedStatus::BidirectVerified
                } else {
                    PeerstateVerifiedStatus::Unverified
                }
            }
            Loaded::MDN => PeerstateVerifiedStatus::Unverified,
        }
    }

    fn should_force_plaintext(&self) -> i32 {
        match self.loaded {
            Loaded::Message => {
                let chat = self.chat.as_ref().unwrap();
                if chat.typ == Chattype::VerifiedGroup {
                    0
                } else {
                    self.msg
                        .param
                        .get_int(Param::ForcePlaintext)
                        .unwrap_or_default()
                }
            }
            Loaded::MDN => DC_FP_NO_AUTOCRYPT_HEADER,
        }
    }

    fn should_do_gossip(&self) -> bool {
        match self.loaded {
            Loaded::Message => {
                let chat = self.chat.as_ref().unwrap();
                // beside key- and member-changes, force re-gossip every 48 hours
                if chat.gossiped_timestamp == 0
                    || (chat.gossiped_timestamp + (2 * 24 * 60 * 60)) > time()
                {
                    return true;
                }

                self.msg.param.get_cmd() == SystemMessage::MemberAddedToGroup
            }
            Loaded::MDN => false,
        }
    }

    fn grpimage(&self) -> Option<String> {
        match self.loaded {
            Loaded::Message => {
                let chat = self.chat.as_ref().unwrap();
                let cmd = self.msg.param.get_cmd();

                match cmd {
                    SystemMessage::MemberAddedToGroup => {
                        return chat.param.get(Param::ProfileImage).map(Into::into);
                    }
                    SystemMessage::GroupImageChanged => {
                        return self.msg.param.get(Param::Arg).map(Into::into)
                    }
                    _ => {}
                }

                None
            }
            Loaded::MDN => None,
        }
    }

    fn subject_str(&self) -> String {
        match self.loaded {
            Loaded::Message => {
                match self.chat {
                    Some(ref chat) => {
                        let raw = message::get_summarytext_by_raw(
                            self.msg.type_0,
                            self.msg.text.as_ref(),
                            &self.msg.param,
                            32,
                            self.context,
                        );
                        let mut lines = raw.lines();
                        let raw_subject = if let Some(line) = lines.next() {
                            line
                        } else {
                            ""
                        };

                        let afwd_email = self.msg.param.exists(Param::Forwarded);
                        let fwd = if afwd_email { "Fwd: " } else { "" };

                        if self.msg.param.get_cmd() == SystemMessage::AutocryptSetupMessage {
                            // do not add the "Chat:" prefix for setup messages
                            self.context
                                .stock_str(StockMessage::AcSetupMsgSubject)
                                .into_owned()
                        } else if chat.typ == Chattype::Group || chat.typ == Chattype::VerifiedGroup
                        {
                            format!("Chat: {}: {}{}", chat.name, fwd, raw_subject)
                        } else {
                            format!("Chat: {}{}", fwd, raw_subject)
                        }
                    }
                    None => String::new(),
                }
            }
            Loaded::MDN => {
                let e = self.context.stock_str(StockMessage::ReadRcpt);
                format!("Chat: {}", e)
            }
        }
    }

    pub fn render(mut self) -> Result<RenderedEmail, Error> {
        // Headers that are encrypted
        // - Chat-*, except Chat-Version
        // - Secure-Join*
        // - Subject
        let mut protected_headers: Vec<Header> = Vec::new();

        // All other headers
        let mut unprotected_headers: Vec<Header> = Vec::new();

        let from = Address::new_mailbox_with_name(
            self.from_displayname.to_string(),
            self.from_addr.clone(),
        );

        let mut to = Vec::with_capacity(self.recipients_names.len());
        let name_iter = self.recipients_names.iter();
        let addr_iter = self.recipients_addr.iter();
        for (name, addr) in name_iter.zip(addr_iter) {
            if name.is_empty() {
                to.push(Address::new_mailbox(addr.clone()));
            } else {
                to.push(Address::new_mailbox_with_name(
                    name.to_string(),
                    addr.clone(),
                ));
            }
        }

        if !self.references.is_empty() {
            unprotected_headers.push(Header::new("References".into(), self.references.clone()));
        }

        if !self.in_reply_to.is_empty() {
            unprotected_headers.push(Header::new("In-Reply-To".into(), self.in_reply_to.clone()));
        }

        let date = chrono::Utc
            .from_local_datetime(&chrono::NaiveDateTime::from_timestamp(self.timestamp, 0))
            .unwrap()
            .to_rfc2822();

        unprotected_headers.push(Header::new("Date".into(), date));

        let os_name = &self.context.os_name;
        let os_part = os_name
            .as_ref()
            .map(|s| format!("/{}", s))
            .unwrap_or_default();
        let version = get_version_str();

        // Add a X-Mailer header.
        // This is only informational for debugging and may be removed in the release.
        // We do not rely on this header as it may be removed by MTAs.

        unprotected_headers.push(Header::new(
            "X-Mailer".into(),
            format!("Delta Chat Core {}{}", version, os_part),
        ));
        unprotected_headers.push(Header::new("Chat-Version".to_string(), "1.0".to_string()));

        if self.req_mdn {
            // we use "Chat-Disposition-Notification-To"
            // because replies to "Disposition-Notification-To" are weird in many cases
            // eg. are just freetext and/or do not follow any standard.
            protected_headers.push(Header::new(
                "Chat-Disposition-Notification-To".into(),
                self.from_addr.clone(),
            ));
        }

        let min_verified = self.min_verified();
        let do_gossip = self.should_do_gossip();
        let grpimage = self.grpimage();
        let force_plaintext = self.should_force_plaintext();
        let subject_str = self.subject_str();
        let e2ee_guranteed = self.is_e2ee_guranteed();
        let mut encrypt_helper = EncryptHelper::new(self.context)?;

        let subject = encode_words(&subject_str);

        let mut message = match self.loaded {
            Loaded::Message => {
                self.render_message(&mut protected_headers, &mut unprotected_headers, &grpimage)?
            }
            Loaded::MDN => self.render_mdn()?,
        };

        if force_plaintext != DC_FP_NO_AUTOCRYPT_HEADER {
            // unless determined otherwise we add the Autocrypt header
            let aheader = encrypt_helper.get_aheader().to_string();
            unprotected_headers.push(Header::new("Autocrypt".into(), aheader));
        }

        protected_headers.push(Header::new("Subject".into(), subject));

        let peerstates = self.peerstates_for_recipients()?;
        let should_encrypt =
            encrypt_helper.should_encrypt(self.context, e2ee_guranteed, &peerstates)?;
        let is_encrypted = should_encrypt && force_plaintext == 0;

        let rfc724_mid = match self.loaded {
            Loaded::Message => self.msg.rfc724_mid.clone(),
            Loaded::MDN => dc_create_outgoing_rfc724_mid(None, &self.from_addr),
        };

        // we could also store the message-id in the protected headers
        // which would probably help to survive providers like
        // Outlook.com or hotmail which mangle the Message-ID.
        // but they also strip the Autocrypt header so we probably
        // never get a chance to tunnel our protected headers in a
        // cryptographic payload.
        unprotected_headers.push(Header::new(
            "Message-ID".into(),
            render_rfc724_mid(&rfc724_mid),
        ));

        unprotected_headers.push(Header::new_with_value("To".into(), to).unwrap());
        unprotected_headers.push(Header::new_with_value("From".into(), vec![from]).unwrap());

        let outer_message = if is_encrypted {
            // Add gossip headers
            if do_gossip {
                for peerstate in peerstates.iter().filter_map(|(state, _)| state.as_ref()) {
                    if peerstate.peek_key(min_verified).is_some() {
                        if let Some(header) = peerstate.render_gossip_header(min_verified) {
                            message =
                                message.header(Header::new("Autocrypt-Gossip".into(), header));
                        }
                    }
                }
            }

            // Store protected headers in the inner message.
            for header in protected_headers.into_iter() {
                message = message.header(header);
            }

            // Set the appropriate Content-Type for the inner message.
            let mut existing_ct = message
                .get_header("Content-Type".to_string())
                .and_then(|h| h.get_value::<String>().ok())
                .unwrap_or_else(|| "text/plain; charset=utf-8;".to_string());

            if !existing_ct.ends_with(';') {
                existing_ct += ";";
            }
            message = message.replace_header(Header::new(
                "Content-Type".to_string(),
                format!("{} protected-headers=\"v1\";", existing_ct),
            ));

            // Set the appropriate Content-Type for the outer message
            let mut outer_message = PartBuilder::new().header((
                "Content-Type".to_string(),
                "multipart/encrypted; protocol=\"application/pgp-encrypted\"".to_string(),
            ));

            // Store the unprotected headers on the outer message.
            for header in unprotected_headers.into_iter() {
                outer_message = outer_message.header(header);
            }

            if std::env::var(crate::DCC_MIME_DEBUG).is_ok() {
                info!(self.context, "mimefactory: outgoing message mime:");
                let raw_message = message.clone().build().as_string();
                println!("{}", raw_message);
            }

            let encrypted =
                encrypt_helper.encrypt(self.context, min_verified, message, &peerstates)?;

            outer_message = outer_message
                .child(
                    // Autocrypt part 1
                    PartBuilder::new()
                        .content_type(&"application/pgp-encrypted".parse::<mime::Mime>().unwrap())
                        .header(("Content-Description", "PGP/MIME version identification"))
                        .body("Version: 1\r\n")
                        .build(),
                )
                .child(
                    // Autocrypt part 2
                    PartBuilder::new()
                        .content_type(
                            &"application/octet-stream; name=\"encrypted.asc\""
                                .parse::<mime::Mime>()
                                .unwrap(),
                        )
                        .header(("Content-Description", "OpenPGP encrypted message"))
                        .header(("Content-Disposition", "inline; filename=\"encrypted.asc\";"))
                        .body(encrypted)
                        .build(),
                )
                .header(("Subject".to_string(), "...".to_string()));

            outer_message
        } else {
            // In the unencrypted case, we add all headers to the outer message.
            for header in protected_headers.into_iter() {
                message = message.header(header);
            }
            for header in unprotected_headers.into_iter() {
                message = message.header(header);
            }
            message
        };

        let is_gossiped = is_encrypted && do_gossip && !peerstates.is_empty();

        let MimeFactory {
            recipients_addr,
            from_addr,
            last_added_location_id,
            msg,
            loaded,
            ..
        } = self;

        Ok(RenderedEmail {
            message: outer_message.build().as_string().into_bytes(),
            // envelope: Envelope::new,
            is_encrypted,
            is_gossiped,
            last_added_location_id,
            foreign_id: match loaded {
                Loaded::Message => Some(msg.id),
                Loaded::MDN => None,
            },
            recipients: recipients_addr,
            from: from_addr,
            rfc724_mid,
        })
    }

    fn render_message(
        &mut self,
        protected_headers: &mut Vec<Header>,
        unprotected_headers: &mut Vec<Header>,
        grpimage: &Option<String>,
    ) -> Result<PartBuilder, Error> {
        let context = self.context;
        let chat = self.chat.as_ref().unwrap();
        let command = self.msg.param.get_cmd();
        let mut placeholdertext = None;
        let mut meta_part = None;

        if chat.typ == Chattype::VerifiedGroup {
            protected_headers.push(Header::new("Chat-Verified".to_string(), "1".to_string()));
        }

        if chat.typ == Chattype::Group || chat.typ == Chattype::VerifiedGroup {
            protected_headers.push(Header::new("Chat-Group-ID".into(), chat.grpid.clone()));

            let encoded = encode_words(&chat.name);
            protected_headers.push(Header::new("Chat-Group-Name".into(), encoded));

            match command {
                SystemMessage::MemberRemovedFromGroup => {
                    let email_to_remove = self.msg.param.get(Param::Arg).unwrap_or_default();
                    if !email_to_remove.is_empty() {
                        protected_headers.push(Header::new(
                            "Chat-Group-Member-Removed".into(),
                            email_to_remove.into(),
                        ));
                    }
                }
                SystemMessage::MemberAddedToGroup => {
                    let email_to_add = self.msg.param.get(Param::Arg).unwrap_or_default();
                    if !email_to_add.is_empty() {
                        protected_headers.push(Header::new(
                            "Chat-Group-Member-Added".into(),
                            email_to_add.into(),
                        ));
                    }
                    if 0 != self.msg.param.get_int(Param::Arg2).unwrap_or_default() & 0x1 {
                        info!(
                            context,
                            "sending secure-join message \'{}\' >>>>>>>>>>>>>>>>>>>>>>>>>",
                            "vg-member-added",
                        );
                        protected_headers.push(Header::new(
                            "Secure-Join".to_string(),
                            "vg-member-added".to_string(),
                        ));
                    }
                }
                SystemMessage::GroupNameChanged => {
                    let value_to_add = self.msg.param.get(Param::Arg).unwrap_or_default();

                    protected_headers.push(Header::new(
                        "Chat-Group-Name-Changed".into(),
                        value_to_add.into(),
                    ));
                }
                SystemMessage::GroupImageChanged => {
                    if grpimage.is_none() {
                        protected_headers
                            .push(Header::new("Chat-Group-Image".to_string(), "0".to_string()));
                    }
                }
                _ => {}
            }
        }

        match command {
            SystemMessage::LocationStreamingEnabled => {
                protected_headers.push(Header::new(
                    "Chat-Content".into(),
                    "location-streaming-enabled".into(),
                ));
            }
            SystemMessage::AutocryptSetupMessage => {
                unprotected_headers
                    .push(Header::new("Autocrypt-Setup-Message".into(), "v1".into()));

                placeholdertext = Some(
                    self.context
                        .stock_str(StockMessage::AcSetupMsgBody)
                        .to_string(),
                );
            }
            SystemMessage::SecurejoinMessage => {
                let msg = &self.msg;
                let step = msg.param.get(Param::Arg).unwrap_or_default();
                if !step.is_empty() {
                    info!(
                        context,
                        "sending secure-join message \'{}\' >>>>>>>>>>>>>>>>>>>>>>>>>", step,
                    );
                    protected_headers.push(Header::new("Secure-Join".into(), step.into()));

                    let param2 = msg.param.get(Param::Arg2).unwrap_or_default();
                    if !param2.is_empty() {
                        protected_headers.push(Header::new(
                            if step == "vg-request-with-auth" || step == "vc-request-with-auth" {
                                "Secure-Join-Auth".into()
                            } else {
                                "Secure-Join-Invitenumber".into()
                            },
                            param2.into(),
                        ));
                    }

                    let fingerprint = msg.param.get(Param::Arg3).unwrap_or_default();
                    if !fingerprint.is_empty() {
                        protected_headers.push(Header::new(
                            "Secure-Join-Fingerprint".into(),
                            fingerprint.into(),
                        ));
                    }
                    if let Some(id) = msg.param.get(Param::Arg4) {
                        protected_headers.push(Header::new("Secure-Join-Group".into(), id.into()));
                    };
                }
            }
            _ => {}
        }

        if let Some(grpimage) = grpimage {
            info!(self.context, "setting group image '{}'", grpimage);
            let mut meta = Message::default();
            meta.type_0 = Viewtype::Image;
            meta.param.set(Param::File, grpimage);

            let (mail, filename_as_sent) = build_body_file(context, &meta, "group-image")?;
            meta_part = Some(mail);
            protected_headers.push(Header::new("Chat-Group-Image".into(), filename_as_sent));
        }

        if self.msg.type_0 == Viewtype::Sticker {
            protected_headers.push(Header::new("Chat-Content".into(), "sticker".into()));
        }

        if self.msg.type_0 == Viewtype::Voice
            || self.msg.type_0 == Viewtype::Audio
            || self.msg.type_0 == Viewtype::Video
        {
            if self.msg.type_0 == Viewtype::Voice {
                protected_headers.push(Header::new("Chat-Voice-Message".into(), "1".into()));
            }
            let duration_ms = self.msg.param.get_int(Param::Duration).unwrap_or_default();
            if duration_ms > 0 {
                let dur = duration_ms.to_string();
                protected_headers.push(Header::new("Chat-Duration".into(), dur));
            }
        }

        // add text part - we even add empty text and force a MIME-multipart-message as:
        // - some Apps have problems with Non-text in the main part (eg. "Mail" from stock Android)
        // - we can add "forward hints" this way
        // - it looks better

        let afwd_email = self.msg.param.exists(Param::Forwarded);
        let fwdhint = if afwd_email {
            Some(
                "---------- Forwarded message ----------\r\n\
                 From: Delta Chat\r\n\
                 \r\n"
                    .to_string(),
            )
        } else {
            None
        };
        let final_text = {
            if let Some(ref text) = placeholdertext {
                text
            } else if let Some(ref text) = self.msg.text {
                text
            } else {
                ""
            }
        };

        let footer = &self.selfstatus;
        let message_text = format!(
            "{}{}{}{}{}",
            fwdhint.unwrap_or_default(),
            &final_text,
            if !final_text.is_empty() && !footer.is_empty() {
                "\r\n\r\n"
            } else {
                ""
            },
            if !footer.is_empty() { "-- \r\n" } else { "" },
            footer
        );

        // Message is sent as text/plain, with charset = utf-8
        let mut parts = vec![PartBuilder::new()
            .content_type(&mime::TEXT_PLAIN_UTF_8)
            .body(message_text)];

        // add attachment part
        if chat::msgtype_has_file(self.msg.type_0) {
            if !is_file_size_okay(context, &self.msg) {
                bail!(
                    "Message exceeds the recommended {} MB.",
                    24 * 1024 * 1024 / 4 * 3 / 1000 / 1000,
                );
            } else {
                let (file_part, _) = build_body_file(context, &self.msg, "")?;
                parts.push(file_part);
            }
        }

        if let Some(meta_part) = meta_part {
            parts.push(meta_part);
        }

        if self.msg.param.exists(Param::SetLatitude) {
            let param = &self.msg.param;
            let kml_file = location::get_message_kml(
                self.msg.timestamp_sort,
                param.get_float(Param::SetLatitude).unwrap_or_default(),
                param.get_float(Param::SetLongitude).unwrap_or_default(),
            );
            parts.push(
                PartBuilder::new()
                    .content_type(
                        &"application/vnd.google-earth.kml+xml"
                            .parse::<mime::Mime>()
                            .unwrap(),
                    )
                    .header((
                        "Content-Disposition",
                        "attachment; filename=\"message.kml\"",
                    ))
                    .body(kml_file),
            );
        }

        if location::is_sending_locations_to_chat(context, self.msg.chat_id) {
            match location::get_kml(context, self.msg.chat_id) {
                Ok((kml_content, last_added_location_id)) => {
                    parts.push(
                        PartBuilder::new()
                            .content_type(
                                &"application/vnd.google-earth.kml+xml"
                                    .parse::<mime::Mime>()
                                    .unwrap(),
                            )
                            .header((
                                "Content-Disposition",
                                "attachment; filename=\"message.kml\"",
                            ))
                            .body(kml_content),
                    );
                    if !self.msg.param.exists(Param::SetLatitude) {
                        // otherwise, the independent location is already filed
                        self.last_added_location_id = last_added_location_id;
                    }
                }
                Err(err) => {
                    warn!(context, "mimefactory: could not get location: {}", err);
                }
            }
        }

        // Single part, render as regular message.
        if parts.len() == 1 {
            return Ok(parts.pop().unwrap());
        }

        // Multiple parts, render as multipart.
        let mut message = PartBuilder::new().message_type(MimeMultipartType::Mixed);
        for part in parts.into_iter() {
            message = message.child(part.build());
        }

        Ok(message)
    }

    /// Render an MDN
    fn render_mdn(&mut self) -> Result<PartBuilder, Error> {
        // RFC 6522, this also requires the `report-type` parameter which is equal
        // to the MIME subtype of the second body part of the multipart/report */
        //
        // currently, we do not send MDNs encrypted:
        // - in a multi-device-setup that is not set up properly, MDNs would disturb the communication as they
        //   are send automatically which may lead to spreading outdated Autocrypt headers.
        // - they do not carry any information but the Message-ID
        // - this save some KB
        // - in older versions, we did not encrypt messages to ourself when they to to SMTP - however, if these messages
        //   are forwarded for any reasons (eg. gmail always forwards to IMAP), we have no chance to decrypt them;
        //   this issue is fixed with 0.9.4

        let mut message = PartBuilder::new().header((
            "Content-Type".to_string(),
            "multipart/report; report-type=disposition-notification".to_string(),
        ));

        // first body part: always human-readable, always REQUIRED by RFC 6522
        let p1 = if 0
            != self
                .msg
                .param
                .get_int(Param::GuaranteeE2ee)
                .unwrap_or_default()
        {
            self.context
                .stock_str(StockMessage::EncryptedMsg)
                .into_owned()
        } else {
            self.msg.get_summarytext(self.context, 32)
        };
        let p2 = self
            .context
            .stock_string_repl_str(StockMessage::ReadRcptMailBody, p1);
        let message_text = format!("{}\r\n", p2);
        message = message.child(
            PartBuilder::new()
                .content_type(&mime::TEXT_PLAIN_UTF_8)
                .body(message_text)
                .build(),
        );

        // second body part: machine-readable, always REQUIRED by RFC 6522
        let version = get_version_str();
        let message_text2 = format!(
            "Reporting-UA: Delta Chat {}\r\n\
             Original-Recipient: rfc822;{}\r\n\
             Final-Recipient: rfc822;{}\r\n\
             Original-Message-ID: <{}>\r\n\
             Disposition: manual-action/MDN-sent-automatically; displayed\r\n",
            version, self.from_addr, self.from_addr, self.msg.rfc724_mid
        );

        message = message.child(
            PartBuilder::new()
                .content_type(&"message/disposition-notification".parse().unwrap())
                .body(message_text2)
                .build(),
        );

        Ok(message)
    }
}

fn build_body_file(
    context: &Context,
    msg: &Message,
    base_name: &str,
) -> Result<(PartBuilder, String), Error> {
    let blob = msg
        .param
        .get_blob(Param::File, context, true)?
        .ok_or_else(|| format_err!("msg has no filename"))?;
    let suffix = blob.suffix().unwrap_or("dat");

    // Get file name to use for sending.  For privacy purposes, we do
    // not transfer the original filenames eg. for images; these names
    // are normally not needed and contain timestamps, running numbers
    // etc.
    let filename_to_send: String = match msg.type_0 {
        Viewtype::Voice => chrono::Utc
            .timestamp(msg.timestamp_sort as i64, 0)
            .format(&format!("voice-message_%Y-%m-%d_%H-%M-%S.{}", &suffix))
            .to_string(),
        Viewtype::Image | Viewtype::Gif => format!(
            "{}.{}",
            if base_name.is_empty() {
                "image"
            } else {
                base_name
            },
            &suffix,
        ),
        Viewtype::Video => format!("video.{}", &suffix),
        _ => blob.as_file_name().to_string(),
    };

    /* check mimetype */
    let mimetype: mime::Mime = match msg.param.get(Param::MimeType) {
        Some(mtype) => mtype.parse()?,
        None => {
            if let Some(res) = message::guess_msgtype_from_suffix(blob.as_rel_path()) {
                res.1.parse()?
            } else {
                mime::APPLICATION_OCTET_STREAM
            }
        }
    };

    // create mime part, for Content-Disposition, see RFC 2183.
    // `Content-Disposition: attachment` seems not to make a difference to `Content-Disposition: inline`
    // at least on tested Thunderbird and Gma'l in 2017.
    // But I've heard about problems with inline and outl'k, so we just use the attachment-type until we
    // run into other problems ...
    let cd_value = if needs_encoding(&filename_to_send) {
        format!(
            "attachment; filename*=\"{}\"",
            encode_words(&filename_to_send)
        )
    } else {
        format!("attachment; filename=\"{}\"", &filename_to_send)
    };

    let body = std::fs::read(blob.to_abs_path())?;
    let encoded_body = base64::encode(&body);

    let mail = PartBuilder::new()
        .content_type(&mimetype)
        .header(("Content-Disposition", cd_value))
        .header(("Content-Transfer-Encoding", "base64"))
        .body(encoded_body);

    Ok((mail, filename_to_send))
}

pub(crate) fn vec_contains_lowercase(vec: &[String], part: &str) -> bool {
    let partlc = part.to_lowercase();
    for cur in vec.iter() {
        if cur.to_lowercase() == partlc {
            return true;
        }
    }
    false
}

fn is_file_size_okay(context: &Context, msg: &Message) -> bool {
    match msg.param.get_path(Param::File, context).unwrap_or(None) {
        Some(path) => {
            let bytes = dc_get_filebytes(context, &path);
            bytes <= (49 * 1024 * 1024 / 4 * 3)
        }
        None => false,
    }
}

fn render_rfc724_mid(rfc724_mid: &str) -> String {
    let rfc724_mid = rfc724_mid.trim().to_string();

    if rfc724_mid.chars().nth(0).unwrap_or_default() == '<' {
        rfc724_mid.to_string()
    } else {
        format!("<{}>", rfc724_mid).to_string()
    }
}

/* ******************************************************************************
 * Encode/decode header words, RFC 2047
 ******************************************************************************/

fn encode_words(word: &str) -> String {
    encoded_words::encode(word, None, encoded_words::EncodingFlag::Shortest, None)
}

pub fn needs_encoding(to_check: impl AsRef<str>) -> bool {
    let to_check = to_check.as_ref();

    if to_check.is_empty() {
        return false;
    }

    to_check.chars().any(|c| {
        !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' && c != '~' && c != '%'
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_email_address() {
        let display_name = "ä space";
        let addr = "x@y.org";

        assert!(!display_name.is_ascii());

        let s = format!(
            "{}",
            Address::new_mailbox_with_name(display_name.to_string(), addr.to_string())
        );

        println!("{}", s);

        assert_eq!(s, "=?utf-8?q?=C3=A4_space?= <x@y.org>");
    }

    #[test]
    fn test_render_rfc724_mid() {
        assert_eq!(
            render_rfc724_mid("kqjwle123@qlwe"),
            "<kqjwle123@qlwe>".to_string()
        );
        assert_eq!(
            render_rfc724_mid("  kqjwle123@qlwe "),
            "<kqjwle123@qlwe>".to_string()
        );
        assert_eq!(
            render_rfc724_mid("<kqjwle123@qlwe>"),
            "<kqjwle123@qlwe>".to_string()
        );
    }
}
