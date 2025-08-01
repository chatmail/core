use anyhow::Result;
use deltachat::color;
use deltachat::context::Context;
use serde::Serialize;
use typescript_type_def::TypeDef;

use super::color_int_to_hex_string;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "Contact", rename_all = "camelCase")]
pub struct ContactObject {
    address: String,
    color: String,
    auth_name: String,
    status: String,
    display_name: String,
    id: u32,
    name: String,
    profile_image: Option<String>, // BLOBS
    name_and_addr: String,
    is_blocked: bool,

    /// Is the contact a key contact.
    is_key_contact: bool,

    /// Is encryption available for this contact.
    ///
    /// This can only be true for key-contacts.
    /// However, it is possible to have a key-contact
    /// for which encryption is not available because we don't have a key yet,
    /// e.g. if we just scanned the fingerprint from a QR code.
    e2ee_avail: bool,

    /// True if the contact
    /// can be added to protected chats
    /// because SELF and contact have verified their fingerprints in both directions.
    ///
    /// See [`Self::verifier_id`]/`Contact.verifierId` for a guidance how to display these information.
    is_verified: bool,

    /// True if the contact profile title should have a green checkmark.
    ///
    /// This indicates whether 1:1 chat has a green checkmark
    /// or will have a green checkmark if created.
    is_profile_verified: bool,

    /// The contact ID that verified a contact.
    ///
    /// As verifier may be unknown,
    /// use [`Self::is_verified`]/`Contact.isVerified` to check if a contact can be added to a protected chat.
    ///
    /// UI should display the information in the contact's profile as follows:
    ///
    /// - If `verifierId` != 0,
    ///   display text "Introduced by ..."
    ///   with the name and address of the contact
    ///   formatted by `name_and_addr`/`nameAndAddr`.
    ///   Prefix the text by a green checkmark.
    ///
    /// - If `verifierId` == 0 and `isVerified` != 0,
    ///   display "Introduced" prefixed by a green checkmark.
    ///
    /// - if `verifierId` == 0 and `isVerified` == 0,
    ///   display nothing
    ///
    /// This contains the contact ID of the verifier.
    /// If it is `DC_CONTACT_ID_SELF`, we verified the contact ourself.
    /// If it is None/Null, we don't have verifier information or
    /// the contact is not verified.
    verifier_id: Option<u32>,

    /// the contact's last seen timestamp
    last_seen: i64,
    was_seen_recently: bool,

    /// If the contact is a bot.
    is_bot: bool,
}

impl ContactObject {
    pub async fn try_from_dc_contact(
        context: &Context,
        contact: deltachat::contact::Contact,
    ) -> Result<Self> {
        let profile_image = match contact.get_profile_image(context).await? {
            Some(path_buf) => path_buf.to_str().map(|s| s.to_owned()),
            None => None,
        };
        let is_verified = contact.is_verified(context).await?;
        let is_profile_verified = contact.is_profile_verified(context).await?;

        let verifier_id = contact
            .get_verifier_id(context)
            .await?
            .flatten()
            .map(|contact_id| contact_id.to_u32());

        Ok(ContactObject {
            address: contact.get_addr().to_owned(),
            color: color_int_to_hex_string(contact.get_color()),
            auth_name: contact.get_authname().to_owned(),
            status: contact.get_status().to_owned(),
            display_name: contact.get_display_name().to_owned(),
            id: contact.id.to_u32(),
            name: contact.get_name().to_owned(),
            profile_image, //BLOBS
            name_and_addr: contact.get_name_n_addr(),
            is_blocked: contact.is_blocked(),
            is_key_contact: contact.is_key_contact(),
            e2ee_avail: contact.e2ee_avail(context).await?,
            is_verified,
            is_profile_verified,
            verifier_id,
            last_seen: contact.last_seen(),
            was_seen_recently: contact.was_seen_recently(),
            is_bot: contact.is_bot(),
        })
    }
}

#[derive(Clone, Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VcardContact {
    /// Email address.
    addr: String,
    /// The contact's name, or the email address if no name was given.
    display_name: String,
    /// Public PGP key in Base64.
    key: Option<String>,
    /// Profile image in Base64.
    profile_image: Option<String>,
    /// Contact color as hex string.
    color: String,
    /// Last update timestamp.
    timestamp: Option<i64>,
}

impl From<deltachat_contact_tools::VcardContact> for VcardContact {
    fn from(vc: deltachat_contact_tools::VcardContact) -> Self {
        let display_name = vc.display_name().to_string();
        let color = color::str_to_color(&vc.addr.to_lowercase());
        Self {
            addr: vc.addr,
            display_name,
            key: vc.key,
            profile_image: vc.profile_image,
            color: color_int_to_hex_string(color),
            timestamp: vc.timestamp.ok(),
        }
    }
}
