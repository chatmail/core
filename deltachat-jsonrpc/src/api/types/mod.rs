pub mod account;
pub mod calls;
pub mod chat;
pub mod chat_list;
pub mod contact;
pub mod events;
pub mod http;
pub mod location;
pub mod login_param;
pub mod message;
pub mod provider_info;
pub mod qr;
pub mod reactions;
pub mod webxdc;

pub fn color_int_to_hex_string(color: u32) -> String {
    format!("{color:#08x}").replace("0x", "#")
}

fn maybe_empty_string_to_option(string: String) -> Option<String> {
    if string.is_empty() {
        None
    } else {
        Some(string)
    }
}
