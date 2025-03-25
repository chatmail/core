#![recursion_limit = "256"]
#![warn(unused, clippy::all)]
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    clippy::missing_safety_doc,
    clippy::expect_fun_call
)]

#[macro_use]
extern crate human_panic;

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Write;
use std::future::Future;
use std::ops::Deref;
use std::ptr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use deltachat::chat::{ChatId, ChatVisibility, MessageListOptions, MuteDuration, ProtectionStatus};
use deltachat::constants::DC_MSG_ID_LAST_SPECIAL;
use deltachat::contact::{Contact, ContactId, Origin};
use deltachat::context::{Context, ContextBuilder};
use deltachat::ephemeral::Timer as EphemeralTimer;
use deltachat::imex::BackupProvider;
use deltachat::key::preconfigure_keypair;
use deltachat::message::MsgId;
use deltachat::qr_code_generator::{create_qr_svg, generate_backup_qr, get_securejoin_qr_svg};
use deltachat::stock_str::StockMessage;
use deltachat::webxdc::StatusUpdateSerial;
use deltachat::*;
use deltachat::{accounts::Accounts, log::LogExt};
use deltachat_jsonrpc::api::CommandApi;
use deltachat_jsonrpc::yerpc::{OutReceiver, RpcClient, RpcSession};
use num_traits::{FromPrimitive, ToPrimitive};
use once_cell::sync::Lazy;
use rand::Rng;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

mod dc_array;
mod lot;

mod string;
use deltachat::chatlist::Chatlist;

use self::string::*;

// as C lacks a good and portable error handling,
// in general, the C Interface is forgiving wrt to bad parameters.
// - objects returned by some functions
//   should be passable to the functions handling that object.
// - if in doubt, the empty string is returned on failures;
//   this avoids panics if the ui just forgets to handle a case
// - finally, this behaviour matches the old core-c API and UIs already depend on it

const DC_GCM_ADDDAYMARKER: u32 = 0x01;
const DC_GCM_INFO_ONLY: u32 = 0x02;

// dc_context_t

/// Struct representing the deltachat context.
pub type dc_context_t = Context;

static RT: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("unable to create tokio runtime"));

fn block_on<T>(fut: T) -> T::Output
where
    T: Future,
{
    RT.block_on(fut)
}

fn spawn<T>(fut: T) -> JoinHandle<T::Output>
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
{
    RT.spawn(fut)
}

#[no_mangle]
pub unsafe extern "C" fn dc_context_new(
    _os_name: *const libc::c_char,
    dbfile: *const libc::c_char,
    blobdir: *const libc::c_char,
) -> *mut dc_context_t {
    setup_panic!();

    if dbfile.is_null() {
        eprintln!("ignoring careless call to dc_context_new()");
        return ptr::null_mut();
    }

    let ctx = if blobdir.is_null() || *blobdir == 0 {
        // generate random ID as this functionality is not yet available on the C-api.
        let id = rand::thread_rng().gen();
        block_on(
            ContextBuilder::new(as_path(dbfile).to_path_buf())
                .with_id(id)
                .open(),
        )
    } else {
        eprintln!("blobdir can not be defined explicitly anymore");
        return ptr::null_mut();
    };
    match ctx {
        Ok(ctx) => Box::into_raw(Box::new(ctx)),
        Err(err) => {
            eprintln!("failed to create context: {err:#}");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_context_new_closed(dbfile: *const libc::c_char) -> *mut dc_context_t {
    setup_panic!();

    if dbfile.is_null() {
        eprintln!("ignoring careless call to dc_context_new_closed()");
        return ptr::null_mut();
    }

    let id = rand::thread_rng().gen();
    match block_on(
        ContextBuilder::new(as_path(dbfile).to_path_buf())
            .with_id(id)
            .build(),
    ) {
        Ok(context) => Box::into_raw(Box::new(context)),
        Err(err) => {
            eprintln!("failed to create context: {err:#}");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_context_open(
    context: *mut dc_context_t,
    passphrase: *const libc::c_char,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_context_open()");
        return 0;
    }

    let ctx = &*context;
    let passphrase = to_string_lossy(passphrase);
    block_on(ctx.open(passphrase))
        .context("dc_context_open() failed")
        .log_err(ctx)
        .map(|b| b as libc::c_int)
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn dc_context_change_passphrase(
    context: *mut dc_context_t,
    passphrase: *const libc::c_char,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_context_change_passphrase()");
        return 0;
    }

    let ctx = &*context;
    let passphrase = to_string_lossy(passphrase);
    block_on(ctx.change_passphrase(passphrase))
        .context("dc_context_change_passphrase() failed")
        .log_err(ctx)
        .is_ok() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_context_is_open(context: *mut dc_context_t) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_context_is_open()");
        return 0;
    }

    let ctx = &*context;
    block_on(ctx.is_open()) as libc::c_int
}

/// Release the context structure.
///
/// This function releases the memory of the `dc_context_t` structure.
#[no_mangle]
pub unsafe extern "C" fn dc_context_unref(context: *mut dc_context_t) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_context_unref()");
        return;
    }
    drop(Box::from_raw(context));
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_blobdir(context: *mut dc_context_t) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_blobdir()");
        return "".strdup();
    }
    let ctx = &*context;
    ctx.get_blobdir().to_string_lossy().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_config(
    context: *mut dc_context_t,
    key: *const libc::c_char,
    value: *const libc::c_char,
) -> libc::c_int {
    if context.is_null() || key.is_null() {
        eprintln!("ignoring careless call to dc_set_config()");
        return 0;
    }
    let ctx = &*context;
    let key = to_string_lossy(key);
    let value = to_opt_string_lossy(value);

    block_on(async move {
        if key.starts_with("ui.") {
            ctx.set_ui_config(&key, value.as_deref())
                .await
                .with_context(|| format!("dc_set_config failed: Can't set {key} to {value:?}"))
                .log_err(ctx)
                .is_ok() as libc::c_int
        } else {
            match config::Config::from_str(&key) {
                Ok(key) => ctx
                    .set_config(key, value.as_deref())
                    .await
                    .with_context(|| {
                        format!("dc_set_config() failed: Can't set {key} to {value:?}")
                    })
                    .log_err(ctx)
                    .is_ok() as libc::c_int,
                Err(_) => {
                    warn!(ctx, "dc_set_config(): invalid key");
                    0
                }
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_config(
    context: *mut dc_context_t,
    key: *const libc::c_char,
) -> *mut libc::c_char {
    if context.is_null() || key.is_null() {
        eprintln!("ignoring careless call to dc_get_config()");
        return "".strdup();
    }
    let ctx = &*context;

    let key = to_string_lossy(key);

    block_on(async move {
        if key.starts_with("ui.") {
            ctx.get_ui_config(&key)
                .await
                .context("Can't get ui-config")
                .log_err(ctx)
                .unwrap_or_default()
                .unwrap_or_default()
                .strdup()
        } else {
            match config::Config::from_str(&key) {
                Ok(key) => ctx
                    .get_config(key)
                    .await
                    .context("Can't get config")
                    .log_err(ctx)
                    .unwrap_or_default()
                    .unwrap_or_default()
                    .strdup(),
                Err(_) => {
                    warn!(ctx, "dc_get_config(): invalid key '{}'", &key);
                    "".strdup()
                }
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_stock_translation(
    context: *mut dc_context_t,
    stock_id: u32,
    stock_msg: *mut libc::c_char,
) -> libc::c_int {
    if context.is_null() || stock_msg.is_null() {
        eprintln!("ignoring careless call to dc_set_stock_string");
        return 0;
    }
    let msg = to_string_lossy(stock_msg);
    let ctx = &*context;

    block_on(async move {
        match StockMessage::from_u32(stock_id) {
            Some(id) => match ctx.set_stock_translation(id, msg).await {
                Ok(()) => 1,
                Err(err) => {
                    warn!(ctx, "set_stock_translation failed: {err:#}");
                    0
                }
            },
            None => {
                warn!(ctx, "invalid stock message id {stock_id}");
                0
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_config_from_qr(
    context: *mut dc_context_t,
    qr: *mut libc::c_char,
) -> libc::c_int {
    if context.is_null() || qr.is_null() {
        eprintln!("ignoring careless call to dc_set_config_from_qr");
        return 0;
    }
    let qr = to_string_lossy(qr);
    let ctx = &*context;

    block_on(async move {
        match qr::set_config_from_qr(ctx, &qr).await {
            Ok(()) => 1,
            Err(err) => {
                error!(ctx, "Failed to create account from QR code: {err:#}");
                0
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_info(context: *const dc_context_t) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_info()");
        return "".strdup();
    }
    let ctx = &*context;
    block_on(async move {
        match ctx.get_info().await {
            Ok(info) => render_info(info).unwrap_or_default().strdup(),
            Err(err) => {
                warn!(ctx, "failed to get info: {err:#}");
                "".strdup()
            }
        }
    })
}

fn render_info(
    info: BTreeMap<&'static str, String>,
) -> std::result::Result<String, std::fmt::Error> {
    let mut res = String::new();
    for (key, value) in &info {
        writeln!(&mut res, "{key}={value}")?;
    }

    Ok(res)
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_connectivity(context: *const dc_context_t) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_connectivity()");
        return 0;
    }
    let ctx = &*context;
    block_on(ctx.get_connectivity()) as u32 as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_connectivity_html(
    context: *const dc_context_t,
) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_connectivity_html()");
        return "".strdup();
    }
    let ctx = &*context;
    block_on(async move {
        match ctx.get_connectivity_html().await {
            Ok(html) => html.strdup(),
            Err(err) => {
                error!(ctx, "Failed to get connectivity html: {err:#}");
                "".strdup()
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_push_state(context: *const dc_context_t) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_push_state()");
        return 0;
    }
    let ctx = &*context;
    block_on(ctx.push_state()) as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_oauth2_url(
    context: *mut dc_context_t,
    addr: *const libc::c_char,
    redirect: *const libc::c_char,
) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_oauth2_url()");
        return ptr::null_mut(); // NULL explicitly defined as "unknown"
    }
    let ctx = &*context;
    let addr = to_string_lossy(addr);
    let redirect = to_string_lossy(redirect);

    block_on(async move {
        match oauth2::get_oauth2_url(ctx, &addr, &redirect)
            .await
            .context("dc_get_oauth2_url failed")
            .log_err(ctx)
        {
            Ok(Some(res)) => res.strdup(),
            Ok(None) | Err(_) => ptr::null_mut(),
        }
    })
}

fn spawn_configure(ctx: Context) {
    spawn(async move {
        ctx.configure()
            .await
            .context("Configure failed")
            .log_err(&ctx)
    });
}

#[no_mangle]
pub unsafe extern "C" fn dc_configure(context: *mut dc_context_t) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_configure()");
        return;
    }

    let ctx = &*context;
    spawn_configure(ctx.clone());
}

#[no_mangle]
pub unsafe extern "C" fn dc_is_configured(context: *mut dc_context_t) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_is_configured()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        ctx.is_configured()
            .await
            .context("failed to get configured state")
            .log_err(ctx)
            .unwrap_or_default() as libc::c_int
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_start_io(context: *mut dc_context_t) {
    if context.is_null() {
        return;
    }
    let ctx = &mut *context;

    block_on(ctx.start_io())
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_id(context: *mut dc_context_t) -> libc::c_int {
    if context.is_null() {
        return 0;
    }
    let ctx = &*context;

    ctx.get_id() as libc::c_int
}

pub type dc_event_t = Event;

#[no_mangle]
pub unsafe extern "C" fn dc_event_unref(a: *mut dc_event_t) {
    if a.is_null() {
        eprintln!("ignoring careless call to dc_event_unref()");
        return;
    }

    drop(Box::from_raw(a));
}

#[no_mangle]
pub unsafe extern "C" fn dc_event_get_id(event: *mut dc_event_t) -> libc::c_int {
    if event.is_null() {
        eprintln!("ignoring careless call to dc_event_get_id()");
        return 0;
    }

    let event = &*event;
    match event.typ {
        EventType::Info(_) => 100,
        EventType::SmtpConnected(_) => 101,
        EventType::ImapConnected(_) => 102,
        EventType::SmtpMessageSent(_) => 103,
        EventType::ImapMessageDeleted(_) => 104,
        EventType::ImapMessageMoved(_) => 105,
        EventType::ImapInboxIdle => 106,
        EventType::NewBlobFile(_) => 150,
        EventType::DeletedBlobFile(_) => 151,
        EventType::Warning(_) => 300,
        EventType::Error(_) => 400,
        EventType::ErrorSelfNotInGroup(_) => 410,
        EventType::MsgsChanged { .. } => 2000,
        EventType::ReactionsChanged { .. } => 2001,
        EventType::IncomingReaction { .. } => 2002,
        EventType::IncomingWebxdcNotify { .. } => 2003,
        EventType::IncomingMsg { .. } => 2005,
        EventType::IncomingMsgBunch { .. } => 2006,
        EventType::MsgsNoticed { .. } => 2008,
        EventType::MsgDelivered { .. } => 2010,
        EventType::MsgFailed { .. } => 2012,
        EventType::MsgRead { .. } => 2015,
        EventType::MsgDeleted { .. } => 2016,
        EventType::ChatModified(_) => 2020,
        EventType::ChatEphemeralTimerModified { .. } => 2021,
        EventType::ChatDeleted { .. } => 2023,
        EventType::ContactsChanged(_) => 2030,
        EventType::LocationChanged(_) => 2035,
        EventType::ConfigureProgress { .. } => 2041,
        EventType::ImexProgress(_) => 2051,
        EventType::ImexFileWritten(_) => 2052,
        EventType::SecurejoinInviterProgress { .. } => 2060,
        EventType::SecurejoinJoinerProgress { .. } => 2061,
        EventType::ConnectivityChanged => 2100,
        EventType::SelfavatarChanged => 2110,
        EventType::ConfigSynced { .. } => 2111,
        EventType::WebxdcStatusUpdate { .. } => 2120,
        EventType::WebxdcInstanceDeleted { .. } => 2121,
        EventType::WebxdcRealtimeData { .. } => 2150,
        EventType::WebxdcRealtimeAdvertisementReceived { .. } => 2151,
        EventType::AccountsBackgroundFetchDone => 2200,
        EventType::ChatlistChanged => 2300,
        EventType::ChatlistItemChanged { .. } => 2301,
        EventType::AccountsChanged => 2302,
        EventType::AccountsItemChanged => 2303,
        EventType::EventChannelOverflow { .. } => 2400,
        #[allow(unreachable_patterns)]
        #[cfg(test)]
        _ => unreachable!("This is just to silence a rust_analyzer false-positive"),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_event_get_data1_int(event: *mut dc_event_t) -> libc::c_int {
    if event.is_null() {
        eprintln!("ignoring careless call to dc_event_get_data1_int()");
        return 0;
    }

    let event = &(*event).typ;
    match event {
        EventType::Info(_)
        | EventType::SmtpConnected(_)
        | EventType::ImapConnected(_)
        | EventType::SmtpMessageSent(_)
        | EventType::ImapMessageDeleted(_)
        | EventType::ImapMessageMoved(_)
        | EventType::ImapInboxIdle
        | EventType::NewBlobFile(_)
        | EventType::DeletedBlobFile(_)
        | EventType::Warning(_)
        | EventType::Error(_)
        | EventType::ConnectivityChanged
        | EventType::SelfavatarChanged
        | EventType::ConfigSynced { .. }
        | EventType::IncomingMsgBunch { .. }
        | EventType::ErrorSelfNotInGroup(_)
        | EventType::AccountsBackgroundFetchDone
        | EventType::ChatlistChanged
        | EventType::AccountsChanged
        | EventType::AccountsItemChanged => 0,
        EventType::IncomingReaction { contact_id, .. }
        | EventType::IncomingWebxdcNotify { contact_id, .. } => contact_id.to_u32() as libc::c_int,
        EventType::MsgsChanged { chat_id, .. }
        | EventType::ReactionsChanged { chat_id, .. }
        | EventType::IncomingMsg { chat_id, .. }
        | EventType::MsgsNoticed(chat_id)
        | EventType::MsgDelivered { chat_id, .. }
        | EventType::MsgFailed { chat_id, .. }
        | EventType::MsgRead { chat_id, .. }
        | EventType::MsgDeleted { chat_id, .. }
        | EventType::ChatModified(chat_id)
        | EventType::ChatEphemeralTimerModified { chat_id, .. }
        | EventType::ChatDeleted { chat_id } => chat_id.to_u32() as libc::c_int,
        EventType::ContactsChanged(id) | EventType::LocationChanged(id) => {
            let id = id.unwrap_or_default();
            id.to_u32() as libc::c_int
        }
        EventType::ConfigureProgress { progress, .. } | EventType::ImexProgress(progress) => {
            *progress as libc::c_int
        }
        EventType::ImexFileWritten(_) => 0,
        EventType::SecurejoinInviterProgress { contact_id, .. }
        | EventType::SecurejoinJoinerProgress { contact_id, .. } => {
            contact_id.to_u32() as libc::c_int
        }
        EventType::WebxdcRealtimeData { msg_id, .. }
        | EventType::WebxdcStatusUpdate { msg_id, .. }
        | EventType::WebxdcRealtimeAdvertisementReceived { msg_id }
        | EventType::WebxdcInstanceDeleted { msg_id, .. } => msg_id.to_u32() as libc::c_int,
        EventType::ChatlistItemChanged { chat_id } => {
            chat_id.unwrap_or_default().to_u32() as libc::c_int
        }
        EventType::EventChannelOverflow { n } => *n as libc::c_int,
        #[allow(unreachable_patterns)]
        #[cfg(test)]
        _ => unreachable!("This is just to silence a rust_analyzer false-positive"),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_event_get_data2_int(event: *mut dc_event_t) -> libc::c_int {
    if event.is_null() {
        eprintln!("ignoring careless call to dc_event_get_data2_int()");
        return 0;
    }

    let event = &(*event).typ;

    match event {
        EventType::Info(_)
        | EventType::SmtpConnected(_)
        | EventType::ImapConnected(_)
        | EventType::SmtpMessageSent(_)
        | EventType::ImapMessageDeleted(_)
        | EventType::ImapMessageMoved(_)
        | EventType::ImapInboxIdle
        | EventType::NewBlobFile(_)
        | EventType::DeletedBlobFile(_)
        | EventType::Warning(_)
        | EventType::Error(_)
        | EventType::ErrorSelfNotInGroup(_)
        | EventType::ContactsChanged(_)
        | EventType::LocationChanged(_)
        | EventType::ConfigureProgress { .. }
        | EventType::ImexProgress(_)
        | EventType::ImexFileWritten(_)
        | EventType::MsgsNoticed(_)
        | EventType::ConnectivityChanged
        | EventType::WebxdcInstanceDeleted { .. }
        | EventType::IncomingMsgBunch { .. }
        | EventType::SelfavatarChanged
        | EventType::AccountsBackgroundFetchDone
        | EventType::ChatlistChanged
        | EventType::ChatlistItemChanged { .. }
        | EventType::AccountsChanged
        | EventType::AccountsItemChanged
        | EventType::ConfigSynced { .. }
        | EventType::ChatModified(_)
        | EventType::ChatDeleted { .. }
        | EventType::WebxdcRealtimeAdvertisementReceived { .. }
        | EventType::EventChannelOverflow { .. } => 0,
        EventType::MsgsChanged { msg_id, .. }
        | EventType::ReactionsChanged { msg_id, .. }
        | EventType::IncomingReaction { msg_id, .. }
        | EventType::IncomingWebxdcNotify { msg_id, .. }
        | EventType::IncomingMsg { msg_id, .. }
        | EventType::MsgDelivered { msg_id, .. }
        | EventType::MsgFailed { msg_id, .. }
        | EventType::MsgRead { msg_id, .. }
        | EventType::MsgDeleted { msg_id, .. } => msg_id.to_u32() as libc::c_int,
        EventType::SecurejoinInviterProgress { progress, .. }
        | EventType::SecurejoinJoinerProgress { progress, .. } => *progress as libc::c_int,
        EventType::ChatEphemeralTimerModified { timer, .. } => timer.to_u32() as libc::c_int,
        EventType::WebxdcStatusUpdate {
            status_update_serial,
            ..
        } => status_update_serial.to_u32() as libc::c_int,
        EventType::WebxdcRealtimeData { data, .. } => data.len() as libc::c_int,
        #[allow(unreachable_patterns)]
        #[cfg(test)]
        _ => unreachable!("This is just to silence a rust_analyzer false-positive"),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_event_get_data1_str(event: *mut dc_event_t) -> *mut libc::c_char {
    if event.is_null() {
        eprintln!("ignoring careless call to dc_event_get_data1_str()");
        return ptr::null_mut();
    }

    let event = &(*event).typ;

    match event {
        EventType::IncomingWebxdcNotify { href, .. } => {
            if let Some(href) = href {
                href.to_c_string().unwrap_or_default().into_raw()
            } else {
                ptr::null_mut()
            }
        }
        _ => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_event_get_data2_str(event: *mut dc_event_t) -> *mut libc::c_char {
    if event.is_null() {
        eprintln!("ignoring careless call to dc_event_get_data2_str()");
        return ptr::null_mut();
    }

    let event = &(*event).typ;

    match event {
        EventType::Info(msg)
        | EventType::SmtpConnected(msg)
        | EventType::ImapConnected(msg)
        | EventType::SmtpMessageSent(msg)
        | EventType::ImapMessageDeleted(msg)
        | EventType::ImapMessageMoved(msg)
        | EventType::NewBlobFile(msg)
        | EventType::DeletedBlobFile(msg)
        | EventType::Warning(msg)
        | EventType::Error(msg)
        | EventType::ErrorSelfNotInGroup(msg) => {
            let data2 = msg.to_c_string().unwrap_or_default();
            data2.into_raw()
        }
        EventType::MsgsChanged { .. }
        | EventType::ReactionsChanged { .. }
        | EventType::IncomingMsg { .. }
        | EventType::ImapInboxIdle
        | EventType::MsgsNoticed(_)
        | EventType::MsgDelivered { .. }
        | EventType::MsgFailed { .. }
        | EventType::MsgRead { .. }
        | EventType::MsgDeleted { .. }
        | EventType::ChatModified(_)
        | EventType::ContactsChanged(_)
        | EventType::LocationChanged(_)
        | EventType::ImexProgress(_)
        | EventType::SecurejoinInviterProgress { .. }
        | EventType::SecurejoinJoinerProgress { .. }
        | EventType::ConnectivityChanged
        | EventType::SelfavatarChanged
        | EventType::WebxdcStatusUpdate { .. }
        | EventType::WebxdcInstanceDeleted { .. }
        | EventType::AccountsBackgroundFetchDone
        | EventType::ChatEphemeralTimerModified { .. }
        | EventType::ChatDeleted { .. }
        | EventType::IncomingMsgBunch { .. }
        | EventType::ChatlistItemChanged { .. }
        | EventType::ChatlistChanged
        | EventType::AccountsChanged
        | EventType::AccountsItemChanged
        | EventType::WebxdcRealtimeAdvertisementReceived { .. }
        | EventType::EventChannelOverflow { .. } => ptr::null_mut(),
        EventType::ConfigureProgress { comment, .. } => {
            if let Some(comment) = comment {
                comment.to_c_string().unwrap_or_default().into_raw()
            } else {
                ptr::null_mut()
            }
        }
        EventType::ImexFileWritten(file) => {
            let data2 = file.to_c_string().unwrap_or_default();
            data2.into_raw()
        }
        EventType::ConfigSynced { key } => {
            let data2 = key.to_string().to_c_string().unwrap_or_default();
            data2.into_raw()
        }
        EventType::WebxdcRealtimeData { data, .. } => {
            let ptr = libc::malloc(data.len());
            libc::memcpy(ptr, data.as_ptr() as *mut libc::c_void, data.len());
            ptr as *mut libc::c_char
        }
        EventType::IncomingReaction { reaction, .. } => reaction
            .as_str()
            .to_c_string()
            .unwrap_or_default()
            .into_raw(),
        EventType::IncomingWebxdcNotify { text, .. } => {
            text.to_c_string().unwrap_or_default().into_raw()
        }
        #[allow(unreachable_patterns)]
        #[cfg(test)]
        _ => unreachable!("This is just to silence a rust_analyzer false-positive"),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_event_get_account_id(event: *mut dc_event_t) -> u32 {
    if event.is_null() {
        eprintln!("ignoring careless call to dc_event_get_account_id()");
        return 0;
    }

    (*event).id
}

pub type dc_event_emitter_t = EventEmitter;

#[no_mangle]
pub unsafe extern "C" fn dc_get_event_emitter(
    context: *mut dc_context_t,
) -> *mut dc_event_emitter_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_event_emitter()");
        return ptr::null_mut();
    }
    let ctx = &*context;
    Box::into_raw(Box::new(ctx.get_event_emitter()))
}

#[no_mangle]
pub unsafe extern "C" fn dc_event_emitter_unref(emitter: *mut dc_event_emitter_t) {
    if emitter.is_null() {
        eprintln!("ignoring careless call to dc_event_emitter_unref()");
        return;
    }

    drop(Box::from_raw(emitter));
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_next_event(events: *mut dc_event_emitter_t) -> *mut dc_event_t {
    if events.is_null() {
        eprintln!("ignoring careless call to dc_get_next_event()");
        return ptr::null_mut();
    }
    let events = &*events;

    block_on(async move {
        events
            .recv()
            .await
            .map(|ev| Box::into_raw(Box::new(ev)))
            .unwrap_or_else(ptr::null_mut)
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_stop_io(context: *mut dc_context_t) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_stop_io()");
        return;
    }
    let ctx = &*context;

    block_on(async move {
        ctx.stop_io().await;
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_maybe_network(context: *mut dc_context_t) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_maybe_network()");
        return;
    }
    let ctx = &*context;

    block_on(async move { ctx.maybe_network().await })
}

#[no_mangle]
pub unsafe extern "C" fn dc_preconfigure_keypair(
    context: *mut dc_context_t,
    secret_data: *const libc::c_char,
) -> i32 {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_preconfigure_keypair()");
        return 0;
    }
    let ctx = &*context;
    let secret_data = to_string_lossy(secret_data);
    block_on(preconfigure_keypair(ctx, &secret_data))
        .context("Failed to save keypair")
        .log_err(ctx)
        .is_ok() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_chatlist(
    context: *mut dc_context_t,
    flags: libc::c_int,
    query_str: *const libc::c_char,
    query_id: u32,
) -> *mut dc_chatlist_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_chatlist()");
        return ptr::null_mut();
    }
    let ctx = &*context;
    let qs = to_opt_string_lossy(query_str);

    let qi = if query_id == 0 {
        None
    } else {
        Some(ContactId::new(query_id))
    };

    block_on(async move {
        match chatlist::Chatlist::try_load(ctx, flags as usize, qs.as_deref(), qi)
            .await
            .context("Failed to get chatlist")
            .log_err(ctx)
        {
            Ok(list) => {
                let ffi_list = ChatlistWrapper { context, list };
                Box::into_raw(Box::new(ffi_list))
            }
            Err(_) => ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_create_chat_by_contact_id(
    context: *mut dc_context_t,
    contact_id: u32,
) -> u32 {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_create_chat_by_contact_id()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        ChatId::create_for_contact(ctx, ContactId::new(contact_id))
            .await
            .context("Failed to create chat from contact_id")
            .log_err(ctx)
            .map(|id| id.to_u32())
            .unwrap_or(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_chat_id_by_contact_id(
    context: *mut dc_context_t,
    contact_id: u32,
) -> u32 {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_chat_id_by_contact_id()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        ChatId::lookup_by_contact(ctx, ContactId::new(contact_id))
            .await
            .context("Failed to get chat for contact_id")
            .log_err(ctx)
            .unwrap_or_default() // unwraps the Result
            .map(|id| id.to_u32())
            .unwrap_or(0) // unwraps the Option
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_send_msg(
    context: *mut dc_context_t,
    chat_id: u32,
    msg: *mut dc_msg_t,
) -> u32 {
    if context.is_null() || msg.is_null() {
        eprintln!("ignoring careless call to dc_send_msg()");
        return 0;
    }
    let ctx = &mut *context;
    let ffi_msg = &mut *msg;

    block_on(async move {
        chat::send_msg(ctx, ChatId::new(chat_id), &mut ffi_msg.message)
            .await
            .unwrap_or_log_default(ctx, "Failed to send message")
    })
    .to_u32()
}

#[no_mangle]
pub unsafe extern "C" fn dc_send_msg_sync(
    context: *mut dc_context_t,
    chat_id: u32,
    msg: *mut dc_msg_t,
) -> u32 {
    if context.is_null() || msg.is_null() {
        eprintln!("ignoring careless call to dc_send_msg_sync()");
        return 0;
    }
    let ctx = &mut *context;
    let ffi_msg = &mut *msg;

    block_on(async move {
        chat::send_msg_sync(ctx, ChatId::new(chat_id), &mut ffi_msg.message)
            .await
            .unwrap_or_log_default(ctx, "Failed to send message")
    })
    .to_u32()
}

#[no_mangle]
pub unsafe extern "C" fn dc_send_text_msg(
    context: *mut dc_context_t,
    chat_id: u32,
    text_to_send: *const libc::c_char,
) -> u32 {
    if context.is_null() || text_to_send.is_null() {
        eprintln!("ignoring careless call to dc_send_text_msg()");
        return 0;
    }
    let ctx = &*context;
    let text_to_send = to_string_lossy(text_to_send);

    block_on(async move {
        chat::send_text_msg(ctx, ChatId::new(chat_id), text_to_send)
            .await
            .map(|msg_id| msg_id.to_u32())
            .unwrap_or_log_default(ctx, "Failed to send text message")
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_send_edit_request(
    context: *mut dc_context_t,
    msg_id: u32,
    new_text: *const libc::c_char,
) {
    if context.is_null() || new_text.is_null() {
        eprintln!("ignoring careless call to dc_send_edit_request()");
        return;
    }
    let ctx = &*context;
    let new_text = to_string_lossy(new_text);

    block_on(chat::send_edit_request(ctx, MsgId::new(msg_id), new_text))
        .unwrap_or_log_default(ctx, "Failed to send text edit")
}

#[no_mangle]
pub unsafe extern "C" fn dc_send_delete_request(
    context: *mut dc_context_t,
    msg_ids: *const u32,
    msg_cnt: libc::c_int,
) {
    if context.is_null() || msg_ids.is_null() || msg_cnt <= 0 {
        eprintln!("ignoring careless call to dc_send_delete_request()");
        return;
    }
    let ctx = &*context;
    let msg_ids = convert_and_prune_message_ids(msg_ids, msg_cnt);

    block_on(message::delete_msgs_ex(ctx, &msg_ids, true))
        .context("failed dc_send_delete_request() call")
        .log_err(ctx)
        .ok();
}

#[no_mangle]
pub unsafe extern "C" fn dc_send_videochat_invitation(
    context: *mut dc_context_t,
    chat_id: u32,
) -> u32 {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_send_videochat_invitation()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        chat::send_videochat_invitation(ctx, ChatId::new(chat_id))
            .await
            .map(|msg_id| msg_id.to_u32())
            .unwrap_or_log_default(ctx, "Failed to send video chat invitation")
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_send_webxdc_status_update(
    context: *mut dc_context_t,
    msg_id: u32,
    json: *const libc::c_char,
    _descr: *const libc::c_char,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_send_webxdc_status_update()");
        return 0;
    }
    let ctx = &*context;

    block_on(ctx.send_webxdc_status_update(MsgId::new(msg_id), &to_string_lossy(json)))
        .context("Failed to send webxdc update")
        .log_err(ctx)
        .is_ok() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_webxdc_status_updates(
    context: *mut dc_context_t,
    msg_id: u32,
    last_known_serial: u32,
) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_webxdc_status_updates()");
        return "".strdup();
    }
    let ctx = &*context;

    block_on(ctx.get_webxdc_status_updates(
        MsgId::new(msg_id),
        StatusUpdateSerial::new(last_known_serial),
    ))
    .unwrap_or_else(|_| "".to_string())
    .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_webxdc_integration(
    context: *mut dc_context_t,
    file: *const libc::c_char,
) {
    if context.is_null() || file.is_null() {
        eprintln!("ignoring careless call to dc_set_webxdc_integration()");
        return;
    }
    let ctx = &*context;
    block_on(ctx.set_webxdc_integration(&to_string_lossy(file)))
        .log_err(ctx)
        .unwrap_or_default();
}

#[no_mangle]
pub unsafe extern "C" fn dc_init_webxdc_integration(
    context: *mut dc_context_t,
    chat_id: u32,
) -> u32 {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_init_webxdc_integration()");
        return 0;
    }
    let ctx = &*context;
    let chat_id = if chat_id == 0 {
        None
    } else {
        Some(ChatId::new(chat_id))
    };

    block_on(ctx.init_webxdc_integration(chat_id))
        .log_err(ctx)
        .map(|msg_id| msg_id.map(|id| id.to_u32()).unwrap_or_default())
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_draft(
    context: *mut dc_context_t,
    chat_id: u32,
    msg: *mut dc_msg_t,
) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_set_draft()");
        return;
    }
    let ctx = &*context;
    let msg = if msg.is_null() {
        None
    } else {
        let ffi_msg: &mut MessageWrapper = &mut *msg;
        Some(&mut ffi_msg.message)
    };

    block_on(async move {
        ChatId::new(chat_id)
            .set_draft(ctx, msg)
            .await
            .unwrap_or_log_default(ctx, "failed to set draft");
    });
}

#[no_mangle]
pub unsafe extern "C" fn dc_add_device_msg(
    context: *mut dc_context_t,
    label: *const libc::c_char,
    msg: *mut dc_msg_t,
) -> u32 {
    if context.is_null() || (label.is_null() && msg.is_null()) {
        eprintln!("ignoring careless call to dc_add_device_msg()");
        return 0;
    }
    let ctx = &mut *context;
    let msg = if msg.is_null() {
        None
    } else {
        let ffi_msg: &mut MessageWrapper = &mut *msg;
        Some(&mut ffi_msg.message)
    };

    block_on(async move {
        chat::add_device_msg(ctx, to_opt_string_lossy(label).as_deref(), msg)
            .await
            .unwrap_or_log_default(ctx, "Failed to add device message")
    })
    .to_u32()
}

#[no_mangle]
pub unsafe extern "C" fn dc_was_device_msg_ever_added(
    context: *mut dc_context_t,
    label: *const libc::c_char,
) -> libc::c_int {
    if context.is_null() || label.is_null() {
        eprintln!("ignoring careless call to dc_was_device_msg_ever_added()");
        return 0;
    }
    let ctx = &mut *context;

    block_on(async move {
        chat::was_device_msg_ever_added(ctx, &to_string_lossy(label))
            .await
            .unwrap_or(false) as libc::c_int
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_draft(context: *mut dc_context_t, chat_id: u32) -> *mut dc_msg_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_draft()");
        return ptr::null_mut(); // NULL explicitly defined as "no draft"
    }
    let ctx = &*context;

    block_on(async move {
        match ChatId::new(chat_id).get_draft(ctx).await {
            Ok(Some(draft)) => {
                let ffi_msg = MessageWrapper {
                    context,
                    message: draft,
                };
                Box::into_raw(Box::new(ffi_msg))
            }
            Ok(None) => ptr::null_mut(),
            Err(err) => {
                error!(ctx, "Failed to get draft for chat #{chat_id}: {err:#}");
                ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_chat_msgs(
    context: *mut dc_context_t,
    chat_id: u32,
    flags: u32,
    _marker1before: u32,
) -> *mut dc_array::dc_array_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_chat_msgs()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    let info_only = (flags & DC_GCM_INFO_ONLY) != 0;
    let add_daymarker = (flags & DC_GCM_ADDDAYMARKER) != 0;
    block_on(async move {
        Box::into_raw(Box::new(
            chat::get_chat_msgs_ex(
                ctx,
                ChatId::new(chat_id),
                MessageListOptions {
                    info_only,
                    add_daymarker,
                },
            )
            .await
            .unwrap_or_log_default(ctx, "failed to get chat msgs")
            .into(),
        ))
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_msg_cnt(context: *mut dc_context_t, chat_id: u32) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_msg_cnt()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        ChatId::new(chat_id)
            .get_msg_cnt(ctx)
            .await
            .unwrap_or_log_default(ctx, "failed to get msg count") as libc::c_int
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_fresh_msg_cnt(
    context: *mut dc_context_t,
    chat_id: u32,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_fresh_msg_cnt()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        ChatId::new(chat_id)
            .get_fresh_msg_cnt(ctx)
            .await
            .unwrap_or_log_default(ctx, "failed to get fresh msg cnt") as libc::c_int
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_similar_chatlist(
    context: *mut dc_context_t,
    chat_id: u32,
) -> *mut dc_chatlist_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_similar_chatlist()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    let chat_id = ChatId::new(chat_id);
    match block_on(chat_id.get_similar_chatlist(ctx))
        .context("failed to get similar chatlist")
        .log_err(ctx)
    {
        Ok(list) => {
            let ffi_list = ChatlistWrapper { context, list };
            Box::into_raw(Box::new(ffi_list))
        }
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_estimate_deletion_cnt(
    context: *mut dc_context_t,
    from_server: libc::c_int,
    seconds: i64,
) -> libc::c_int {
    if context.is_null() || seconds < 0 {
        eprintln!("ignoring careless call to dc_estimate_deletion_cnt()");
        return 0;
    }
    let ctx = &*context;
    block_on(async move {
        message::estimate_deletion_cnt(ctx, from_server != 0, seconds)
            .await
            .unwrap_or(0) as libc::c_int
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_fresh_msgs(
    context: *mut dc_context_t,
) -> *mut dc_array::dc_array_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_fresh_msgs()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    block_on(async move {
        let arr = dc_array_t::from(
            ctx.get_fresh_msgs()
                .await
                .context("Failed to get fresh messages")
                .log_err(ctx)
                .unwrap_or_default()
                .iter()
                .map(|msg_id| msg_id.to_u32())
                .collect::<Vec<u32>>(),
        );
        Box::into_raw(Box::new(arr))
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_next_msgs(context: *mut dc_context_t) -> *mut dc_array::dc_array_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_next_msgs()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    let msg_ids = block_on(ctx.get_next_msgs())
        .context("failed to get next messages")
        .log_err(ctx)
        .unwrap_or_default();
    let arr = dc_array_t::from(
        msg_ids
            .iter()
            .map(|msg_id| msg_id.to_u32())
            .collect::<Vec<u32>>(),
    );
    Box::into_raw(Box::new(arr))
}

#[no_mangle]
pub unsafe extern "C" fn dc_wait_next_msgs(
    context: *mut dc_context_t,
) -> *mut dc_array::dc_array_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_wait_next_msgs()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    let msg_ids = block_on(ctx.wait_next_msgs())
        .context("failed to wait for next messages")
        .log_err(ctx)
        .unwrap_or_default();
    let arr = dc_array_t::from(
        msg_ids
            .iter()
            .map(|msg_id| msg_id.to_u32())
            .collect::<Vec<u32>>(),
    );
    Box::into_raw(Box::new(arr))
}

#[no_mangle]
pub unsafe extern "C" fn dc_marknoticed_chat(context: *mut dc_context_t, chat_id: u32) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_marknoticed_chat()");
        return;
    }
    let ctx = &*context;

    block_on(async move {
        chat::marknoticed_chat(ctx, ChatId::new(chat_id))
            .await
            .context("Failed marknoticed chat")
            .log_err(ctx)
            .unwrap_or(())
    })
}

fn from_prim<S, T>(s: S) -> Option<T>
where
    T: FromPrimitive,
    S: Into<i64>,
{
    FromPrimitive::from_i64(s.into())
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_chat_media(
    context: *mut dc_context_t,
    chat_id: u32,
    msg_type: libc::c_int,
    or_msg_type2: libc::c_int,
    or_msg_type3: libc::c_int,
) -> *mut dc_array::dc_array_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_chat_media()");
        return ptr::null_mut();
    }
    let ctx = &*context;
    let chat_id = if chat_id == 0 {
        None
    } else {
        Some(ChatId::new(chat_id))
    };
    let msg_type = from_prim(msg_type).expect(&format!("invalid msg_type = {msg_type}"));
    let or_msg_type2 =
        from_prim(or_msg_type2).expect(&format!("incorrect or_msg_type2 = {or_msg_type2}"));
    let or_msg_type3 =
        from_prim(or_msg_type3).expect(&format!("incorrect or_msg_type3 = {or_msg_type3}"));

    block_on(async move {
        Box::into_raw(Box::new(
            chat::get_chat_media(ctx, chat_id, msg_type, or_msg_type2, or_msg_type3)
                .await
                .unwrap_or_log_default(ctx, "Failed get_chat_media")
                .into(),
        ))
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_chat_visibility(
    context: *mut dc_context_t,
    chat_id: u32,
    archive: libc::c_int,
) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_set_chat_visibility()");
        return;
    }
    let ctx = &*context;
    let visibility = match archive {
        0 => ChatVisibility::Normal,
        1 => ChatVisibility::Archived,
        2 => ChatVisibility::Pinned,
        _ => {
            warn!(
                ctx,
                "ignoring careless call to dc_set_chat_visibility(): unknown archived state",
            );
            return;
        }
    };

    block_on(async move {
        ChatId::new(chat_id)
            .set_visibility(ctx, visibility)
            .await
            .context("Failed setting chat visibility")
            .log_err(ctx)
            .unwrap_or(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_delete_chat(context: *mut dc_context_t, chat_id: u32) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_delete_chat()");
        return;
    }
    let ctx = &*context;

    block_on(async move {
        ChatId::new(chat_id)
            .delete(ctx)
            .await
            .context("Failed chat delete")
            .log_err(ctx)
            .ok();
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_block_chat(context: *mut dc_context_t, chat_id: u32) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_block_chat()");
        return;
    }
    let ctx = &*context;

    block_on(async move {
        ChatId::new(chat_id)
            .block(ctx)
            .await
            .context("Failed chat block")
            .log_err(ctx)
            .ok();
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_accept_chat(context: *mut dc_context_t, chat_id: u32) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_accept_chat()");
        return;
    }
    let ctx = &*context;

    block_on(async move {
        ChatId::new(chat_id)
            .accept(ctx)
            .await
            .context("Failed chat accept")
            .log_err(ctx)
            .ok();
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_chat_contacts(
    context: *mut dc_context_t,
    chat_id: u32,
) -> *mut dc_array::dc_array_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_chat_contacts()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    block_on(async move {
        let arr = dc_array_t::from(
            chat::get_chat_contacts(ctx, ChatId::new(chat_id))
                .await
                .unwrap_or_log_default(ctx, "Failed get_chat_contacts")
                .iter()
                .map(|id| id.to_u32())
                .collect::<Vec<u32>>(),
        );
        Box::into_raw(Box::new(arr))
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_search_msgs(
    context: *mut dc_context_t,
    chat_id: u32,
    query: *const libc::c_char,
) -> *mut dc_array::dc_array_t {
    if context.is_null() || query.is_null() {
        eprintln!("ignoring careless call to dc_search_msgs()");
        return ptr::null_mut();
    }
    let ctx = &*context;
    let chat_id = if chat_id == 0 {
        None
    } else {
        Some(ChatId::new(chat_id))
    };

    block_on(async move {
        let arr = dc_array_t::from(
            ctx.search_msgs(chat_id, &to_string_lossy(query))
                .await
                .unwrap_or_log_default(ctx, "Failed search_msgs")
                .iter()
                .map(|msg_id| msg_id.to_u32())
                .collect::<Vec<u32>>(),
        );
        Box::into_raw(Box::new(arr))
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_chat(context: *mut dc_context_t, chat_id: u32) -> *mut dc_chat_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_chat()");
        return ptr::null_mut();
    }
    let ctx = &*context;
    let context: Context = ctx.clone();

    block_on(async move {
        match chat::Chat::load_from_db(ctx, ChatId::new(chat_id)).await {
            Ok(chat) => {
                let ffi_chat = ChatWrapper { context, chat };
                Box::into_raw(Box::new(ffi_chat))
            }
            Err(_) => ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_create_group_chat(
    context: *mut dc_context_t,
    protect: libc::c_int,
    name: *const libc::c_char,
) -> u32 {
    if context.is_null() || name.is_null() {
        eprintln!("ignoring careless call to dc_create_group_chat()");
        return 0;
    }
    let ctx = &*context;
    let protect = if let Some(s) = ProtectionStatus::from_i32(protect) {
        s
    } else {
        warn!(ctx, "bad protect-value for dc_create_group_chat()");
        return 0;
    };

    block_on(async move {
        chat::create_group_chat(ctx, protect, &to_string_lossy(name))
            .await
            .context("Failed to create group chat")
            .log_err(ctx)
            .map(|id| id.to_u32())
            .unwrap_or(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_create_broadcast_list(context: *mut dc_context_t) -> u32 {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_create_broadcast_list()");
        return 0;
    }
    let ctx = &*context;
    block_on(chat::create_broadcast_list(ctx))
        .context("Failed to create broadcast list")
        .log_err(ctx)
        .map(|id| id.to_u32())
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn dc_is_contact_in_chat(
    context: *mut dc_context_t,
    chat_id: u32,
    contact_id: u32,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_is_contact_in_chat()");
        return 0;
    }
    let ctx = &*context;

    block_on(chat::is_contact_in_chat(
        ctx,
        ChatId::new(chat_id),
        ContactId::new(contact_id),
    ))
    .context("is_contact_in_chat failed")
    .log_err(ctx)
    .unwrap_or_default() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_add_contact_to_chat(
    context: *mut dc_context_t,
    chat_id: u32,
    contact_id: u32,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_add_contact_to_chat()");
        return 0;
    }
    let ctx = &*context;

    block_on(chat::add_contact_to_chat(
        ctx,
        ChatId::new(chat_id),
        ContactId::new(contact_id),
    ))
    .context("Failed to add contact")
    .log_err(ctx)
    .is_ok() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_remove_contact_from_chat(
    context: *mut dc_context_t,
    chat_id: u32,
    contact_id: u32,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_remove_contact_from_chat()");
        return 0;
    }
    let ctx = &*context;

    block_on(chat::remove_contact_from_chat(
        ctx,
        ChatId::new(chat_id),
        ContactId::new(contact_id),
    ))
    .context("Failed to remove contact")
    .log_err(ctx)
    .is_ok() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_chat_name(
    context: *mut dc_context_t,
    chat_id: u32,
    name: *const libc::c_char,
) -> libc::c_int {
    if context.is_null() || chat_id <= constants::DC_CHAT_ID_LAST_SPECIAL.to_u32() || name.is_null()
    {
        eprintln!("ignoring careless call to dc_set_chat_name()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        chat::set_chat_name(ctx, ChatId::new(chat_id), &to_string_lossy(name))
            .await
            .map(|_| 1)
            .unwrap_or_log_default(ctx, "Failed to set chat name")
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_chat_profile_image(
    context: *mut dc_context_t,
    chat_id: u32,
    image: *const libc::c_char,
) -> libc::c_int {
    if context.is_null() || chat_id <= constants::DC_CHAT_ID_LAST_SPECIAL.to_u32() {
        eprintln!("ignoring careless call to dc_set_chat_profile_image()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        chat::set_chat_profile_image(ctx, ChatId::new(chat_id), &to_string_lossy(image))
            .await
            .map(|_| 1)
            .unwrap_or_log_default(ctx, "Failed to set profile image")
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_chat_mute_duration(
    context: *mut dc_context_t,
    chat_id: u32,
    duration: i64,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_set_chat_mute_duration()");
        return 0;
    }
    let ctx = &*context;
    let muteDuration = match duration {
        0 => MuteDuration::NotMuted,
        -1 => MuteDuration::Forever,
        n if n > 0 => SystemTime::now()
            .checked_add(Duration::from_secs(duration as u64))
            .map_or(MuteDuration::Forever, MuteDuration::Until),
        _ => {
            warn!(
                ctx,
                "dc_chat_set_mute_duration(): Can not use negative duration other than -1",
            );
            return 0;
        }
    };

    block_on(async move {
        chat::set_muted(ctx, ChatId::new(chat_id), muteDuration)
            .await
            .map(|_| 1)
            .unwrap_or_log_default(ctx, "Failed to set mute duration")
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_chat_encrinfo(
    context: *mut dc_context_t,
    chat_id: u32,
) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_chat_encrinfo()");
        return "".strdup();
    }
    let ctx = &*context;

    block_on(async move {
        ChatId::new(chat_id)
            .get_encryption_info(ctx)
            .await
            .map(|s| s.strdup())
            .unwrap_or_else(|e| {
                error!(ctx, "{e:#}");
                ptr::null_mut()
            })
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_chat_ephemeral_timer(
    context: *mut dc_context_t,
    chat_id: u32,
) -> u32 {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_chat_ephemeral_timer()");
        return 0;
    }
    let ctx = &*context;

    // Timer value 0 is returned in the rare case of a database error,
    // but it is not dangerous since it is only meant to be used as a
    // default when changing the value. Such errors should not be
    // ignored when ephemeral timer value is used to construct
    // message headers.
    block_on(async move { ChatId::new(chat_id).get_ephemeral_timer(ctx).await })
        .context("Failed to get ephemeral timer")
        .log_err(ctx)
        .unwrap_or_default()
        .to_u32()
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_chat_ephemeral_timer(
    context: *mut dc_context_t,
    chat_id: u32,
    timer: u32,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_set_chat_ephemeral_timer()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        ChatId::new(chat_id)
            .set_ephemeral_timer(ctx, EphemeralTimer::from_u32(timer))
            .await
            .context("Failed to set ephemeral timer")
            .log_err(ctx)
            .is_ok() as libc::c_int
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_msg_info(
    context: *mut dc_context_t,
    msg_id: u32,
) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_msg_info()");
        return "".strdup();
    }
    let ctx = &*context;
    let msg_id = MsgId::new(msg_id);
    block_on(msg_id.get_info(ctx))
        .unwrap_or_log_default(ctx, "failed to get msg id")
        .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_msg_html(
    context: *mut dc_context_t,
    msg_id: u32,
) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_msg_html()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    block_on(MsgId::new(msg_id).get_html(ctx))
        .unwrap_or_log_default(ctx, "Failed get_msg_html")
        .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_delete_msgs(
    context: *mut dc_context_t,
    msg_ids: *const u32,
    msg_cnt: libc::c_int,
) {
    if context.is_null() || msg_ids.is_null() || msg_cnt <= 0 {
        eprintln!("ignoring careless call to dc_delete_msgs()");
        return;
    }
    let ctx = &*context;
    let msg_ids = convert_and_prune_message_ids(msg_ids, msg_cnt);

    block_on(message::delete_msgs(ctx, &msg_ids))
        .context("failed dc_delete_msgs() call")
        .log_err(ctx)
        .ok();
}

#[no_mangle]
pub unsafe extern "C" fn dc_forward_msgs(
    context: *mut dc_context_t,
    msg_ids: *const u32,
    msg_cnt: libc::c_int,
    chat_id: u32,
) {
    if context.is_null()
        || msg_ids.is_null()
        || msg_cnt <= 0
        || chat_id <= constants::DC_CHAT_ID_LAST_SPECIAL.to_u32()
    {
        eprintln!("ignoring careless call to dc_forward_msgs()");
        return;
    }
    let msg_ids = convert_and_prune_message_ids(msg_ids, msg_cnt);
    let ctx = &*context;

    block_on(async move {
        chat::forward_msgs(ctx, &msg_ids[..], ChatId::new(chat_id))
            .await
            .unwrap_or_log_default(ctx, "Failed to forward message")
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_save_msgs(
    context: *mut dc_context_t,
    msg_ids: *const u32,
    msg_cnt: libc::c_int,
) {
    if context.is_null() || msg_ids.is_null() || msg_cnt <= 0 {
        eprintln!("ignoring careless call to dc_save_msgs()");
        return;
    }
    let msg_ids = convert_and_prune_message_ids(msg_ids, msg_cnt);
    let ctx = &*context;

    block_on(async move {
        chat::save_msgs(ctx, &msg_ids[..])
            .await
            .unwrap_or_log_default(ctx, "Failed to save message")
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_resend_msgs(
    context: *mut dc_context_t,
    msg_ids: *const u32,
    msg_cnt: libc::c_int,
) -> libc::c_int {
    if context.is_null() || msg_ids.is_null() || msg_cnt <= 0 {
        eprintln!("ignoring careless call to dc_resend_msgs()");
        return 0;
    }
    let ctx = &*context;
    let msg_ids = convert_and_prune_message_ids(msg_ids, msg_cnt);

    if let Err(err) = block_on(chat::resend_msgs(ctx, &msg_ids)) {
        error!(ctx, "Resending failed: {err:#}");
        0
    } else {
        1
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_markseen_msgs(
    context: *mut dc_context_t,
    msg_ids: *const u32,
    msg_cnt: libc::c_int,
) {
    if context.is_null() || msg_ids.is_null() || msg_cnt <= 0 {
        eprintln!("ignoring careless call to dc_markseen_msgs()");
        return;
    }
    let msg_ids = convert_and_prune_message_ids(msg_ids, msg_cnt);
    let ctx = &*context;

    block_on(message::markseen_msgs(ctx, msg_ids))
        .context("failed dc_markseen_msgs() call")
        .log_err(ctx)
        .ok();
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_msg(context: *mut dc_context_t, msg_id: u32) -> *mut dc_msg_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_msg()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    block_on(async move {
        let message = match message::Message::load_from_db(ctx, MsgId::new(msg_id)).await {
            Ok(msg) => msg,
            Err(e) => {
                if msg_id <= constants::DC_MSG_ID_LAST_SPECIAL {
                    // C-core API returns empty messages, do the same
                    warn!(
                        ctx,
                        "dc_get_msg called with special msg_id={msg_id}, returning empty msg"
                    );
                    message::Message::default()
                } else {
                    warn!(ctx, "dc_get_msg could not retrieve msg_id {msg_id}: {e:#}");
                    return ptr::null_mut();
                }
            }
        };
        let ffi_msg = MessageWrapper { context, message };
        Box::into_raw(Box::new(ffi_msg))
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_download_full_msg(context: *mut dc_context_t, msg_id: u32) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_download_full_msg()");
        return;
    }
    let ctx = &*context;
    block_on(MsgId::new(msg_id).download_full(ctx))
        .context("Failed to download message fully.")
        .log_err(ctx)
        .ok();
}

#[no_mangle]
pub unsafe extern "C" fn dc_may_be_valid_addr(addr: *const libc::c_char) -> libc::c_int {
    if addr.is_null() {
        eprintln!("ignoring careless call to dc_may_be_valid_addr()");
        return 0;
    }

    contact::may_be_valid_addr(&to_string_lossy(addr)) as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_lookup_contact_id_by_addr(
    context: *mut dc_context_t,
    addr: *const libc::c_char,
) -> u32 {
    if context.is_null() || addr.is_null() {
        eprintln!("ignoring careless call to dc_lookup_contact_id_by_addr()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        Contact::lookup_id_by_addr(ctx, &to_string_lossy(addr), Origin::IncomingReplyTo)
            .await
            .unwrap_or_log_default(ctx, "failed to lookup id")
            .map(|id| id.to_u32())
            .unwrap_or_default()
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_create_contact(
    context: *mut dc_context_t,
    name: *const libc::c_char,
    addr: *const libc::c_char,
) -> u32 {
    if context.is_null() || addr.is_null() {
        eprintln!("ignoring careless call to dc_create_contact()");
        return 0;
    }
    let ctx = &*context;
    let name = to_string_lossy(name);

    block_on(Contact::create(ctx, &name, &to_string_lossy(addr)))
        .context("Cannot create contact")
        .log_err(ctx)
        .map(|id| id.to_u32())
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn dc_add_address_book(
    context: *mut dc_context_t,
    addr_book: *const libc::c_char,
) -> libc::c_int {
    if context.is_null() || addr_book.is_null() {
        eprintln!("ignoring careless call to dc_add_address_book()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        match Contact::add_address_book(ctx, &to_string_lossy(addr_book)).await {
            Ok(cnt) => cnt as libc::c_int,
            Err(_) => 0,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_contacts(
    context: *mut dc_context_t,
    flags: u32,
    query: *const libc::c_char,
) -> *mut dc_array::dc_array_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_contacts()");
        return ptr::null_mut();
    }
    let ctx = &*context;
    let query = to_opt_string_lossy(query);

    block_on(async move {
        match Contact::get_all(ctx, flags, query.as_deref()).await {
            Ok(contacts) => Box::into_raw(Box::new(dc_array_t::from(
                contacts.iter().map(|id| id.to_u32()).collect::<Vec<u32>>(),
            ))),
            Err(_) => ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_blocked_cnt(context: *mut dc_context_t) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_blocked_cnt()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        Contact::get_all_blocked(ctx)
            .await
            .unwrap_or_log_default(ctx, "failed to get blocked count")
            .len() as libc::c_int
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_blocked_contacts(
    context: *mut dc_context_t,
) -> *mut dc_array::dc_array_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_blocked_contacts()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    block_on(async move {
        Box::into_raw(Box::new(dc_array_t::from(
            Contact::get_all_blocked(ctx)
                .await
                .context("Can't get blocked contacts")
                .log_err(ctx)
                .unwrap_or_default()
                .iter()
                .map(|id| id.to_u32())
                .collect::<Vec<u32>>(),
        )))
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_block_contact(
    context: *mut dc_context_t,
    contact_id: u32,
    block: libc::c_int,
) {
    let contact_id = ContactId::new(contact_id);
    if context.is_null() || contact_id.is_special() {
        eprintln!("ignoring careless call to dc_block_contact()");
        return;
    }
    let ctx = &*context;
    block_on(async move {
        if block == 0 {
            Contact::unblock(ctx, contact_id)
                .await
                .context("Can't unblock contact")
                .log_err(ctx)
                .ok();
        } else {
            Contact::block(ctx, contact_id)
                .await
                .context("Can't block contact")
                .log_err(ctx)
                .ok();
        }
    });
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_contact_encrinfo(
    context: *mut dc_context_t,
    contact_id: u32,
) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_contact_encrinfo()");
        return "".strdup();
    }
    let ctx = &*context;

    block_on(async move {
        Contact::get_encrinfo(ctx, ContactId::new(contact_id))
            .await
            .map(|s| s.strdup())
            .unwrap_or_else(|e| {
                error!(ctx, "{e:#}");
                ptr::null_mut()
            })
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_delete_contact(
    context: *mut dc_context_t,
    contact_id: u32,
) -> libc::c_int {
    let contact_id = ContactId::new(contact_id);
    if context.is_null() || contact_id.is_special() {
        eprintln!("ignoring careless call to dc_delete_contact()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        match Contact::delete(ctx, contact_id).await {
            Ok(_) => 1,
            Err(err) => {
                error!(ctx, "cannot delete contact: {err:#}");
                0
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_contact(
    context: *mut dc_context_t,
    contact_id: u32,
) -> *mut dc_contact_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_contact()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    block_on(async move {
        Contact::get_by_id(ctx, ContactId::new(contact_id))
            .await
            .map(|contact| Box::into_raw(Box::new(ContactWrapper { context, contact })))
            .unwrap_or_else(|_| ptr::null_mut())
    })
}

fn spawn_imex(ctx: Context, what: imex::ImexMode, param1: String, passphrase: Option<String>) {
    spawn(async move {
        imex::imex(&ctx, what, param1.as_ref(), passphrase)
            .await
            .context("IMEX failed")
            .log_err(&ctx)
    });
}

#[no_mangle]
pub unsafe extern "C" fn dc_imex(
    context: *mut dc_context_t,
    what_raw: libc::c_int,
    param1: *const libc::c_char,
    param2: *const libc::c_char,
) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_imex()");
        return;
    }
    let what = match imex::ImexMode::from_i32(what_raw) {
        Some(what) => what,
        None => {
            eprintln!("ignoring invalid argument {what_raw} to dc_imex");
            return;
        }
    };
    let passphrase = to_opt_string_lossy(param2);

    let ctx = &*context;

    if let Some(param1) = to_opt_string_lossy(param1) {
        spawn_imex(ctx.clone(), what, param1, passphrase);
    } else {
        eprintln!("dc_imex called without a valid directory");
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_imex_has_backup(
    context: *mut dc_context_t,
    dir: *const libc::c_char,
) -> *mut libc::c_char {
    if context.is_null() || dir.is_null() {
        eprintln!("ignoring careless call to dc_imex_has_backup()");
        return ptr::null_mut(); // NULL explicitly defined as "has no backup"
    }
    let ctx = &*context;

    block_on(async move {
        match imex::has_backup(ctx, to_string_lossy(dir).as_ref()).await {
            Ok(res) => res.strdup(),
            Err(err) => {
                // do not bubble up error to the user,
                // the ui will expect that the file does not exist or cannot be accessed
                warn!(ctx, "dc_imex_has_backup: {err:#}");
                ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_initiate_key_transfer(context: *mut dc_context_t) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_initiate_key_transfer()");
        return ptr::null_mut(); // NULL explicitly defined as "error"
    }
    let ctx = &*context;

    block_on(async move {
        match imex::initiate_key_transfer(ctx).await {
            Ok(res) => res.strdup(),
            Err(err) => {
                error!(ctx, "dc_initiate_key_transfer(): {err:#}");
                ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_continue_key_transfer(
    context: *mut dc_context_t,
    msg_id: u32,
    setup_code: *const libc::c_char,
) -> libc::c_int {
    if context.is_null() || msg_id <= constants::DC_MSG_ID_LAST_SPECIAL || setup_code.is_null() {
        eprintln!("ignoring careless call to dc_continue_key_transfer()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        match imex::continue_key_transfer(ctx, MsgId::new(msg_id), &to_string_lossy(setup_code))
            .await
        {
            Ok(()) => 1,
            Err(err) => {
                warn!(ctx, "dc_continue_key_transfer: {err:#}");
                0
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_stop_ongoing_process(context: *mut dc_context_t) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_stop_ongoing_process()");
        return;
    }
    let ctx = &*context;
    block_on(ctx.stop_ongoing());
}

#[no_mangle]
pub unsafe extern "C" fn dc_check_qr(
    context: *mut dc_context_t,
    qr: *const libc::c_char,
) -> *mut dc_lot_t {
    if context.is_null() || qr.is_null() {
        eprintln!("ignoring careless call to dc_check_qr()");
        return ptr::null_mut();
    }
    let ctx = &*context;

    let lot = match block_on(qr::check_qr(ctx, &to_string_lossy(qr))) {
        Ok(qr) => qr.into(),
        Err(err) => err.into(),
    };
    Box::into_raw(Box::new(lot))
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_securejoin_qr(
    context: *mut dc_context_t,
    chat_id: u32,
) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_securejoin_qr()");
        return "".strdup();
    }
    let ctx = &*context;
    let chat_id = if chat_id == 0 {
        None
    } else {
        Some(ChatId::new(chat_id))
    };

    block_on(securejoin::get_securejoin_qr(ctx, chat_id))
        .unwrap_or_else(|_| "".to_string())
        .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_securejoin_qr_svg(
    context: *mut dc_context_t,
    chat_id: u32,
) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to generate_verification_qr()");
        return "".strdup();
    }
    let ctx = &*context;
    let chat_id = if chat_id == 0 {
        None
    } else {
        Some(ChatId::new(chat_id))
    };

    block_on(get_securejoin_qr_svg(ctx, chat_id))
        .unwrap_or_else(|_| "".to_string())
        .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_join_securejoin(
    context: *mut dc_context_t,
    qr: *const libc::c_char,
) -> u32 {
    if context.is_null() || qr.is_null() {
        eprintln!("ignoring careless call to dc_join_securejoin()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        securejoin::join_securejoin(ctx, &to_string_lossy(qr))
            .await
            .map(|chatid| chatid.to_u32())
            .context("failed dc_join_securejoin() call")
            .log_err(ctx)
            .unwrap_or_default()
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_send_locations_to_chat(
    context: *mut dc_context_t,
    chat_id: u32,
    seconds: libc::c_int,
) {
    if context.is_null() || chat_id <= constants::DC_CHAT_ID_LAST_SPECIAL.to_u32() || seconds < 0 {
        eprintln!("ignoring careless call to dc_send_locations_to_chat()");
        return;
    }
    let ctx = &*context;

    block_on(location::send_locations_to_chat(
        ctx,
        ChatId::new(chat_id),
        seconds as i64,
    ))
    .context("Failed dc_send_locations_to_chat()")
    .log_err(ctx)
    .ok();
}

#[no_mangle]
pub unsafe extern "C" fn dc_is_sending_locations_to_chat(
    context: *mut dc_context_t,
    chat_id: u32,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_is_sending_locations_to_chat()");
        return 0;
    }
    let ctx = &*context;
    let chat_id = if chat_id == 0 {
        None
    } else {
        Some(ChatId::new(chat_id))
    };

    block_on(location::is_sending_locations_to_chat(ctx, chat_id))
        .unwrap_or_log_default(ctx, "Failed dc_is_sending_locations_to_chat()") as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_set_location(
    context: *mut dc_context_t,
    latitude: libc::c_double,
    longitude: libc::c_double,
    accuracy: libc::c_double,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_set_location()");
        return 0;
    }
    let ctx = &*context;

    block_on(async move {
        location::set(ctx, latitude, longitude, accuracy)
            .await
            .log_err(ctx)
            .unwrap_or_default()
    }) as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_locations(
    context: *mut dc_context_t,
    chat_id: u32,
    contact_id: u32,
    timestamp_begin: i64,
    timestamp_end: i64,
) -> *mut dc_array::dc_array_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_locations()");
        return ptr::null_mut();
    }
    let ctx = &*context;
    let chat_id = if chat_id == 0 {
        None
    } else {
        Some(ChatId::new(chat_id))
    };
    let contact_id = if contact_id == 0 {
        None
    } else {
        Some(contact_id)
    };

    block_on(async move {
        let res = location::get_range(ctx, chat_id, contact_id, timestamp_begin, timestamp_end)
            .await
            .unwrap_or_log_default(ctx, "Failed get_locations");
        Box::into_raw(Box::new(dc_array_t::from(res)))
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_delete_all_locations(context: *mut dc_context_t) {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_delete_all_locations()");
        return;
    }
    let ctx = &*context;

    block_on(async move {
        location::delete_all(ctx)
            .await
            .context("Failed to delete locations")
            .log_err(ctx)
            .ok()
    });
}

#[no_mangle]
pub unsafe extern "C" fn dc_create_qr_svg(payload: *const libc::c_char) -> *mut libc::c_char {
    if payload.is_null() {
        eprintln!("ignoring careless call to dc_create_qr_svg()");
        return "".strdup();
    }

    create_qr_svg(&to_string_lossy(payload))
        .unwrap_or_else(|_| "".to_string())
        .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_get_last_error(context: *mut dc_context_t) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_get_last_error()");
        return "".strdup();
    }
    let ctx = &*context;
    ctx.get_last_error().strdup()
}

// dc_array_t

pub type dc_array_t = dc_array::dc_array_t;

#[no_mangle]
pub unsafe extern "C" fn dc_array_unref(a: *mut dc_array::dc_array_t) {
    if a.is_null() {
        eprintln!("ignoring careless call to dc_array_unref()");
        return;
    }

    drop(Box::from_raw(a));
}

#[no_mangle]
pub unsafe extern "C" fn dc_array_get_cnt(array: *const dc_array_t) -> libc::size_t {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_get_cnt()");
        return 0;
    }

    (*array).len()
}
#[no_mangle]
pub unsafe extern "C" fn dc_array_get_id(array: *const dc_array_t, index: libc::size_t) -> u32 {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_get_id()");
        return 0;
    }

    (*array).get_id(index)
}
#[no_mangle]
pub unsafe extern "C" fn dc_array_get_latitude(
    array: *const dc_array_t,
    index: libc::size_t,
) -> libc::c_double {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_get_latitude()");
        return 0.0;
    }

    (*array).get_location(index).latitude
}
#[no_mangle]
pub unsafe extern "C" fn dc_array_get_longitude(
    array: *const dc_array_t,
    index: libc::size_t,
) -> libc::c_double {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_get_longitude()");
        return 0.0;
    }

    (*array).get_location(index).longitude
}
#[no_mangle]
pub unsafe extern "C" fn dc_array_get_accuracy(
    array: *const dc_array_t,
    index: libc::size_t,
) -> libc::c_double {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_get_accuracy()");
        return 0.0;
    }

    (*array).get_location(index).accuracy
}
#[no_mangle]
pub unsafe extern "C" fn dc_array_get_timestamp(
    array: *const dc_array_t,
    index: libc::size_t,
) -> i64 {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_get_timestamp()");
        return 0;
    }

    (*array).get_timestamp(index).unwrap_or_default()
}
#[no_mangle]
pub unsafe extern "C" fn dc_array_get_chat_id(
    array: *const dc_array_t,
    index: libc::size_t,
) -> libc::c_uint {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_get_chat_id()");
        return 0;
    }
    (*array).get_location(index).chat_id.to_u32()
}
#[no_mangle]
pub unsafe extern "C" fn dc_array_get_contact_id(
    array: *const dc_array_t,
    index: libc::size_t,
) -> libc::c_uint {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_get_contact_id()");
        return 0;
    }

    (*array).get_location(index).contact_id.to_u32()
}
#[no_mangle]
pub unsafe extern "C" fn dc_array_get_msg_id(
    array: *const dc_array_t,
    index: libc::size_t,
) -> libc::c_uint {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_get_msg_id()");
        return 0;
    }

    (*array).get_location(index).msg_id
}
#[no_mangle]
pub unsafe extern "C" fn dc_array_get_marker(
    array: *const dc_array_t,
    index: libc::size_t,
) -> *mut libc::c_char {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_get_marker()");
        return std::ptr::null_mut(); // NULL explicitly defined as "no markers"
    }

    if let Some(s) = (*array).get_marker(index) {
        s.strdup()
    } else {
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_array_search_id(
    array: *const dc_array_t,
    needle: libc::c_uint,
    ret_index: *mut libc::size_t,
) -> libc::c_int {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_search_id()");
        return 0;
    }

    if let Some(i) = (*array).search_id(needle) {
        if !ret_index.is_null() {
            *ret_index = i
        }
        1
    } else {
        0
    }
}

// Return the independent-state of the location at the given index.
// Independent locations do not belong to the track of the user.
// Returns 1 if location belongs to the track of the user,
// 0 if location was reported independently.
#[no_mangle]
pub unsafe fn dc_array_is_independent(
    array: *const dc_array_t,
    index: libc::size_t,
) -> libc::c_int {
    if array.is_null() {
        eprintln!("ignoring careless call to dc_array_is_independent()");
        return 0;
    }

    (*array).get_location(index).independent as libc::c_int
}

// dc_chatlist_t

/// FFI struct for [dc_chatlist_t]
///
/// This is the structure behind [dc_chatlist_t] which is the opaque
/// structure representing a chatlist in the FFI API.  It exists
/// because the FFI API has a reference from the message to the
/// context, but the Rust API does not, so the FFI layer needs to glue
/// these together.
pub struct ChatlistWrapper {
    context: *const dc_context_t,
    list: chatlist::Chatlist,
}

pub type dc_chatlist_t = ChatlistWrapper;

#[no_mangle]
pub unsafe extern "C" fn dc_chatlist_unref(chatlist: *mut dc_chatlist_t) {
    if chatlist.is_null() {
        eprintln!("ignoring careless call to dc_chatlist_unref()");
        return;
    }
    drop(Box::from_raw(chatlist));
}

#[no_mangle]
pub unsafe extern "C" fn dc_chatlist_get_cnt(chatlist: *mut dc_chatlist_t) -> libc::size_t {
    if chatlist.is_null() {
        eprintln!("ignoring careless call to dc_chatlist_get_cnt()");
        return 0;
    }
    let ffi_list = &*chatlist;
    ffi_list.list.len() as libc::size_t
}

#[no_mangle]
pub unsafe extern "C" fn dc_chatlist_get_chat_id(
    chatlist: *mut dc_chatlist_t,
    index: libc::size_t,
) -> u32 {
    if chatlist.is_null() {
        eprintln!("ignoring careless call to dc_chatlist_get_chat_id()");
        return 0;
    }
    let ffi_list = &*chatlist;
    let ctx = &*ffi_list.context;
    match ffi_list.list.get_chat_id(index) {
        Ok(chat_id) => chat_id.to_u32(),
        Err(err) => {
            warn!(ctx, "get_chat_id failed: {err:#}");
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_chatlist_get_msg_id(
    chatlist: *mut dc_chatlist_t,
    index: libc::size_t,
) -> u32 {
    if chatlist.is_null() {
        eprintln!("ignoring careless call to dc_chatlist_get_msg_id()");
        return 0;
    }
    let ffi_list = &*chatlist;
    let ctx = &*ffi_list.context;
    match ffi_list.list.get_msg_id(index) {
        Ok(msg_id) => msg_id.map_or(0, |msg_id| msg_id.to_u32()),
        Err(err) => {
            warn!(ctx, "get_msg_id failed: {err:#}");
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_chatlist_get_summary(
    chatlist: *mut dc_chatlist_t,
    index: libc::size_t,
    chat: *mut dc_chat_t,
) -> *mut dc_lot_t {
    if chatlist.is_null() {
        eprintln!("ignoring careless call to dc_chatlist_get_summary()");
        return ptr::null_mut();
    }
    let maybe_chat = if chat.is_null() {
        None
    } else {
        let ffi_chat = &*chat;
        Some(&ffi_chat.chat)
    };
    let ffi_list = &*chatlist;
    let ctx = &*ffi_list.context;

    block_on(async move {
        let summary = ffi_list
            .list
            .get_summary(ctx, index, maybe_chat)
            .await
            .context("get_summary failed")
            .log_err(ctx)
            .unwrap_or_default();
        Box::into_raw(Box::new(summary.into()))
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_chatlist_get_summary2(
    context: *mut dc_context_t,
    chat_id: u32,
    msg_id: u32,
) -> *mut dc_lot_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_chatlist_get_summary2()");
        return ptr::null_mut();
    }
    let ctx = &*context;
    let msg_id = if msg_id == 0 {
        None
    } else {
        Some(MsgId::new(msg_id))
    };
    let summary = block_on(Chatlist::get_summary2(
        ctx,
        ChatId::new(chat_id),
        msg_id,
        None,
    ))
    .context("get_summary2 failed")
    .log_err(ctx)
    .unwrap_or_default();
    Box::into_raw(Box::new(summary.into()))
}

#[no_mangle]
pub unsafe extern "C" fn dc_chatlist_get_context(
    chatlist: *mut dc_chatlist_t,
) -> *const dc_context_t {
    if chatlist.is_null() {
        eprintln!("ignoring careless call to dc_chatlist_get_context()");
        return ptr::null_mut();
    }
    let ffi_list = &*chatlist;
    ffi_list.context
}

// dc_chat_t

/// FFI struct for [dc_chat_t]
///
/// This is the structure behind [dc_chat_t] which is the opaque
/// structure representing a chat in the FFI API.  It exists
/// because the FFI API has a reference from the message to the
/// context, but the Rust API does not, so the FFI layer needs to glue
/// these together.
pub struct ChatWrapper {
    context: Context,
    chat: chat::Chat,
}

pub type dc_chat_t = ChatWrapper;

#[no_mangle]
pub unsafe extern "C" fn dc_chat_unref(chat: *mut dc_chat_t) {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_unref()");
        return;
    }

    drop(Box::from_raw(chat));
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_get_id(chat: *mut dc_chat_t) -> u32 {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_get_id()");
        return 0;
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.get_id().to_u32()
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_get_type(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_get_type()");
        return 0;
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.get_type() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_get_name(chat: *mut dc_chat_t) -> *mut libc::c_char {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_get_name()");
        return "".strdup();
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.get_name().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_get_mailinglist_addr(chat: *mut dc_chat_t) -> *mut libc::c_char {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_get_mailinglist_addr()");
        return "".strdup();
    }
    let ffi_chat = &*chat;
    ffi_chat
        .chat
        .get_mailinglist_addr()
        .unwrap_or_default()
        .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_get_profile_image(chat: *mut dc_chat_t) -> *mut libc::c_char {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_get_profile_image()");
        return ptr::null_mut(); // NULL explicitly defined as "no image"
    }
    let ffi_chat = &*chat;

    block_on(async move {
        match ffi_chat.chat.get_profile_image(&ffi_chat.context).await {
            Ok(Some(p)) => p.to_string_lossy().strdup(),
            Ok(None) => ptr::null_mut(),
            Err(err) => {
                error!(ffi_chat.context, "failed to get profile image: {err:#}");
                ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_get_color(chat: *mut dc_chat_t) -> u32 {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_get_color()");
        return 0;
    }
    let ffi_chat = &*chat;

    block_on(ffi_chat.chat.get_color(&ffi_chat.context))
        .unwrap_or_log_default(&ffi_chat.context, "Failed get_color")
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_get_visibility(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_get_visibility()");
        return 0;
    }
    let ffi_chat = &*chat;
    match ffi_chat.chat.visibility {
        ChatVisibility::Normal => 0,
        ChatVisibility::Archived => 1,
        ChatVisibility::Pinned => 2,
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_is_contact_request(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_is_contact_request()");
        return 0;
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.is_contact_request() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_is_unpromoted(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_is_unpromoted()");
        return 0;
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.is_unpromoted() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_is_self_talk(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_is_self_talk()");
        return 0;
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.is_self_talk() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_is_device_talk(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_is_device_talk()");
        return 0;
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.is_device_talk() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_can_send(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_can_send()");
        return 0;
    }
    let ffi_chat = &*chat;
    block_on(ffi_chat.chat.can_send(&ffi_chat.context))
        .context("can_send failed")
        .log_err(&ffi_chat.context)
        .unwrap_or_default() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_is_protected(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_is_protected()");
        return 0;
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.is_protected() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_is_protection_broken(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_is_protection_broken()");
        return 0;
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.is_protection_broken() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_is_sending_locations(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_is_sending_locations()");
        return 0;
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.is_sending_locations() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_is_muted(chat: *mut dc_chat_t) -> libc::c_int {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_is_muted()");
        return 0;
    }
    let ffi_chat = &*chat;
    ffi_chat.chat.is_muted() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_get_remaining_mute_duration(chat: *mut dc_chat_t) -> i64 {
    if chat.is_null() {
        eprintln!("ignoring careless call to dc_chat_get_remaining_mute_duration()");
        return 0;
    }
    let ffi_chat = &*chat;
    if !ffi_chat.chat.is_muted() {
        return 0;
    }
    // If the chat was muted to before the epoch, it is not muted.
    match ffi_chat.chat.mute_duration {
        MuteDuration::NotMuted => 0,
        MuteDuration::Forever => -1,
        MuteDuration::Until(when) => when
            .duration_since(SystemTime::now())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_chat_get_info_json(
    context: *mut dc_context_t,
    chat_id: u32,
) -> *mut libc::c_char {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_chat_get_info_json()");
        return "".strdup();
    }
    let ctx = &*context;

    block_on(async move {
        let chat = match chat::Chat::load_from_db(ctx, ChatId::new(chat_id)).await {
            Ok(chat) => chat,
            Err(err) => {
                error!(ctx, "dc_get_chat_info_json() failed to load chat: {err:#}");
                return "".strdup();
            }
        };
        let info = match chat.get_info(ctx).await {
            Ok(info) => info,
            Err(err) => {
                error!(
                    ctx,
                    "dc_get_chat_info_json() failed to get chat info: {err:#}"
                );
                return "".strdup();
            }
        };
        serde_json::to_string(&info)
            .unwrap_or_log_default(ctx, "dc_get_chat_info_json() failed to serialise to json")
            .strdup()
    })
}

// dc_msg_t

/// FFI struct for [dc_msg_t]
///
/// This is the structure behind [dc_msg_t] which is the opaque
/// structure representing a message in the FFI API.  It exists
/// because the FFI API has a reference from the message to the
/// context, but the Rust API does not, so the FFI layer needs to glue
/// these together.
pub struct MessageWrapper {
    context: *const dc_context_t,
    message: message::Message,
}

pub type dc_msg_t = MessageWrapper;

#[no_mangle]
pub unsafe extern "C" fn dc_msg_new(
    context: *mut dc_context_t,
    viewtype: libc::c_int,
) -> *mut dc_msg_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_msg_new()");
        return ptr::null_mut();
    }
    let context = &*context;
    let viewtype = from_prim(viewtype).expect(&format!("invalid viewtype = {viewtype}"));
    let msg = MessageWrapper {
        context,
        message: message::Message::new(viewtype),
    };
    Box::into_raw(Box::new(msg))
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_unref(msg: *mut dc_msg_t) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_unref()");
        return;
    }

    drop(Box::from_raw(msg));
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_id(msg: *mut dc_msg_t) -> u32 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_id()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_id().to_u32()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_from_id(msg: *mut dc_msg_t) -> u32 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_from_id()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_from_id().to_u32()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_chat_id(msg: *mut dc_msg_t) -> u32 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_chat_id()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_chat_id().to_u32()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_viewtype(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_viewtype()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg
        .message
        .get_viewtype()
        .to_i64()
        .expect("impossible: Viewtype -> i64 conversion failed") as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_state(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_state()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_state() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_download_state(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_download_state()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.download_state() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_timestamp(msg: *mut dc_msg_t) -> i64 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_received_timestamp()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_timestamp()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_received_timestamp(msg: *mut dc_msg_t) -> i64 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_received_timestamp()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_received_timestamp()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_sort_timestamp(msg: *mut dc_msg_t) -> i64 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_sort_timestamp()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_sort_timestamp()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_text(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_text()");
        return "".strdup();
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_text().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_subject(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_subject()");
        return "".strdup();
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_subject().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_file(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_file()");
        return "".strdup();
    }
    let ffi_msg = &*msg;
    let ctx = &*ffi_msg.context;
    ffi_msg
        .message
        .get_file(ctx)
        .map(|p| p.to_string_lossy().strdup())
        .unwrap_or_else(|| "".strdup())
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_save_file(
    msg: *mut dc_msg_t,
    path: *const libc::c_char,
) -> libc::c_int {
    if msg.is_null() || path.is_null() {
        eprintln!("ignoring careless call to dc_msg_save_file()");
        return 0;
    }
    let ffi_msg = &*msg;
    let ctx = &*ffi_msg.context;
    let path = to_string_lossy(path);
    let r = block_on(
        ffi_msg
            .message
            .save_file(ctx, &std::path::PathBuf::from(path)),
    );
    match r {
        Ok(()) => 1,
        Err(_) => {
            r.context("Failed to save file from message")
                .log_err(ctx)
                .unwrap_or_default();
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_filename(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_filename()");
        return "".strdup();
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_filename().unwrap_or_default().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_webxdc_blob(
    msg: *mut dc_msg_t,
    filename: *const libc::c_char,
    ret_bytes: *mut libc::size_t,
) -> *mut libc::c_char {
    if msg.is_null() || filename.is_null() || ret_bytes.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_webxdc_blob()");
        return ptr::null_mut();
    }
    let ffi_msg = &*msg;
    let ctx = &*ffi_msg.context;
    let blob = block_on(async move {
        ffi_msg
            .message
            .get_webxdc_blob(ctx, &to_string_lossy(filename))
            .await
    });
    match blob {
        Ok(blob) => {
            *ret_bytes = blob.len();
            let ptr = libc::malloc(*ret_bytes);
            libc::memcpy(ptr, blob.as_ptr() as *mut libc::c_void, *ret_bytes);
            ptr as *mut libc::c_char
        }
        Err(err) => {
            eprintln!("failed read blob from archive: {err}");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_webxdc_info(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_webxdc_info()");
        return "".strdup();
    }
    let ffi_msg = &*msg;
    let ctx = &*ffi_msg.context;

    block_on(async move {
        let info = match ffi_msg.message.get_webxdc_info(ctx).await {
            Ok(info) => info,
            Err(err) => {
                error!(ctx, "dc_msg_get_webxdc_info() failed to get info: {err:#}");
                return "".strdup();
            }
        };
        serde_json::to_string(&info)
            .unwrap_or_log_default(ctx, "dc_msg_get_webxdc_info() failed to serialise to json")
            .strdup()
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_filemime(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_filemime()");
        return "".strdup();
    }
    let ffi_msg = &*msg;
    if let Some(x) = ffi_msg.message.get_filemime() {
        x.strdup()
    } else {
        "".strdup()
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_filebytes(msg: *mut dc_msg_t) -> u64 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_filebytes()");
        return 0;
    }
    let ffi_msg = &*msg;
    let ctx = &*ffi_msg.context;

    block_on(ffi_msg.message.get_filebytes(ctx))
        .unwrap_or_log_default(ctx, "Cannot get file size")
        .unwrap_or_default()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_width(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_width()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_width()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_height(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_height()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_height()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_duration(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_duration()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_duration()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_showpadlock(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_showpadlock()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_showpadlock() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_is_bot(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_is_bot()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.is_bot() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_ephemeral_timer(msg: *mut dc_msg_t) -> u32 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_ephemeral_timer()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_ephemeral_timer().to_u32()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_ephemeral_timestamp(msg: *mut dc_msg_t) -> i64 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_ephemeral_timer()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_ephemeral_timestamp()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_summary(
    msg: *mut dc_msg_t,
    chat: *mut dc_chat_t,
) -> *mut dc_lot_t {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_summary()");
        return ptr::null_mut();
    }
    let maybe_chat = if chat.is_null() {
        None
    } else {
        let ffi_chat = &*chat;
        Some(&ffi_chat.chat)
    };
    let ffi_msg = &mut *msg;
    let ctx = &*ffi_msg.context;

    let summary = block_on(ffi_msg.message.get_summary(ctx, maybe_chat))
        .context("dc_msg_get_summary failed")
        .log_err(ctx)
        .unwrap_or_default();
    Box::into_raw(Box::new(summary.into()))
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_summarytext(
    msg: *mut dc_msg_t,
    approx_characters: libc::c_int,
) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_summarytext()");
        return "".strdup();
    }
    let ffi_msg = &mut *msg;
    let ctx = &*ffi_msg.context;

    let summary = block_on(ffi_msg.message.get_summary(ctx, None))
        .context("dc_msg_get_summarytext failed")
        .log_err(ctx)
        .unwrap_or_default();
    match usize::try_from(approx_characters) {
        Ok(chars) => summary.truncated_text(chars).strdup(),
        Err(_) => summary.text.strdup(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_override_sender_name(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_override_sender_name()");
        return "".strdup();
    }
    let ffi_msg = &mut *msg;

    ffi_msg.message.get_override_sender_name().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_has_deviating_timestamp(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_has_deviating_timestamp()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.has_deviating_timestamp().into()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_has_location(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_has_location()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.has_location() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_is_sent(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_is_sent()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.is_sent().into()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_is_forwarded(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_is_forwarded()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.is_forwarded().into()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_is_edited(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_is_edited()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.is_edited().into()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_is_info(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_is_info()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.is_info().into()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_info_type(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_info_type()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_info_type() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_info_contact_id(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_info_contact_id()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg
        .message
        .get_info_contact_id()
        .map(|id| id.to_u32())
        .unwrap_or_default()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_webxdc_href(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_webxdc_href()");
        return "".strdup();
    }

    let ffi_msg = &*msg;
    ffi_msg.message.get_webxdc_href().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_is_setupmessage(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_is_setupmessage()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.is_setupmessage().into()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_has_html(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_has_html()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.has_html().into()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_videochat_url(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_videochat_url()");
        return "".strdup();
    }
    let ffi_msg = &*msg;

    ffi_msg
        .message
        .get_videochat_url()
        .unwrap_or_default()
        .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_videochat_type(msg: *mut dc_msg_t) -> libc::c_int {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_videochat_type()");
        return 0;
    }
    let ffi_msg = &*msg;
    ffi_msg.message.get_videochat_type().unwrap_or_default() as i32
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_setupcodebegin(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_setupcodebegin()");
        return "".strdup();
    }
    let ffi_msg = &*msg;
    let ctx = &*ffi_msg.context;

    block_on(ffi_msg.message.get_setupcodebegin(ctx))
        .unwrap_or_default()
        .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_set_text(msg: *mut dc_msg_t, text: *const libc::c_char) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_set_text()");
        return;
    }
    let ffi_msg = &mut *msg;
    ffi_msg.message.set_text(to_string_lossy(text))
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_set_html(msg: *mut dc_msg_t, html: *const libc::c_char) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_set_html()");
        return;
    }
    let ffi_msg = &mut *msg;
    ffi_msg.message.set_html(to_opt_string_lossy(html))
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_set_subject(msg: *mut dc_msg_t, subject: *const libc::c_char) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_subject()");
        return;
    }
    let ffi_msg = &mut *msg;
    ffi_msg.message.set_subject(to_string_lossy(subject));
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_set_override_sender_name(
    msg: *mut dc_msg_t,
    name: *const libc::c_char,
) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_set_override_sender_name()");
        return;
    }
    let ffi_msg = &mut *msg;
    ffi_msg
        .message
        .set_override_sender_name(to_opt_string_lossy(name))
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_set_file_and_deduplicate(
    msg: *mut dc_msg_t,
    file: *const libc::c_char,
    name: *const libc::c_char,
    filemime: *const libc::c_char,
) {
    if msg.is_null() || file.is_null() {
        eprintln!("ignoring careless call to dc_msg_set_file_and_deduplicate()");
        return;
    }
    let ffi_msg = &mut *msg;
    let ctx = &*ffi_msg.context;

    ffi_msg
        .message
        .set_file_and_deduplicate(
            ctx,
            as_path(file),
            to_opt_string_lossy(name).as_deref(),
            to_opt_string_lossy(filemime).as_deref(),
        )
        .context("Failed to set file")
        .log_err(&*ffi_msg.context)
        .ok();
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_set_dimension(
    msg: *mut dc_msg_t,
    width: libc::c_int,
    height: libc::c_int,
) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_set_dimension()");
        return;
    }
    let ffi_msg = &mut *msg;
    ffi_msg.message.set_dimension(width, height)
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_set_duration(msg: *mut dc_msg_t, duration: libc::c_int) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_set_duration()");
        return;
    }
    let ffi_msg = &mut *msg;
    ffi_msg.message.set_duration(duration)
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_set_location(
    msg: *mut dc_msg_t,
    latitude: libc::c_double,
    longitude: libc::c_double,
) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_set_location()");
        return;
    }
    let ffi_msg = &mut *msg;
    ffi_msg.message.set_location(latitude, longitude)
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_latefiling_mediasize(
    msg: *mut dc_msg_t,
    width: libc::c_int,
    height: libc::c_int,
    duration: libc::c_int,
) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_latefiling_mediasize()");
        return;
    }
    let ffi_msg = &mut *msg;
    let ctx = &*ffi_msg.context;

    block_on({
        ffi_msg
            .message
            .latefiling_mediasize(ctx, width, height, duration)
    })
    .context("Cannot set media size")
    .log_err(ctx)
    .ok();
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_error(msg: *mut dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_error()");
        return ptr::null_mut();
    }
    let ffi_msg = &*msg;
    match ffi_msg.message.error() {
        Some(error) => error.strdup(),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_set_quote(msg: *mut dc_msg_t, quote: *const dc_msg_t) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_set_quote()");
        return;
    }
    let ffi_msg = &mut *msg;
    let quote_msg = if quote.is_null() {
        None
    } else {
        let ffi_quote = &*quote;
        if ffi_msg.context != ffi_quote.context {
            eprintln!("ignoring attempt to quote message from a different context");
            return;
        }
        Some(&ffi_quote.message)
    };

    block_on(async move {
        ffi_msg
            .message
            .set_quote(&*ffi_msg.context, quote_msg)
            .await
            .context("failed to set quote")
            .log_err(&*ffi_msg.context)
            .ok();
    });
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_quoted_text(msg: *const dc_msg_t) -> *mut libc::c_char {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_quoted_text()");
        return ptr::null_mut();
    }
    let ffi_msg: &MessageWrapper = &*msg;
    ffi_msg
        .message
        .quoted_text()
        .map_or_else(ptr::null_mut, |s| s.strdup())
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_quoted_msg(msg: *const dc_msg_t) -> *mut dc_msg_t {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_get_quoted_msg()");
        return ptr::null_mut();
    }
    let ffi_msg: &MessageWrapper = &*msg;
    let context = &*ffi_msg.context;
    let res = block_on(async move {
        ffi_msg
            .message
            .quoted_message(context)
            .await
            .context("failed to get quoted message")
            .log_err(context)
            .unwrap_or(None)
    });

    match res {
        Some(message) => Box::into_raw(Box::new(MessageWrapper { context, message })),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_parent(msg: *const dc_msg_t) -> *mut dc_msg_t {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_parent()");
        return ptr::null_mut();
    }
    let ffi_msg: &MessageWrapper = &*msg;
    let context = &*ffi_msg.context;
    let res = block_on(async move {
        ffi_msg
            .message
            .parent(context)
            .await
            .context("failed to get parent message")
            .log_err(context)
            .unwrap_or(None)
    });

    match res {
        Some(message) => Box::into_raw(Box::new(MessageWrapper { context, message })),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_original_msg_id(msg: *const dc_msg_t) -> u32 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_original_msg_id()");
        return 0;
    }
    let ffi_msg: &MessageWrapper = &*msg;
    let context = &*ffi_msg.context;
    block_on(async move {
        ffi_msg
            .message
            .get_original_msg_id(context)
            .await
            .context("failed to get original message")
            .log_err(context)
            .unwrap_or_default()
            .map(|id| id.to_u32())
            .unwrap_or(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_get_saved_msg_id(msg: *const dc_msg_t) -> u32 {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_get_saved_msg_id()");
        return 0;
    }
    let ffi_msg: &MessageWrapper = &*msg;
    let context = &*ffi_msg.context;
    block_on(async move {
        ffi_msg
            .message
            .get_saved_msg_id(context)
            .await
            .context("failed to get original message")
            .log_err(context)
            .unwrap_or_default()
            .map(|id| id.to_u32())
            .unwrap_or(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_msg_force_plaintext(msg: *mut dc_msg_t) {
    if msg.is_null() {
        eprintln!("ignoring careless call to dc_msg_force_plaintext()");
        return;
    }
    let ffi_msg = &mut *msg;
    ffi_msg.message.force_plaintext();
}

// dc_contact_t

/// FFI struct for [dc_contact_t]
///
/// This is the structure behind [dc_contact_t] which is the opaque
/// structure representing a contact in the FFI API.  It exists
/// because the FFI API has a reference from the message to the
/// context, but the Rust API does not, so the FFI layer needs to glue
/// these together.
pub struct ContactWrapper {
    context: *const dc_context_t,
    contact: contact::Contact,
}

pub type dc_contact_t = ContactWrapper;

#[no_mangle]
pub unsafe extern "C" fn dc_contact_unref(contact: *mut dc_contact_t) {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_unref()");
        return;
    }
    drop(Box::from_raw(contact));
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_id(contact: *mut dc_contact_t) -> u32 {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_id()");
        return 0;
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.get_id().to_u32()
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_addr(contact: *mut dc_contact_t) -> *mut libc::c_char {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_addr()");
        return "".strdup();
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.get_addr().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_name(contact: *mut dc_contact_t) -> *mut libc::c_char {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_name()");
        return "".strdup();
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.get_name().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_auth_name(contact: *mut dc_contact_t) -> *mut libc::c_char {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_auth_name()");
        return "".strdup();
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.get_authname().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_display_name(
    contact: *mut dc_contact_t,
) -> *mut libc::c_char {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_display_name()");
        return "".strdup();
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.get_display_name().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_name_n_addr(
    contact: *mut dc_contact_t,
) -> *mut libc::c_char {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_name_n_addr()");
        return "".strdup();
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.get_name_n_addr().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_profile_image(
    contact: *mut dc_contact_t,
) -> *mut libc::c_char {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_profile_image()");
        return ptr::null_mut(); // NULL explicitly defined as "no profile image"
    }
    let ffi_contact = &*contact;
    let ctx = &*ffi_contact.context;

    block_on(async move {
        ffi_contact
            .contact
            .get_profile_image(ctx)
            .await
            .unwrap_or_log_default(ctx, "failed to get profile image")
            .map(|p| p.to_string_lossy().strdup())
            .unwrap_or_else(std::ptr::null_mut)
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_color(contact: *mut dc_contact_t) -> u32 {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_color()");
        return 0;
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.get_color()
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_status(contact: *mut dc_contact_t) -> *mut libc::c_char {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_status()");
        return "".strdup();
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.get_status().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_last_seen(contact: *mut dc_contact_t) -> i64 {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_last_seen()");
        return 0;
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.last_seen()
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_was_seen_recently(contact: *mut dc_contact_t) -> libc::c_int {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_was_seen_recently()");
        return 0;
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.was_seen_recently() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_is_blocked(contact: *mut dc_contact_t) -> libc::c_int {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_is_blocked()");
        return 0;
    }
    let ffi_contact = &*contact;
    ffi_contact.contact.is_blocked() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_is_verified(contact: *mut dc_contact_t) -> libc::c_int {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_is_verified()");
        return 0;
    }
    let ffi_contact = &*contact;
    let ctx = &*ffi_contact.context;

    if block_on(ffi_contact.contact.is_verified(ctx))
        .context("is_verified failed")
        .log_err(ctx)
        .unwrap_or_default()
    {
        // Return value is essentially a boolean,
        // but we return 2 for true for backwards compatibility.
        2
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_is_bot(contact: *mut dc_contact_t) -> libc::c_int {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_is_bot()");
        return 0;
    }
    (*contact).contact.is_bot() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_contact_get_verifier_id(contact: *mut dc_contact_t) -> u32 {
    if contact.is_null() {
        eprintln!("ignoring careless call to dc_contact_get_verifier_id()");
        return 0;
    }
    let ffi_contact = &*contact;
    let ctx = &*ffi_contact.context;
    let verifier_contact_id = block_on(ffi_contact.contact.get_verifier_id(ctx))
        .context("failed to get verifier")
        .log_err(ctx)
        .unwrap_or_default()
        .unwrap_or_default();

    verifier_contact_id.to_u32()
}
// dc_lot_t

pub type dc_lot_t = lot::Lot;

#[no_mangle]
pub unsafe extern "C" fn dc_lot_unref(lot: *mut dc_lot_t) {
    if lot.is_null() {
        eprintln!("ignoring careless call to dc_lot_unref()");
        return;
    }

    drop(Box::from_raw(lot));
}

#[no_mangle]
pub unsafe extern "C" fn dc_lot_get_text1(lot: *mut dc_lot_t) -> *mut libc::c_char {
    if lot.is_null() {
        eprintln!("ignoring careless call to dc_lot_get_text1()");
        return ptr::null_mut(); // NULL explicitly defined as "there is no such text"
    }

    let lot = &*lot;
    lot.get_text1().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_lot_get_text2(lot: *mut dc_lot_t) -> *mut libc::c_char {
    if lot.is_null() {
        eprintln!("ignoring careless call to dc_lot_get_text2()");
        return ptr::null_mut(); // NULL explicitly defined as "there is no such text"
    }

    let lot = &*lot;
    lot.get_text2().strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_lot_get_text1_meaning(lot: *mut dc_lot_t) -> libc::c_int {
    if lot.is_null() {
        eprintln!("ignoring careless call to dc_lot_get_text1_meaning()");
        return 0;
    }

    let lot = &*lot;
    lot.get_text1_meaning() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_lot_get_state(lot: *mut dc_lot_t) -> libc::c_int {
    if lot.is_null() {
        eprintln!("ignoring careless call to dc_lot_get_state()");
        return 0;
    }

    let lot = &*lot;
    lot.get_state() as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn dc_lot_get_id(lot: *mut dc_lot_t) -> u32 {
    if lot.is_null() {
        eprintln!("ignoring careless call to dc_lot_get_id()");
        return 0;
    }

    let lot = &*lot;
    lot.get_id()
}

#[no_mangle]
pub unsafe extern "C" fn dc_lot_get_timestamp(lot: *mut dc_lot_t) -> i64 {
    if lot.is_null() {
        eprintln!("ignoring careless call to dc_lot_get_timestamp()");
        return 0;
    }

    let lot = &*lot;
    lot.get_timestamp()
}

#[no_mangle]
pub unsafe extern "C" fn dc_str_unref(s: *mut libc::c_char) {
    libc::free(s as *mut _)
}

pub struct BackupProviderWrapper {
    context: *const dc_context_t,
    provider: BackupProvider,
}

pub type dc_backup_provider_t = BackupProviderWrapper;

#[no_mangle]
pub unsafe extern "C" fn dc_backup_provider_new(
    context: *mut dc_context_t,
) -> *mut dc_backup_provider_t {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_backup_provider_new()");
        return ptr::null_mut();
    }
    let ctx = &*context;
    block_on(BackupProvider::prepare(ctx))
        .map(|provider| BackupProviderWrapper {
            context: ctx,
            provider,
        })
        .map(|ffi_provider| Box::into_raw(Box::new(ffi_provider)))
        .context("BackupProvider failed")
        .log_err(ctx)
        .set_last_error(ctx)
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn dc_backup_provider_get_qr(
    provider: *const dc_backup_provider_t,
) -> *mut libc::c_char {
    if provider.is_null() {
        eprintln!("ignoring careless call to dc_backup_provider_qr");
        return "".strdup();
    }
    let ffi_provider = &*provider;
    let ctx = &*ffi_provider.context;
    deltachat::qr::format_backup(&ffi_provider.provider.qr())
        .context("BackupProvider get_qr failed")
        .log_err(ctx)
        .set_last_error(ctx)
        .unwrap_or_default()
        .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_backup_provider_get_qr_svg(
    provider: *const dc_backup_provider_t,
) -> *mut libc::c_char {
    if provider.is_null() {
        eprintln!("ignoring careless call to dc_backup_provider_qr_svg()");
        return "".strdup();
    }
    let ffi_provider = &*provider;
    let ctx = &*ffi_provider.context;
    let provider = &ffi_provider.provider;
    block_on(generate_backup_qr(ctx, &provider.qr()))
        .context("BackupProvider get_qr_svg failed")
        .log_err(ctx)
        .set_last_error(ctx)
        .unwrap_or_default()
        .strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_backup_provider_wait(provider: *mut dc_backup_provider_t) {
    if provider.is_null() {
        eprintln!("ignoring careless call to dc_backup_provider_wait()");
        return;
    }
    let ffi_provider = &mut *provider;
    let ctx = &*ffi_provider.context;
    let provider = &mut ffi_provider.provider;
    block_on(provider)
        .context("Failed to await backup provider")
        .log_err(ctx)
        .set_last_error(ctx)
        .ok();
}

#[no_mangle]
pub unsafe extern "C" fn dc_backup_provider_unref(provider: *mut dc_backup_provider_t) {
    if provider.is_null() {
        eprintln!("ignoring careless call to dc_backup_provider_unref()");
        return;
    }
    drop(Box::from_raw(provider));
}

#[no_mangle]
pub unsafe extern "C" fn dc_receive_backup(
    context: *mut dc_context_t,
    qr: *const libc::c_char,
) -> libc::c_int {
    if context.is_null() {
        eprintln!("ignoring careless call to dc_receive_backup()");
        return 0;
    }
    let ctx = &*context;
    let qr_text = to_string_lossy(qr);
    receive_backup(ctx.clone(), qr_text)
}

// Because this is a long-running operation make sure we own the Context.  This stops a FFI
// user from deallocating it by calling unref on the object while we are using it.
fn receive_backup(ctx: Context, qr_text: String) -> libc::c_int {
    let qr = match block_on(qr::check_qr(&ctx, &qr_text))
        .context("Invalid QR code")
        .log_err(&ctx)
        .set_last_error(&ctx)
    {
        Ok(qr) => qr,
        Err(_) => return 0,
    };
    match block_on(imex::get_backup(&ctx, qr))
        .context("Get backup failed")
        .log_err(&ctx)
        .set_last_error(&ctx)
    {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

trait ResultExt<T, E> {
    /// Like `log_err()`, but:
    /// - returns the default value instead of an Err value.
    /// - emits an error instead of a warning for an [Err] result. This means
    ///   that the error will be shown to the user in a small pop-up.
    fn unwrap_or_log_default(self, context: &context::Context, message: &str) -> T;
}

impl<T: Default, E: std::fmt::Display> ResultExt<T, E> for Result<T, E> {
    fn unwrap_or_log_default(self, context: &context::Context, message: &str) -> T {
        match self {
            Ok(t) => t,
            Err(err) => {
                error!(context, "{message}: {err:#}");
                Default::default()
            }
        }
    }
}

trait ResultLastError<T, E>
where
    E: std::fmt::Display,
{
    /// Sets this `Err` value using [`Context::set_last_error`].
    ///
    /// Normally each FFI-API *should* call this if it handles an error from the Rust API:
    /// errors which need to be reported to users in response to an API call need to be
    /// propagated up the Rust API and at the FFI boundary need to be stored into the "last
    /// error" so the FFI users can retrieve an appropriate error message on failure.  Often
    /// you will want to combine this with a call to [`LogExt::log_err`].
    ///
    /// Since historically calls to the `deltachat::log::error!()` macro were (and sometimes
    /// still are) shown as error toasts to the user, this macro also calls
    /// [`Context::set_last_error`].  It is preferable however to rely on normal error
    /// propagation in Rust code however and only use this `ResultExt::set_last_error` call
    /// in the FFI layer.
    ///
    /// # Example
    ///
    /// Fully handling an error in the FFI code looks like this currently:
    ///
    /// ```no_compile
    /// some_dc_rust_api_call_returning_result()
    ///     .context("My API call failed")
    ///     .log_err(&context)
    ///     .set_last_error(&context)
    ///     .unwrap_or_default()
    /// ```
    ///
    /// As shows it is a shame the `.log_err()` call currently needs a message instead of
    /// relying on an implicit call to the [`anyhow::Context`] call if needed.  This stems
    /// from a time before we fully embraced anyhow.  Some day we'll also fix that.
    ///
    /// [`Context::set_last_error`]: context::Context::set_last_error
    fn set_last_error(self, context: &context::Context) -> Result<T, E>;
}

impl<T, E> ResultLastError<T, E> for Result<T, E>
where
    E: std::fmt::Display,
{
    fn set_last_error(self, context: &context::Context) -> Result<T, E> {
        if let Err(ref err) = self {
            context.set_last_error(&format!("{err:#}"));
        }
        self
    }
}

fn convert_and_prune_message_ids(msg_ids: *const u32, msg_cnt: libc::c_int) -> Vec<MsgId> {
    let ids = unsafe { std::slice::from_raw_parts(msg_ids, msg_cnt as usize) };
    let msg_ids: Vec<MsgId> = ids
        .iter()
        .filter(|id| **id > DC_MSG_ID_LAST_SPECIAL)
        .map(|id| MsgId::new(*id))
        .collect();

    msg_ids
}

// dc_provider_t

pub type dc_provider_t = provider::Provider;

#[no_mangle]
pub unsafe extern "C" fn dc_provider_new_from_email(
    context: *const dc_context_t,
    addr: *const libc::c_char,
) -> *const dc_provider_t {
    if context.is_null() || addr.is_null() {
        eprintln!("ignoring careless call to dc_provider_new_from_email()");
        return ptr::null();
    }
    let addr = to_string_lossy(addr);

    let ctx = &*context;

    match block_on(provider::get_provider_info_by_addr(
        ctx,
        addr.as_str(),
        true,
    ))
    .log_err(ctx)
    .unwrap_or_default()
    {
        Some(provider) => provider,
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_provider_new_from_email_with_dns(
    context: *const dc_context_t,
    addr: *const libc::c_char,
) -> *const dc_provider_t {
    if context.is_null() || addr.is_null() {
        eprintln!("ignoring careless call to dc_provider_new_from_email_with_dns()");
        return ptr::null();
    }
    let addr = to_string_lossy(addr);

    let ctx = &*context;
    let proxy_enabled = block_on(ctx.get_config_bool(config::Config::ProxyEnabled))
        .context("Can't get config")
        .log_err(ctx);

    match proxy_enabled {
        Ok(proxy_enabled) => {
            match block_on(provider::get_provider_info_by_addr(
                ctx,
                addr.as_str(),
                proxy_enabled,
            ))
            .log_err(ctx)
            .unwrap_or_default()
            {
                Some(provider) => provider,
                None => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dc_provider_get_overview_page(
    provider: *const dc_provider_t,
) -> *mut libc::c_char {
    if provider.is_null() {
        eprintln!("ignoring careless call to dc_provider_get_overview_page()");
        return "".strdup();
    }
    let provider = &*provider;
    provider.overview_page.strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_provider_get_before_login_hint(
    provider: *const dc_provider_t,
) -> *mut libc::c_char {
    if provider.is_null() {
        eprintln!("ignoring careless call to dc_provider_get_before_login_hint()");
        return "".strdup();
    }
    let provider = &*provider;
    provider.before_login_hint.strdup()
}

#[no_mangle]
pub unsafe extern "C" fn dc_provider_get_status(provider: *const dc_provider_t) -> libc::c_int {
    if provider.is_null() {
        eprintln!("ignoring careless call to dc_provider_get_status()");
        return 0;
    }
    let provider = &*provider;
    provider.status as libc::c_int
}

#[no_mangle]
#[allow(clippy::needless_return)]
pub unsafe extern "C" fn dc_provider_unref(provider: *mut dc_provider_t) {
    if provider.is_null() {
        eprintln!("ignoring careless call to dc_provider_unref()");
        return;
    }
    // currently, there is nothing to free, the provider info is a static object.
    // this may change once we start localizing string.
}

// -- Accounts

/// Reader-writer lock wrapper for accounts manager to guarantee thread safety when using
/// `dc_accounts_t` in multiple threads at once.
pub struct AccountsWrapper {
    inner: Arc<RwLock<Accounts>>,
}

impl Deref for AccountsWrapper {
    type Target = Arc<RwLock<Accounts>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AccountsWrapper {
    fn new(accounts: Accounts) -> Self {
        let inner = Arc::new(RwLock::new(accounts));
        Self { inner }
    }
}

/// Struct representing a list of deltachat accounts.
pub type dc_accounts_t = AccountsWrapper;

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_new(
    dir: *const libc::c_char,
    writable: libc::c_int,
) -> *mut dc_accounts_t {
    setup_panic!();

    if dir.is_null() {
        eprintln!("ignoring careless call to dc_accounts_new()");
        return ptr::null_mut();
    }

    let accs = block_on(Accounts::new(as_path(dir).into(), writable != 0));

    match accs {
        Ok(accs) => Box::into_raw(Box::new(AccountsWrapper::new(accs))),
        Err(err) => {
            // We are using Anyhow's .context() and to show the inner error, too, we need the {:#}:
            eprintln!("failed to create accounts: {err:#}");
            ptr::null_mut()
        }
    }
}

/// Release the accounts structure.
///
/// This function releases the memory of the `dc_accounts_t` structure.
#[no_mangle]
pub unsafe extern "C" fn dc_accounts_unref(accounts: *mut dc_accounts_t) {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_unref()");
        return;
    }
    let _ = Box::from_raw(accounts);
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_get_account(
    accounts: *mut dc_accounts_t,
    id: u32,
) -> *mut dc_context_t {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_get_account()");
        return ptr::null_mut();
    }

    let accounts = &*accounts;
    block_on(accounts.read())
        .get_account(id)
        .map(|ctx| Box::into_raw(Box::new(ctx)))
        .unwrap_or_else(std::ptr::null_mut)
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_get_selected_account(
    accounts: *mut dc_accounts_t,
) -> *mut dc_context_t {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_get_selected_account()");
        return ptr::null_mut();
    }

    let accounts = &*accounts;
    block_on(accounts.read())
        .get_selected_account()
        .map(|ctx| Box::into_raw(Box::new(ctx)))
        .unwrap_or_else(std::ptr::null_mut)
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_select_account(
    accounts: *mut dc_accounts_t,
    id: u32,
) -> libc::c_int {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_select_account()");
        return 0;
    }

    let accounts = &*accounts;
    block_on(async move {
        let mut accounts = accounts.write().await;
        match accounts.select_account(id).await {
            Ok(()) => 1,
            Err(err) => {
                accounts.emit_event(EventType::Error(format!(
                    "Failed to select account: {err:#}"
                )));
                0
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_add_account(accounts: *mut dc_accounts_t) -> u32 {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_add_account()");
        return 0;
    }

    let accounts = &mut *accounts;

    block_on(async move {
        let mut accounts = accounts.write().await;
        match accounts.add_account().await {
            Ok(id) => id,
            Err(err) => {
                accounts.emit_event(EventType::Error(format!("Failed to add account: {err:#}")));
                0
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_add_closed_account(accounts: *mut dc_accounts_t) -> u32 {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_add_closed_account()");
        return 0;
    }

    let accounts = &mut *accounts;

    block_on(async move {
        let mut accounts = accounts.write().await;
        match accounts.add_closed_account().await {
            Ok(id) => id,
            Err(err) => {
                accounts.emit_event(EventType::Error(format!("Failed to add account: {err:#}")));
                0
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_remove_account(
    accounts: *mut dc_accounts_t,
    id: u32,
) -> libc::c_int {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_remove_account()");
        return 0;
    }

    let accounts = &mut *accounts;

    block_on(async move {
        let mut accounts = accounts.write().await;
        match accounts.remove_account(id).await {
            Ok(()) => 1,
            Err(err) => {
                accounts.emit_event(EventType::Error(format!(
                    "Failed to remove account: {err:#}"
                )));
                0
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_migrate_account(
    accounts: *mut dc_accounts_t,
    dbfile: *const libc::c_char,
) -> u32 {
    if accounts.is_null() || dbfile.is_null() {
        eprintln!("ignoring careless call to dc_accounts_migrate_account()");
        return 0;
    }

    let accounts = &mut *accounts;
    let dbfile = to_string_lossy(dbfile);

    block_on(async move {
        let mut accounts = accounts.write().await;
        match accounts
            .migrate_account(std::path::PathBuf::from(dbfile))
            .await
        {
            Ok(id) => id,
            Err(err) => {
                accounts.emit_event(EventType::Error(format!(
                    "Failed to migrate account: {err:#}"
                )));
                0
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_get_all(accounts: *mut dc_accounts_t) -> *mut dc_array_t {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_get_all()");
        return ptr::null_mut();
    }

    let accounts = &*accounts;
    let list = block_on(accounts.read()).get_all();
    let array: dc_array_t = list.into();

    Box::into_raw(Box::new(array))
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_start_io(accounts: *mut dc_accounts_t) {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_start_io()");
        return;
    }

    let accounts = &mut *accounts;
    block_on(async move { accounts.write().await.start_io().await });
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_stop_io(accounts: *mut dc_accounts_t) {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_stop_io()");
        return;
    }

    let accounts = &*accounts;
    block_on(async move { accounts.read().await.stop_io().await });
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_maybe_network(accounts: *mut dc_accounts_t) {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_maybe_network()");
        return;
    }

    let accounts = &*accounts;
    block_on(async move { accounts.read().await.maybe_network().await });
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_maybe_network_lost(accounts: *mut dc_accounts_t) {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_maybe_network_lost()");
        return;
    }

    let accounts = &*accounts;
    block_on(async move { accounts.read().await.maybe_network_lost().await });
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_background_fetch(
    accounts: *mut dc_accounts_t,
    timeout_in_seconds: u64,
) -> libc::c_int {
    if accounts.is_null() || timeout_in_seconds <= 2 {
        eprintln!("ignoring careless call to dc_accounts_background_fetch()");
        return 0;
    }

    let accounts = &*accounts;
    let background_fetch_future = {
        let lock = block_on(accounts.read());
        lock.background_fetch(Duration::from_secs(timeout_in_seconds))
    };
    // At this point account manager is not locked anymore.
    block_on(background_fetch_future);
    1
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_set_push_device_token(
    accounts: *mut dc_accounts_t,
    token: *const libc::c_char,
) {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_set_push_device_token()");
        return;
    }

    let accounts = &*accounts;
    let token = to_string_lossy(token);

    block_on(async move {
        let accounts = accounts.read().await;
        if let Err(err) = accounts.set_push_device_token(&token).await {
            accounts.emit_event(EventType::Error(format!(
                "Failed to set notify token: {err:#}."
            )));
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dc_accounts_get_event_emitter(
    accounts: *mut dc_accounts_t,
) -> *mut dc_event_emitter_t {
    if accounts.is_null() {
        eprintln!("ignoring careless call to dc_accounts_get_event_emitter()");
        return ptr::null_mut();
    }

    let accounts = &*accounts;
    let emitter = block_on(accounts.read()).get_event_emitter();

    Box::into_raw(Box::new(emitter))
}

pub struct dc_jsonrpc_instance_t {
    receiver: OutReceiver,
    handle: RpcSession<CommandApi>,
}

#[no_mangle]
pub unsafe extern "C" fn dc_jsonrpc_init(
    account_manager: *mut dc_accounts_t,
) -> *mut dc_jsonrpc_instance_t {
    if account_manager.is_null() {
        eprintln!("ignoring careless call to dc_jsonrpc_init()");
        return ptr::null_mut();
    }

    let account_manager = &*account_manager;
    let cmd_api = block_on(deltachat_jsonrpc::api::CommandApi::from_arc(
        account_manager.inner.clone(),
    ));

    let (request_handle, receiver) = RpcClient::new();
    let handle = RpcSession::new(request_handle, cmd_api);

    let instance = dc_jsonrpc_instance_t { receiver, handle };

    Box::into_raw(Box::new(instance))
}

#[no_mangle]
pub unsafe extern "C" fn dc_jsonrpc_unref(jsonrpc_instance: *mut dc_jsonrpc_instance_t) {
    if jsonrpc_instance.is_null() {
        eprintln!("ignoring careless call to dc_jsonrpc_unref()");
        return;
    }
    drop(Box::from_raw(jsonrpc_instance));
}

fn spawn_handle_jsonrpc_request(handle: RpcSession<CommandApi>, request: String) {
    spawn(async move {
        handle.handle_incoming(&request).await;
    });
}

#[no_mangle]
pub unsafe extern "C" fn dc_jsonrpc_request(
    jsonrpc_instance: *mut dc_jsonrpc_instance_t,
    request: *const libc::c_char,
) {
    if jsonrpc_instance.is_null() || request.is_null() {
        eprintln!("ignoring careless call to dc_jsonrpc_request()");
        return;
    }

    let handle = &(*jsonrpc_instance).handle;
    let request = to_string_lossy(request);
    spawn_handle_jsonrpc_request(handle.clone(), request);
}

#[no_mangle]
pub unsafe extern "C" fn dc_jsonrpc_next_response(
    jsonrpc_instance: *mut dc_jsonrpc_instance_t,
) -> *mut libc::c_char {
    if jsonrpc_instance.is_null() {
        eprintln!("ignoring careless call to dc_jsonrpc_next_response()");
        return ptr::null_mut();
    }
    let api = &*jsonrpc_instance;
    block_on(api.receiver.recv())
        .map(|result| serde_json::to_string(&result).unwrap_or_default().strdup())
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn dc_jsonrpc_blocking_call(
    jsonrpc_instance: *mut dc_jsonrpc_instance_t,
    input: *const libc::c_char,
) -> *mut libc::c_char {
    if jsonrpc_instance.is_null() {
        eprintln!("ignoring careless call to dc_jsonrpc_blocking_call()");
        return ptr::null_mut();
    }
    let api = &*jsonrpc_instance;
    let input = to_string_lossy(input);
    let res = block_on(api.handle.process_incoming(&input));
    match res {
        Some(message) => {
            if let Ok(message) = serde_json::to_string(&message) {
                message.strdup()
            } else {
                ptr::null_mut()
            }
        }
        None => ptr::null_mut(),
    }
}
