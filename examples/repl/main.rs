//! This is a CLI program and a little testing frame.  This file must not be
//! included when using Delta Chat Core as a library.
//!
//! Usage:  cargo run --example repl --release -- <databasefile>
//! All further options can be set using the set-command (type ? for help).
#![feature(ptr_cast)]

#[macro_use]
extern crate deltachat;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate rusqlite;

use std::borrow::Cow::{self, Borrowed, Owned};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use deltachat::config;
use deltachat::constants::*;
use deltachat::context::*;
use deltachat::dc_configure::*;
use deltachat::dc_job::*;
use deltachat::dc_securejoin::*;
use deltachat::dc_tools::*;
use deltachat::oauth2::*;
use deltachat::types::*;
use deltachat::x::*;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::config::OutputStreamType;
use rustyline::error::ReadlineError;
use rustyline::highlight::{Highlighter, MatchingBracketHighlighter};
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::{
    Cmd, CompletionType, Config, Context as RustyContext, EditMode, Editor, Helper, KeyPress,
};

mod cmdline;
use self::cmdline::*;

// Event Handler

unsafe extern "C" fn receive_event(
    _context: &Context,
    event: Event,
    data1: uintptr_t,
    data2: uintptr_t,
) -> uintptr_t {
    match event {
        Event::GET_STRING => {}
        Event::INFO => {
            /* do not show the event as this would fill the screen */
            println!("{}", to_string(data2 as *const _),);
        }
        Event::SMTP_CONNECTED => {
            println!("[DC_EVENT_SMTP_CONNECTED] {}", to_string(data2 as *const _));
        }
        Event::IMAP_CONNECTED => {
            println!("[DC_EVENT_IMAP_CONNECTED] {}", to_string(data2 as *const _),);
        }
        Event::SMTP_MESSAGE_SENT => {
            println!(
                "[DC_EVENT_SMTP_MESSAGE_SENT] {}",
                to_string(data2 as *const _),
            );
        }
        Event::WARNING => {
            println!("[Warning] {}", to_string(data2 as *const _),);
        }
        Event::ERROR => {
            println!(
                "\x1b[31m[DC_EVENT_ERROR] {}\x1b[0m",
                to_string(data2 as *const _),
            );
        }
        Event::ERROR_NETWORK => {
            println!(
                "\x1b[31m[DC_EVENT_ERROR_NETWORK] first={}, msg={}\x1b[0m",
                data1 as usize,
                to_string(data2 as *const _),
            );
        }
        Event::ERROR_SELF_NOT_IN_GROUP => {
            println!(
                "\x1b[31m[DC_EVENT_ERROR_SELF_NOT_IN_GROUP] {}\x1b[0m",
                to_string(data2 as *const _),
            );
        }
        Event::MSGS_CHANGED => {
            print!(
                "\x1b[33m{{Received DC_EVENT_MSGS_CHANGED({}, {})}}\n\x1b[0m",
                data1 as usize, data2 as usize,
            );
        }
        Event::CONTACTS_CHANGED => {
            print!("\x1b[33m{{Received DC_EVENT_CONTACTS_CHANGED()}}\n\x1b[0m");
        }
        Event::LOCATION_CHANGED => {
            print!(
                "\x1b[33m{{Received DC_EVENT_LOCATION_CHANGED(contact={})}}\n\x1b[0m",
                data1 as usize,
            );
        }
        Event::CONFIGURE_PROGRESS => {
            print!(
                "\x1b[33m{{Received DC_EVENT_CONFIGURE_PROGRESS({} ‰)}}\n\x1b[0m",
                data1 as usize,
            );
        }
        Event::IMEX_PROGRESS => {
            print!(
                "\x1b[33m{{Received DC_EVENT_IMEX_PROGRESS({} ‰)}}\n\x1b[0m",
                data1 as usize,
            );
        }
        Event::IMEX_FILE_WRITTEN => {
            print!(
                "\x1b[33m{{Received DC_EVENT_IMEX_FILE_WRITTEN({})}}\n\x1b[0m",
                to_string(data1 as *const _)
            );
        }
        Event::CHAT_MODIFIED => {
            print!(
                "\x1b[33m{{Received DC_EVENT_CHAT_MODIFIED({})}}\n\x1b[0m",
                data1 as usize,
            );
        }
        _ => {
            print!(
                "\x1b[33m{{Received {:?}({}, {})}}\n\x1b[0m",
                event, data1 as usize, data2 as usize,
            );
        }
    }

    0
}

// Threads for waiting for messages and for jobs

lazy_static! {
    static ref HANDLE: Arc<Mutex<Option<Handle>>> = Arc::new(Mutex::new(None));
    static ref IS_RUNNING: AtomicBool = AtomicBool::new(true);
}

struct Handle {
    handle_imap: Option<std::thread::JoinHandle<()>>,
    handle_mvbox: Option<std::thread::JoinHandle<()>>,
    handle_sentbox: Option<std::thread::JoinHandle<()>>,
    handle_smtp: Option<std::thread::JoinHandle<()>>,
}

macro_rules! while_running {
    ($code:block) => {
        if IS_RUNNING.load(Ordering::Relaxed) {
            $code
        } else {
            break;
        }
    };
}

fn start_threads(c: Arc<RwLock<Context>>) {
    if HANDLE.clone().lock().unwrap().is_some() {
        return;
    }

    println!("Starting threads");
    IS_RUNNING.store(true, Ordering::Relaxed);

    let ctx = c.clone();
    let handle_imap = std::thread::spawn(move || loop {
        while_running!({
            unsafe {
                dc_perform_imap_jobs(&ctx.read().unwrap());
                dc_perform_imap_fetch(&ctx.read().unwrap());
            }
            while_running!({
                let context = ctx.read().unwrap();
                dc_perform_imap_idle(&context);
            });
        });
    });

    let ctx = c.clone();
    let handle_mvbox = std::thread::spawn(move || loop {
        while_running!({
            unsafe { dc_perform_mvbox_fetch(&ctx.read().unwrap()) };
            while_running!({
                unsafe { dc_perform_mvbox_idle(&ctx.read().unwrap()) };
            });
        });
    });

    let ctx = c.clone();
    let handle_sentbox = std::thread::spawn(move || loop {
        while_running!({
            unsafe { dc_perform_sentbox_fetch(&ctx.read().unwrap()) };
            while_running!({
                unsafe { dc_perform_sentbox_idle(&ctx.read().unwrap()) };
            });
        });
    });

    let ctx = c;
    let handle_smtp = std::thread::spawn(move || loop {
        while_running!({
            unsafe { dc_perform_smtp_jobs(&ctx.read().unwrap()) };
            while_running!({
                unsafe { dc_perform_smtp_idle(&ctx.read().unwrap()) };
            });
        });
    });

    *HANDLE.clone().lock().unwrap() = Some(Handle {
        handle_imap: Some(handle_imap),
        handle_mvbox: Some(handle_mvbox),
        handle_sentbox: Some(handle_sentbox),
        handle_smtp: Some(handle_smtp),
    });
}

fn stop_threads(context: &Context) {
    if let Some(ref mut handle) = *HANDLE.clone().lock().unwrap() {
        println!("Stopping threads");
        IS_RUNNING.store(false, Ordering::Relaxed);

        unsafe {
            dc_interrupt_imap_idle(context);
            dc_interrupt_mvbox_idle(context);
            dc_interrupt_sentbox_idle(context);
            dc_interrupt_smtp_idle(context);
        }

        handle.handle_imap.take().unwrap().join().unwrap();
        handle.handle_mvbox.take().unwrap().join().unwrap();
        handle.handle_sentbox.take().unwrap().join().unwrap();
        handle.handle_smtp.take().unwrap().join().unwrap();
    }
}

// === The main loop

struct DcHelper {
    completer: FilenameCompleter,
    highlighter: MatchingBracketHighlighter,
    hinter: HistoryHinter,
}

impl Completer for DcHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &RustyContext<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        self.completer.complete(line, pos, ctx)
    }
}

const IMEX_COMMANDS: [&'static str; 12] = [
    "initiate-key-transfer",
    "get-setupcodebegin",
    "continue-key-transfer",
    "has-backup",
    "export-backup",
    "import-backup",
    "export-keys",
    "import-keys",
    "export-setup",
    "poke",
    "reset",
    "stop",
];

const DB_COMMANDS: [&'static str; 11] = [
    "info",
    "open",
    "close",
    "set",
    "get",
    "oauth2",
    "configure",
    "connect",
    "disconnect",
    "maybenetwork",
    "housekeeping",
];

const CHAT_COMMANDS: [&'static str; 25] = [
    "listchats",
    "listarchived",
    "chat",
    "createchat",
    "createchatbymsg",
    "creategroup",
    "createverified",
    "addmember",
    "removemember",
    "groupname",
    "groupimage",
    "chatinfo",
    "sendlocations",
    "setlocation",
    "dellocations",
    "getlocations",
    "send",
    "send-garbage",
    "sendimage",
    "sendfile",
    "draft",
    "listmedia",
    "archive",
    "unarchive",
    "delchat",
];
const MESSAGE_COMMANDS: [&'static str; 8] = [
    "listmsgs",
    "msginfo",
    "listfresh",
    "forward",
    "markseen",
    "star",
    "unstar",
    "delmsg",
];
const CONTACT_COMMANDS: [&'static str; 6] = [
    "listcontacts",
    "listverified",
    "addcontact",
    "contactinfo",
    "delcontact",
    "cleanupcontacts",
];
const MISC_COMMANDS: [&'static str; 8] = [
    "getqr", "getbadqr", "checkqr", "event", "fileinfo", "clear", "exit", "help",
];

impl Hinter for DcHelper {
    fn hint(&self, line: &str, pos: usize, ctx: &RustyContext<'_>) -> Option<String> {
        if !line.is_empty() {
            for &cmds in &[
                &IMEX_COMMANDS[..],
                &DB_COMMANDS[..],
                &CHAT_COMMANDS[..],
                &MESSAGE_COMMANDS[..],
                &CONTACT_COMMANDS[..],
                &MISC_COMMANDS[..],
            ] {
                if let Some(entry) = cmds.iter().find(|el| el.starts_with(&line[..pos])) {
                    if *entry != line && *entry != &line[..pos] {
                        return Some(entry[pos..].to_owned());
                    }
                }
            }
        }
        self.hinter.hint(line, pos, ctx)
    }
}

static COLORED_PROMPT: &'static str = "\x1b[1;32m> \x1b[0m";
static PROMPT: &'static str = "> ";

impl Highlighter for DcHelper {
    fn highlight_prompt<'p>(&self, prompt: &'p str) -> Cow<'p, str> {
        if prompt == PROMPT {
            Borrowed(COLORED_PROMPT)
        } else {
            Borrowed(prompt)
        }
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
    }

    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
        self.highlighter.highlight(line, pos)
    }

    fn highlight_char(&self, line: &str, pos: usize) -> bool {
        self.highlighter.highlight_char(line, pos)
    }
}

impl Helper for DcHelper {}

fn main_0(args: Vec<String>) -> Result<(), failure::Error> {
    let mut context = dc_context_new(
        Some(receive_event),
        0 as *mut libc::c_void,
        Some("CLI".into()),
    );

    unsafe { dc_cmdline_skip_auth() };

    if args.len() == 2 {
        if unsafe { !dc_open(&mut context, &args[1], None) } {
            println!("Error: Cannot open {}.", args[0],);
        }
    } else if args.len() != 1 {
        println!("Error: Bad arguments, expected [db-name].");
    }

    println!("Delta Chat Core is awaiting your commands.");

    let ctx = Arc::new(RwLock::new(context));

    let config = Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Emacs)
        .output_stream(OutputStreamType::Stdout)
        .build();
    let h = DcHelper {
        completer: FilenameCompleter::new(),
        highlighter: MatchingBracketHighlighter::new(),
        hinter: HistoryHinter {},
    };
    let mut rl = Editor::with_config(config);
    rl.set_helper(Some(h));
    rl.bind_sequence(KeyPress::Meta('N'), Cmd::HistorySearchForward);
    rl.bind_sequence(KeyPress::Meta('P'), Cmd::HistorySearchBackward);
    if rl.load_history(".dc-history.txt").is_err() {
        println!("No previous history.");
    }

    loop {
        let p = "> ";
        let readline = rl.readline(&p);
        match readline {
            Ok(line) => {
                // TODO: ignore "set mail_pw"
                rl.add_history_entry(line.as_str());
                let ctx = ctx.clone();
                match unsafe { handle_cmd(line.trim(), ctx) } {
                    Ok(ExitResult::Continue) => {}
                    Ok(ExitResult::Exit) => break,
                    Err(err) => println!("Error: {}", err),
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                println!("Exiting...");
                break;
            }
            Err(err) => {
                println!("Error: {}", err);
                break;
            }
        }
    }
    rl.save_history(".dc-history.txt")?;
    println!("history saved");
    {
        stop_threads(&ctx.read().unwrap());

        unsafe {
            let mut ctx = ctx.write().unwrap();
            dc_close(&mut ctx);
            dc_context_unref(&mut ctx);
        }
    }

    Ok(())
}

#[derive(Debug)]
enum ExitResult {
    Continue,
    Exit,
}

unsafe fn handle_cmd(line: &str, ctx: Arc<RwLock<Context>>) -> Result<ExitResult, failure::Error> {
    let mut args = line.splitn(2, ' ');
    let arg0 = args.next().unwrap_or_default();
    let arg1 = args.next().unwrap_or_default();
    let arg1_c = if arg1.is_empty() {
        std::ptr::null()
    } else {
        arg1.strdup()
    };

    match arg0 {
        "connect" => {
            start_threads(ctx);
        }
        "disconnect" => {
            stop_threads(&ctx.read().unwrap());
        }
        "smtp-jobs" => {
            if HANDLE.clone().lock().unwrap().is_some() {
                println!("smtp-jobs are already running in a thread.",);
            } else {
                dc_perform_smtp_jobs(&ctx.read().unwrap());
            }
        }
        "imap-jobs" => {
            if HANDLE.clone().lock().unwrap().is_some() {
                println!("imap-jobs are already running in a thread.");
            } else {
                dc_perform_imap_jobs(&ctx.read().unwrap());
            }
        }
        "configure" => {
            start_threads(ctx.clone());
            dc_configure(&ctx.read().unwrap());
        }
        "oauth2" => {
            if let Some(addr) = ctx.read().unwrap().get_config(config::Config::Addr) {
                let oauth2_url = dc_get_oauth2_url(
                    &ctx.read().unwrap(),
                    &addr,
                    "chat.delta:/com.b44t.messenger",
                );
                if oauth2_url.is_none() {
                    println!("OAuth2 not available for {}.", &addr);
                } else {
                    println!("Open the following url, set mail_pw to the generated token and server_flags to 2:\n{}", oauth2_url.unwrap());
                }
            } else {
                println!("oauth2: set addr first.");
            }
        }
        "clear" => {
            println!("\n\n\n");
            print!("\x1b[1;1H\x1b[2J");
        }
        "getqr" | "getbadqr" => {
            start_threads(ctx.clone());
            let qrstr =
                dc_get_securejoin_qr(&ctx.read().unwrap(), arg1.parse().unwrap_or_default());
            if !qrstr.is_null() && 0 != *qrstr.offset(0isize) as libc::c_int {
                if arg0 == "getbadqr" && strlen(qrstr) > 40 {
                    let mut i: libc::c_int = 12i32;
                    while i < 22i32 {
                        *qrstr.offset(i as isize) = '0' as i32 as libc::c_char;
                        i += 1
                    }
                }
                println!("{}", to_string(qrstr as *const _));
                let syscmd = dc_mprintf(
                    b"qrencode -t ansiutf8 \"%s\" -o -\x00" as *const u8 as *const libc::c_char,
                    qrstr,
                );
                system(syscmd);
                free(syscmd as *mut libc::c_void);
            }
            free(qrstr as *mut libc::c_void);
        }
        "joinqr" => {
            start_threads(ctx.clone());
            if !arg0.is_empty() {
                dc_join_securejoin(&ctx.read().unwrap(), arg1_c);
            }
        }
        "exit" => return Ok(ExitResult::Exit),
        _ => dc_cmdline(&ctx.read().unwrap(), line)?,
    }

    free(arg1_c as *mut _);

    Ok(ExitResult::Continue)
}

pub fn main() -> Result<(), failure::Error> {
    let _ = pretty_env_logger::try_init();

    let args: Vec<String> = std::env::args().collect();
    main_0(args)?;

    Ok(())
}
