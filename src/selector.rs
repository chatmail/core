//! # User-defined relay selector.
//!
//! A user can upload a small [Rhai] script that decides which configured
//! transport ("relay") is activated for sending. When no user script is
//! installed, a built-in default script implementing the standard
//! ping-and-failover algorithm is used instead.
//!
//! The core does not cache or participate in the decision. It calls one of
//! two required script functions:
//!
//! - `init(relays)` — called when a relay is needed and the previous attempt
//!   did not fail (first run, restart or a stale reconnect). It may simply
//!   return the remembered relay for a fast start.
//! - `on_failure(relays, bad_relay)` — called after the previously selected
//!   relay failed, with the failed relay as the second argument.
//!
//! The script receives an array of object maps, one per configured transport:
//!
//! ```text
//! #{ id: 1, addr: "alice@example.org", host: "example.org", added: 1234567890 }
//! ```
//!
//! and may call the host functions:
//!
//! - `ping(host) -> int` — TCP connect to port 443, returns RTT in milliseconds,
//!   throws (catchable with `try`/`catch`) on failure. Only hosts from the
//!   current relay set may be pinged.
//! - `state_get(key)` / `state_set(key, value)` — persistent state, stored in
//!   the `relay_selector` table and surviving restarts.
//! - `mem_get(key)` / `mem_set(key, value)` — volatile state, kept in memory
//!   for the lifetime of the process and cleared on restart.
//! - `now() -> int` — current unix time in seconds.
//! - `log(message)` — emit a message into the core log.
//!
//! Both functions must return the address of the relay to activate, or `()`
//! (nothing) to leave no relay selected.
//!
//! [Rhai]: https://rhai.rs

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, format_err};
use rhai::{Dynamic, Engine, EvalAltResult, Map, Scope};
use serde::Serialize;

use crate::context::Context;
use crate::log::warn;
use crate::net::connect_tcp;
use crate::tools::time;

/// Timeout for a single `ping()` call.
const PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Port used by `ping()`.
const PING_PORT: u16 = 443;

/// Upper bound on the number of operations a selector script may execute.
const MAX_OPERATIONS: u64 = 1_000_000;

/// Maximum size of strings, arrays and maps inside a selector script.
const MAX_CONTAINER_SIZE: usize = 100_000;

/// Name of the cold-start function the selector script must define.
const INIT_FN: &str = "init";

/// Name of the failover function the selector script must define.
const ON_FAILURE_FN: &str = "on_failure";

/// Default relay selector script: ping all relays, then fail over to the
/// fastest responder until all of them are known to be broken.
pub(crate) const DEFAULT_RELAY_SELECTOR: &str = r#"
fn relay_has_addr(relays, addr) {
    for r in relays {
        if r.addr == addr {
            return true;
        }
    }
    return false;
}

// Pings all relays and returns them sorted by ascending RTT (tie-break by id).
fn relay_ping_sorted(relays) {
    let order = [];
    for r in relays {
        try {
            order.push(#{ addr: r.addr, id: r.id, ms: ping(r.host) });
        } catch (e) {
            // Unreachable relay, skip it.
        }
    }
    let sorted = [];
    for o in order {
        let pos = sorted.len();
        for i in 0..sorted.len() {
            let s = sorted[i];
            if o.ms < s.ms || (o.ms == s.ms && o.id < s.id) {
                pos = i;
                break;
            }
        }
        sorted.insert(pos, o);
    }
    return sorted;
}

fn init(relays) {
    let current = state_get("current");
    if type_of(current) == "string" && relay_has_addr(relays, current) {
        // Fast start: keep the previously active relay, no pings.
        return current;
    }
    let order = relay_ping_sorted(relays);
    mem_set("order", order);
    state_set("bad", []);
    let pick = ();
    if order.len() > 0 {
        pick = order[0].addr;
    }
    state_set("current", pick);
    return pick;
}

fn on_failure(relays, bad_relay) {
    let bad = state_get("bad");
    if type_of(bad) != "array" {
        bad = [];
    }
    if !bad.contains(bad_relay) {
        bad.push(bad_relay);
    }
    let order = mem_get("order");
    if type_of(order) != "array" || order.len() == 0 || bad.len() >= order.len() {
        // All known relays failed (or the ping cache was lost on restart):
        // start over from scratch.
        bad = [];
        order = relay_ping_sorted(relays);
        mem_set("order", order);
    }
    let pick = ();
    for o in order {
        if !bad.contains(o.addr) {
            pick = o.addr;
            break;
        }
    }
    state_set("bad", bad);
    state_set("current", pick);
    return pick;
}
"#;

/// A configured transport as presented to the selector script.
#[derive(Clone, Serialize)]
struct RelayInfo {
    id: u32,
    addr: String,
    host: String,
    added: i64,
}

/// Information about the currently installed selector script.
#[derive(Debug, Clone, Serialize)]
pub struct RelaySelectorInfo {
    /// Source code of the selector script (the default one if none is installed).
    pub script: String,

    /// Persistent state of the selector script.
    pub state: serde_json::Value,

    /// Whether the default built-in script is active.
    pub is_default: bool,
}

impl Context {
    /// Installs, replaces or removes the relay selector script.
    ///
    /// Passing `None` or an empty string restores the built-in default script.
    /// Replacing the script with a different source resets its persistent
    /// state; installing a byte-for-byte identical source keeps the state.
    pub async fn set_relay_selector(&self, script: Option<&str>) -> Result<()> {
        let Some(script) = script.map(str::trim).filter(|s| !s.is_empty()) else {
            self.sql.execute("DELETE FROM relay_selector", ()).await?;
            self.relay_selector_mem.lock().clear();
            return Ok(());
        };

        validate_script(script)?;

        let stored: Option<(String, i64)> = self
            .sql
            .query_row_optional(
                "SELECT script, is_default FROM relay_selector WHERE id=1",
                (),
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .await?;
        if matches!(&stored, Some((stored, 0)) if stored == script) {
            // Identical user script: keep the persistent state.
            self.sql
                .execute("UPDATE relay_selector SET is_default=0 WHERE id=1", ())
                .await?;
        } else {
            self.sql
                .execute(
                    "INSERT INTO relay_selector (id, script, is_default, state)
                     VALUES (1, ?, 0, '{}')
                     ON CONFLICT (id) DO UPDATE SET
                         script=excluded.script, is_default=0, state='{}'",
                    (script,),
                )
                .await?;
            self.relay_selector_mem.lock().clear();
        }
        Ok(())
    }

    /// Returns the installed selector script together with its state.
    pub async fn get_relay_selector(&self) -> Result<RelaySelectorInfo> {
        let row: Option<(String, i64, String)> = self
            .sql
            .query_row_optional(
                "SELECT script, is_default, state FROM relay_selector WHERE id=1",
                (),
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .await?;
        let (script, state, is_default) = match row {
            Some((script, 0, state)) => (script, state, false),
            Some((_script, _is_default, state)) => {
                (DEFAULT_RELAY_SELECTOR.to_string(), state, true)
            }
            None => (DEFAULT_RELAY_SELECTOR.to_string(), "{}".to_string(), true),
        };
        let state = serde_json::from_str(&state).unwrap_or_else(|_| serde_json::json!({}));
        Ok(RelaySelectorInfo {
            script,
            state,
            is_default,
        })
    }

    /// Clears the persistent and volatile state of the selector script.
    pub async fn reset_relay_selector_state(&self) -> Result<()> {
        self.sql
            .execute("UPDATE relay_selector SET state='{}' WHERE id=1", ())
            .await?;
        self.relay_selector_mem.lock().clear();
        Ok(())
    }

    /// Test-only: overrides the relay selector `ping()` behavior.
    #[cfg(test)]
    pub(crate) fn set_relay_selector_ping_succeeds(&self, succeeds: bool) {
        self.relay_selector_ping_succeeds
            .store(succeeds, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Compiles `script` and checks that it defines the required functions.
fn validate_script(script: &str) -> Result<()> {
    let engine = Engine::new();
    let ast = engine.compile(script).context("Invalid selector script")?;
    if !ast.iter_functions().any(|f| f.name == INIT_FN) {
        bail!("Selector script must define `fn {INIT_FN}(relays)`");
    }
    if !ast.iter_functions().any(|f| f.name == ON_FAILURE_FN) {
        bail!("Selector script must define `fn {ON_FAILURE_FN}(relays, bad_relay)`");
    }
    Ok(())
}

/// Asks the selector script for a relay on a cold start or stale reconnect.
pub(crate) async fn choose_init(context: &Context) -> Result<Option<String>> {
    run_selector(context, INIT_FN, None).await
}

/// Asks the selector script for a relay after `bad_addr` failed.
pub(crate) async fn choose_on_failure(context: &Context, bad_addr: &str) -> Result<Option<String>> {
    run_selector(context, ON_FAILURE_FN, Some(bad_addr.to_string())).await
}

/// Loads the selector script and runs `func`, persisting the resulting state.
async fn run_selector(
    context: &Context,
    func: &'static str,
    bad_addr: Option<String>,
) -> Result<Option<String>> {
    let (script, state_json) = load_selector(context).await?;

    let relays = load_relays(context).await?;
    if relays.is_empty() {
        return Ok(None);
    }
    let allowed_hosts: HashSet<String> = relays.iter().map(|r| r.host.clone()).collect();

    let state: Dynamic = serde_json::from_str(&state_json).unwrap_or_default();
    let mem = context.relay_selector_mem.clone();
    let handle = tokio::runtime::Handle::current();
    let ctx = context.clone();

    let result = tokio::task::spawn_blocking(move || {
        run_script(ScriptRun {
            context: &ctx,
            script: &script,
            func,
            relays,
            bad_addr,
            state,
            mem: &mem,
            allowed_hosts: &allowed_hosts,
            handle: &handle,
        })
    })
    .await
    .context("Relay selector task panicked");

    let (chosen, new_state) = match result {
        Ok(Ok(ok)) => ok,
        Ok(Err(err)) => {
            warn!(context, "Relay selector script failed: {err:#}.");
            return Ok(None);
        }
        Err(err) => {
            warn!(context, "Relay selector task failed: {err:#}.");
            return Ok(None);
        }
    };

    let new_json = serde_json::to_string(&new_state)?;
    if new_json != state_json {
        persist_state(context, &new_json).await?;
    }

    Ok(chosen)
}

/// Loads the active selector script source and its persisted state.
async fn load_selector(context: &Context) -> Result<(String, String)> {
    let row: Option<(String, i64, String)> = context
        .sql
        .query_row_optional(
            "SELECT script, is_default, state FROM relay_selector WHERE id=1",
            (),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .await?;
    Ok(match row {
        Some((script, 0, state)) => (script, state),
        Some((_script, _is_default, state)) => (DEFAULT_RELAY_SELECTOR.to_string(), state),
        None => (DEFAULT_RELAY_SELECTOR.to_string(), "{}".to_string()),
    })
}

/// Loads all configured transports as relay descriptors.
async fn load_relays(context: &Context) -> Result<Vec<RelayInfo>> {
    context
        .sql
        .query_map_vec("SELECT id, addr, add_timestamp FROM transports", (), |row| {
            let id: u32 = row.get(0)?;
            let addr: String = row.get(1)?;
            let added: i64 = row.get(2)?;
            let host = addr.rsplit_once('@').map(|(_, host)| host).unwrap_or("");
            Ok(RelayInfo {
                id,
                host: host.to_string(),
                addr,
                added,
            })
        })
        .await
}

/// Persists the selector script state as JSON.
async fn persist_state(context: &Context, state_json: &str) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT INTO relay_selector (id, script, is_default, state)
             VALUES (1, '', 1, ?)
             ON CONFLICT (id) DO UPDATE SET state=excluded.state",
            (state_json,),
        )
        .await?;
    Ok(())
}

/// Input for [`run_script`].
struct ScriptRun<'a> {
    context: &'a Context,
    script: &'a str,
    func: &'a str,
    relays: Vec<RelayInfo>,
    bad_addr: Option<String>,
    state: Dynamic,
    mem: &'a Arc<parking_lot::Mutex<Map>>,
    allowed_hosts: &'a HashSet<String>,
    handle: &'a tokio::runtime::Handle,
}

/// Compiles and runs the selector script on a blocking thread.
///
/// Returns the chosen relay address (if any) and the final persistent state.
fn run_script(run: ScriptRun<'_>) -> Result<(Option<String>, Dynamic)> {
    let ScriptRun {
        context,
        script,
        func,
        relays,
        bad_addr,
        state,
        mem,
        allowed_hosts,
        handle,
    } = run;
    let state_map: Map = state.try_cast().unwrap_or_default();
    let state_arc = Arc::new(parking_lot::Mutex::new(state_map));

    let chosen = {
        let engine = build_engine(context, &state_arc, mem, allowed_hosts, handle);
        let ast = engine.compile(script)?;

        let relays_arg = relays
            .iter()
            .map(rhai::serde::to_dynamic)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| format_err!("{err}"))?;

        let mut scope = Scope::new();
        let result: Dynamic = match bad_addr {
            Some(bad_addr) => engine.call_fn(&mut scope, &ast, func, (relays_arg, bad_addr))?,
            None => engine.call_fn(&mut scope, &ast, func, (relays_arg,))?,
        };

        result.into_string().ok()
    };

    let final_map = Arc::try_unwrap(state_arc)
        .ok()
        .map(|m| m.into_inner())
        .unwrap_or_default();
    Ok((chosen, Dynamic::from(final_map)))
}

/// Builds a sandboxed Rhai engine with the selector host functions.
fn build_engine(
    context: &Context,
    state: &Arc<parking_lot::Mutex<Map>>,
    mem: &Arc<parking_lot::Mutex<Map>>,
    allowed_hosts: &HashSet<String>,
    handle: &tokio::runtime::Handle,
) -> Engine {
    let mut engine = Engine::new();
    engine.set_max_operations(MAX_OPERATIONS);
    engine.set_max_string_size(MAX_CONTAINER_SIZE);
    engine.set_max_array_size(MAX_CONTAINER_SIZE);
    engine.set_max_map_size(MAX_CONTAINER_SIZE);
    engine.set_max_expr_depths(64, 64);
    engine.set_max_call_levels(32);

    let ctx = context.clone();
    engine.register_fn("log", move |msg: String| {
        info!(ctx, "{msg}");
    });

    engine.register_fn("now", time);

    let st = Arc::clone(state);
    engine.register_fn("state_get", move |key: String| -> Dynamic {
        st.lock().get(key.as_str()).cloned().unwrap_or_default()
    });
    let st = Arc::clone(state);
    engine.register_fn("state_set", move |key: String, value: Dynamic| {
        st.lock().insert(key.into(), value);
    });

    let me = Arc::clone(mem);
    engine.register_fn("mem_get", move |key: String| -> Dynamic {
        me.lock().get(key.as_str()).cloned().unwrap_or_default()
    });
    let me = Arc::clone(mem);
    engine.register_fn("mem_set", move |key: String, value: Dynamic| {
        me.lock().insert(key.into(), value);
    });

    let ctx = context.clone();
    let allowed = allowed_hosts.clone();
    let handle = handle.clone();
    #[cfg(test)]
    let ping_succeeds = context
        .relay_selector_ping_succeeds
        .load(std::sync::atomic::Ordering::Relaxed);
    engine.register_fn(
        "ping",
        move |host: String| -> Result<i64, Box<EvalAltResult>> {
            if !allowed.contains(&host) {
                return Err(format!("ping: host {host:?} is not one of the relays").into());
            }
            #[cfg(test)]
            if !ping_succeeds {
                return Err(format!("ping {host} failed (test override)").into());
            }
            #[cfg(test)]
            if ping_succeeds {
                return Ok(1);
            }
            let start = Instant::now();
            let result = handle.block_on(async {
                let _stream =
                    tokio::time::timeout(PING_TIMEOUT, connect_tcp(&ctx, &host, PING_PORT, false))
                        .await
                        .map_err(|_| format_err!("ping {host} timed out"))??;
                Ok::<(), anyhow::Error>(())
            });
            match result {
                Ok(()) => Ok(start.elapsed().as_millis() as i64),
                Err(err) => Err(format!("ping {host} failed: {err:#}").into()),
            }
        },
    );

    engine
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestContext;
    use crate::transport::add_pseudo_transport;

    fn relay(addr: &str, id: u32, added: i64) -> RelayInfo {
        RelayInfo {
            id,
            addr: addr.to_string(),
            host: addr.rsplit_once('@').unwrap_or((addr, "")).1.to_string(),
            added,
        }
    }

    fn empty_mem() -> Arc<parking_lot::Mutex<Map>> {
        Arc::new(parking_lot::Mutex::new(Map::new()))
    }

    fn order_entry(addr: &str, id: i64, ms: i64) -> Dynamic {
        let mut m = Map::new();
        m.insert("addr".into(), Dynamic::from(addr.to_string()));
        m.insert("id".into(), Dynamic::from(id));
        m.insert("ms".into(), Dynamic::from(ms));
        Dynamic::from(m)
    }

    /// Runs `run_script` on a blocking thread, as production code does.
    async fn call_script(
        context: &Context,
        script: &str,
        func: &'static str,
        relays: Vec<RelayInfo>,
        bad: Option<String>,
        state: Dynamic,
        mem: Arc<parking_lot::Mutex<Map>>,
    ) -> Result<(Option<String>, Dynamic)> {
        let allowed: HashSet<String> = relays.iter().map(|r| r.host.clone()).collect();
        let handle = tokio::runtime::Handle::current();
        let context = context.clone();
        let script = script.to_string();
        tokio::task::spawn_blocking(move || {
            run_script(ScriptRun {
                context: &context,
                script: &script,
                func,
                relays,
                bad_addr: bad,
                state,
                mem: &mem,
                allowed_hosts: &allowed,
                handle: &handle,
            })
        })
        .await?
    }

    #[test]
    fn test_validate_script() {
        assert!(validate_script("let x = 1;").is_err());
        assert!(validate_script("fn init(relays) { () }").is_err());
        assert!(validate_script("fn init(relays) { () } fn on_failure(relays, bad) { () }").is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_default_script_fast_start_returns_current() -> Result<()> {
        let t = TestContext::new().await;
        let state: Dynamic =
            serde_json::from_str(r#"{"current":"alice@a.example.org","bad":[]}"#)?;
        let (chosen, _) = call_script(
            &t,
            DEFAULT_RELAY_SELECTOR,
            INIT_FN,
            vec![relay("alice@a.example.org", 1, 1)],
            None,
            state,
            empty_mem(),
        )
        .await?;
        assert_eq!(chosen.as_deref(), Some("alice@a.example.org"));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_default_script_init_no_reachable_relay() -> Result<()> {
        let t = TestContext::new().await;
        t.set_relay_selector_ping_succeeds(false);
        let (chosen, state) = call_script(
            &t,
            DEFAULT_RELAY_SELECTOR,
            INIT_FN,
            vec![relay("alice@a.invalid", 1, 1), relay("alice@b.invalid", 2, 2)],
            None,
            Dynamic::from(Map::new()),
            empty_mem(),
        )
        .await?;
        assert_eq!(chosen, None);
        let map: Map = state.try_cast().unwrap();
        assert!(map
            .get("current")
            .cloned()
            .unwrap_or_default()
            .into_string()
            .is_err());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_default_script_on_failure_demotes() -> Result<()> {
        let t = TestContext::new().await;
        let mem = empty_mem();
        // Seed the volatile order cache: `a` is faster than `b`.
        mem.lock().insert(
            "order".into(),
            Dynamic::from(vec![
                order_entry("alice@a.example.org", 1, 1),
                order_entry("alice@b.example.org", 2, 2),
            ]),
        );
        let state: Dynamic =
            serde_json::from_str(r#"{"current":"alice@a.example.org","bad":[]}"#)?;
        let (chosen, new_state) = call_script(
            &t,
            DEFAULT_RELAY_SELECTOR,
            ON_FAILURE_FN,
            vec![
                relay("alice@a.example.org", 1, 1),
                relay("alice@b.example.org", 2, 2),
            ],
            Some("alice@a.example.org".to_string()),
            state,
            mem,
        )
        .await?;
        assert_eq!(chosen.as_deref(), Some("alice@b.example.org"));

        let map: Map = new_state.try_cast().unwrap();
        let bad = map
            .get("bad")
            .cloned()
            .unwrap()
            .try_cast::<rhai::Array>()
            .unwrap();
        assert_eq!(bad.len(), 1);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_set_get_and_reset_selector() -> Result<()> {
        let t = TestContext::new().await;
        let script = "fn init(relays) { () }\nfn on_failure(relays, bad_relay) { () }";

        assert!(t.get_relay_selector().await?.is_default);

        t.set_relay_selector(Some(script)).await?;
        let info = t.get_relay_selector().await?;
        assert_eq!(info.script, script);
        assert!(!info.is_default);

        assert!(t.set_relay_selector(Some("let x = 1;")).await.is_err());

        t.set_relay_selector(None).await?;
        assert!(t.get_relay_selector().await?.is_default);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_choose_uses_default_and_user_script() -> Result<()> {
        let t = TestContext::new().await;
        t.set_relay_selector_ping_succeeds(false);
        add_pseudo_transport(&t, "alice@a.invalid").await?;

        // Default script: the relay is unreachable, nothing is selected.
        assert_eq!(choose_init(&t).await?, None);

        // A user script always picks the only relay.
        t.set_relay_selector(Some(
            "fn init(relays) { relays[0].addr }\nfn on_failure(relays, bad_relay) { relays[0].addr }",
        ))
        .await?;
        assert_eq!(choose_init(&t).await?, Some("alice@a.invalid".to_string()));
        assert_eq!(
            choose_on_failure(&t, "alice@a.invalid").await?,
            Some("alice@a.invalid".to_string())
        );
        Ok(())
    }
}

