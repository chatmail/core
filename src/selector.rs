//! # User-defined relay selector.
//!
//! A user can upload a small [Rhai] script that decides which configured
//! transport ("relay") is activated for sending. The core does not cache or
//! participate in the decision: whenever a new SMTP connection is needed it
//! calls the script's `select_relay(relays)` function and connects to the
//! returned relay. The only memory that persists between invocations is the
//! script's own `state`, stored in the `relay_selector` table.
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
//! - `state_get(key) -> value` and `state_set(key, value)` — persistent state.
//! - `now() -> int` — current unix time in seconds.
//! - `log(message)` — emit a message into the core log.
//!
//! The function must return the address of the relay to activate, or `()`
//! (nothing) to leave no relay selected.
//!
//! [Rhai]: https://rhai.rs

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
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

/// Name of the function the selector script must define.
const SELECT_FN: &str = "select_relay";

/// A configured transport as presented to the selector script.
#[derive(Clone, Serialize)]
struct RelayInfo {
    id: u32,
    addr: String,
    host: String,
    added: i64,
}

/// Result of asking the selector script which relay to activate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RelayChoice {
    /// No selector script is configured, use the built-in transport ordering.
    Disabled,

    /// The selector script chose this relay address.
    Selected(String),

    /// A selector script is configured but it did not choose any relay.
    None,
}

/// Information about the currently installed selector script.
#[derive(Debug, Clone, Serialize)]
pub struct RelaySelectorInfo {
    /// Source code of the selector script, if one is installed.
    pub script: Option<String>,

    /// Persistent state of the selector script.
    pub state: serde_json::Value,
}

impl Context {
    /// Installs, replaces or removes the relay selector script.
    ///
    /// Passing `None` or an empty string removes the selector script entirely.
    /// Replacing the script with a different source resets its persistent
    /// state; installing a byte-for-byte identical source keeps the state.
    pub async fn set_relay_selector(&self, script: Option<&str>) -> Result<()> {
        let Some(script) = script.map(str::trim).filter(|s| !s.is_empty()) else {
            self.sql.execute("DELETE FROM relay_selector", ()).await?;
            return Ok(());
        };

        validate_script(script)?;

        let stored: Option<String> = self
            .sql
            .query_get_value("SELECT script FROM relay_selector WHERE id=1", ())
            .await?;
        match stored {
            Some(old) if old == script => {
                self.sql
                    .execute("UPDATE relay_selector SET enabled=1 WHERE id=1", ())
                    .await?;
            }
            _ => {
                self.sql
                    .execute(
                        "INSERT INTO relay_selector (id, script, enabled, state)
                         VALUES (1, ?, 1, '{}')
                         ON CONFLICT (id) DO UPDATE SET
                             script=excluded.script, enabled=1, state='{}'",
                        (script,),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Returns the installed selector script together with its persistent
    /// state, or `None` if no selector script is installed.
    pub async fn get_relay_selector(&self) -> Result<Option<RelaySelectorInfo>> {
        let Some((script, state)) = self
            .sql
            .query_row_optional(
                "SELECT script, state FROM relay_selector WHERE id=1",
                (),
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .await?
        else {
            return Ok(None);
        };
        let state = serde_json::from_str(&state).unwrap_or(serde_json::Value::Null);
        Ok(Some(RelaySelectorInfo {
            script: Some(script),
            state,
        }))
    }

    /// Clears the persistent state of the selector script.
    pub async fn reset_relay_selector_state(&self) -> Result<()> {
        self.sql
            .execute("UPDATE relay_selector SET state='{}' WHERE id=1", ())
            .await?;
        Ok(())
    }
}

/// Compiles `script` and checks that it defines `select_relay`.
fn validate_script(script: &str) -> Result<()> {
    let engine = Engine::new();
    let ast = engine.compile(script).context("Invalid selector script")?;
    if !ast.iter_functions().any(|f| f.name == SELECT_FN) {
        bail!("Selector script must define `fn {SELECT_FN}(relays)`");
    }
    Ok(())
}

/// Asks the selector script which relay to activate.
pub(crate) async fn choose_active_relay(context: &Context) -> Result<RelayChoice> {
    let Some((script, state_json)) = load_enabled_script(context).await? else {
        return Ok(RelayChoice::Disabled);
    };

    let relays = load_relays(context).await?;
    if relays.is_empty() {
        return Ok(RelayChoice::None);
    }
    let allowed_hosts: HashSet<String> = relays.iter().map(|r| r.host.clone()).collect();

    let state: Dynamic = serde_json::from_str(&state_json).unwrap_or_default();
    let handle = tokio::runtime::Handle::current();
    let ctx = context.clone();

    let result = tokio::task::spawn_blocking(move || {
        run_script(&ctx, &script, relays, state, &allowed_hosts, &handle)
    })
    .await
    .context("Relay selector task panicked");

    let (chosen, new_state) = match result {
        Ok(Ok(ok)) => ok,
        Ok(Err(err)) => {
            warn!(context, "Relay selector script failed: {err:#}.");
            return Ok(RelayChoice::None);
        }
        Err(err) => {
            warn!(context, "Relay selector task failed: {err:#}.");
            return Ok(RelayChoice::None);
        }
    };

    persist_state(context, &new_state).await?;

    Ok(chosen.map(RelayChoice::Selected).unwrap_or(RelayChoice::None))
}

/// Loads the enabled selector script source and its state, if any.
async fn load_enabled_script(context: &Context) -> Result<Option<(String, String)>> {
    context
        .sql
        .query_row_optional(
            "SELECT script, state FROM relay_selector WHERE id=1 AND enabled=1",
            (),
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .await
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
async fn persist_state(context: &Context, state: &Dynamic) -> Result<()> {
    let json = serde_json::to_string(state)?;
    context
        .sql
        .execute("UPDATE relay_selector SET state=? WHERE id=1", (json,))
        .await?;
    Ok(())
}

/// Compiles and runs the selector script on a blocking thread.
///
/// Returns the chosen relay address (if any) and the final script state.
fn run_script(
    context: &Context,
    script: &str,
    relays: Vec<RelayInfo>,
    state: Dynamic,
    allowed_hosts: &HashSet<String>,
    handle: &tokio::runtime::Handle,
) -> Result<(Option<String>, Dynamic)> {
    let state_map: Map = state.try_cast().unwrap_or_default();
    let state_arc = Arc::new(Mutex::new(state_map));

    let chosen = {
        let engine = build_engine(context, &state_arc, allowed_hosts, handle);
        let ast = engine.compile(script)?;

        let relays_arg = relays
            .iter()
            .map(rhai::serde::to_dynamic)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| anyhow::format_err!("{err}"))?;

        let mut scope = Scope::new();
        let result: Dynamic = engine.call_fn(&mut scope, &ast, SELECT_FN, (relays_arg,))?;

        result.into_string().ok()
    };

    let final_map = Arc::try_unwrap(state_arc)
        .ok()
        .and_then(|m| m.into_inner().ok())
        .unwrap_or_default();
    Ok((chosen, Dynamic::from(final_map)))
}

/// Builds a sandboxed Rhai engine with the selector host functions.
fn build_engine(
    context: &Context,
    state: &Arc<Mutex<Map>>,
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
        st.lock().unwrap().get(key.as_str()).cloned().unwrap_or_default()
    });

    let st = Arc::clone(state);
    engine.register_fn("state_set", move |key: String, value: Dynamic| {
        st.lock().unwrap().insert(key.into(), value);
    });

    let ctx = context.clone();
    let allowed = allowed_hosts.clone();
    let handle = handle.clone();
    engine.register_fn(
        "ping",
        move |host: String| -> Result<i64, Box<EvalAltResult>> {
            if !allowed.contains(&host) {
                return Err(format!("ping: host {host:?} is not one of the relays").into());
            }
            let start = Instant::now();
            let result = handle.block_on(async {
                let _stream = tokio::time::timeout(
                    PING_TIMEOUT,
                    connect_tcp(&ctx, &host, PING_PORT, false),
                )
                .await
                .map_err(|_| anyhow::format_err!("ping {host} timed out"))??;
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

    fn sample_relays() -> Vec<RelayInfo> {
        vec![
            RelayInfo {
                id: 1,
                addr: "alice@a.example.org".to_string(),
                host: "a.example.org".to_string(),
                added: 1,
            },
            RelayInfo {
                id: 2,
                addr: "alice@b.example.org".to_string(),
                host: "b.example.org".to_string(),
                added: 2,
            },
        ]
    }

    fn handle() -> tokio::runtime::Handle {
        tokio::runtime::Handle::current()
    }

    #[test]
    fn test_validate_script_rejects_missing_function() {
        assert!(validate_script("let x = 1;").is_err());
        assert!(validate_script("fn select_relay(relays) { () }").is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_run_script_selects_constant() -> Result<()> {
        let t = TestContext::new().await;
        let relays = sample_relays();
        let state = Dynamic::from(Map::new());
        let allowed: HashSet<String> = relays.iter().map(|r| r.host.clone()).collect();
        let (chosen, _) = run_script(
            &t,
            "fn select_relay(relays) { relays[0].addr }",
            relays,
            state,
            &allowed,
            &handle(),
        )?;
        assert_eq!(chosen, Some("alice@a.example.org".to_string()));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_run_script_state_persists() -> Result<()> {
        let t = TestContext::new().await;
        let relays = sample_relays();
        let allowed: HashSet<String> = relays.iter().map(|r| r.host.clone()).collect();
        let script = r#"
            fn select_relay(relays) {
                let n = state_get("count") ?? 0;
                state_set("count", n + 1);
                relays[0].addr
            }
        "#;

        let state = Dynamic::from(Map::new());
        let (chosen, state1) = run_script(&t, script, relays.clone(), state, &allowed, &handle())?;
        assert_eq!(chosen, Some("alice@a.example.org".to_string()));

        let (_, state2) = run_script(&t, script, relays, state1, &allowed, &handle())?;

        let map: Map = state2.try_cast().unwrap();
        assert_eq!(map.get("count").cloned().unwrap().try_cast::<i64>(), Some(2));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_set_get_and_reset_selector() -> Result<()> {
        let t = TestContext::new().await;
        let script = "fn select_relay(relays) { () }";

        assert!(t.get_relay_selector().await?.is_none());

        t.set_relay_selector(Some(script)).await?;
        let info = t.get_relay_selector().await?.unwrap();
        assert_eq!(info.script.as_deref(), Some(script));

        // Replacing the script resets the state, identical source keeps it.
        t.set_relay_selector(Some(script)).await?;

        // Removing the selector clears everything.
        t.set_relay_selector(None).await?;
        assert!(t.get_relay_selector().await?.is_none());

        // Invalid script is rejected and does not replace the current one.
        t.set_relay_selector(Some(script)).await?;
        assert!(t.set_relay_selector(Some("let x = 1;")).await.is_err());
        assert_eq!(
            t.get_relay_selector().await?.unwrap().script.as_deref(),
            Some(script)
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_choose_active_relay() -> Result<()> {
        let t = TestContext::new().await;

        // No script installed: use the built-in ordering.
        assert_eq!(choose_active_relay(&t).await?, RelayChoice::Disabled);

        crate::transport::add_pseudo_transport(&t, "alice@example.org").await?;

        // Script selecting the only relay.
        t.set_relay_selector(Some("fn select_relay(relays) { relays[0].addr }"))
            .await?;
        assert_eq!(
            choose_active_relay(&t).await?,
            RelayChoice::Selected("alice@example.org".to_string())
        );

        // Script returning nothing: no relay selected.
        t.set_relay_selector(Some("fn select_relay(relays) { () }"))
            .await?;
        assert_eq!(choose_active_relay(&t).await?, RelayChoice::None);

        // Removing the script disables the selector again.
        t.set_relay_selector(None).await?;
        assert_eq!(choose_active_relay(&t).await?, RelayChoice::Disabled);
        Ok(())
    }
}

