//! # Logging.

#![allow(missing_docs)]

use crate::context::Context;

mod stream;

pub(crate) use stream::LoggingStream;

macro_rules! info {
    ($ctx:expr,  $msg:expr) => {
        info!($ctx, $msg,)
    };
    ($ctx:expr, $msg:expr, $($args:expr),* $(,)?) => {{
        let formatted = format!($msg, $($args),*);
        let full = format!("{file}:{line}: {msg}",
                           file = file!(),
                           line = line!(),
                           msg = &formatted);
        ::tracing::event!(::tracing::Level::INFO, account_id = $ctx.get_id(), "{}", &formatted);
        $ctx.emit_event($crate::EventType::Info(full));
    }};
}

pub(crate) use info;

// Workaround for <https://github.com/rust-lang/rust/issues/133708>.
#[macro_use]
mod warn_macro_mod {
    macro_rules! warn_macro {
        ($ctx:expr, $msg:expr) => {
            warn_macro!($ctx, $msg,)
        };
        ($ctx:expr, $msg:expr, $($args:expr),* $(,)?) => {{
            let formatted = format!($msg, $($args),*);
            let full = format!("{file}:{line}: {msg}",
                               file = file!(),
                               line = line!(),
                               msg = &formatted);
            ::tracing::event!(::tracing::Level::WARN, account_id = $ctx.get_id(), "{}", &formatted);
            $ctx.emit_event($crate::EventType::Warning(full));
        }};
    }

    pub(crate) use warn_macro;
}

pub(crate) use warn_macro_mod::warn_macro as warn;

macro_rules! error {
    ($ctx:expr, $msg:expr) => {
        error!($ctx, $msg,)
    };
    ($ctx:expr, $msg:expr, $($args:expr),* $(,)?) => {{
        let formatted = format!($msg, $($args),*);
        ::tracing::event!(::tracing::Level::ERROR, account_id = $ctx.get_id(), "{}", &formatted);
        $ctx.set_last_error(&formatted);
        $ctx.emit_event($crate::EventType::Error(formatted));
    }};
}

pub(crate) use error;

impl Context {
    /// Set last error string.
    /// Implemented as blocking as used from macros in different, not always async blocks.
    pub fn set_last_error(&self, error: &str) {
        let mut last_error = self.last_error.write();
        *last_error = error.to_string();
    }

    /// Get last error string.
    pub fn get_last_error(&self) -> String {
        let last_error = &*self.last_error.read();
        last_error.clone()
    }

    pub fn set_migration_error(&self, error: &str) {
        let mut migration_error = self.migration_error.write();
        *migration_error = Some(error.to_string());
    }

    pub fn get_migration_error(&self) -> Option<String> {
        let migration_error = &*self.migration_error.read();
        migration_error.clone()
    }
}

pub trait LogExt<T, E>
where
    Self: std::marker::Sized,
{
    /// Emits a warning if the receiver contains an Err value.
    ///
    /// Thanks to the [track_caller](https://blog.rust-lang.org/2020/08/27/Rust-1.46.0.html#track_caller)
    /// feature, the location of the caller is printed to the log, just like with the warn!() macro.
    ///
    /// Unfortunately, the track_caller feature does not work on async functions (as of Rust 1.50).
    /// Once it is, you can add `#[track_caller]` to helper functions that use one of the log helpers here
    /// so that the location of the caller can be seen in the log. (this won't work with the macros,
    /// like warn!(), since the file!() and line!() macros don't work with track_caller)
    /// See <https://github.com/rust-lang/rust/issues/78840> for progress on this.
    #[track_caller]
    fn log_err(self, context: &Context) -> Result<T, E>;
}

impl<T, E: std::fmt::Display> LogExt<T, E> for Result<T, E> {
    #[track_caller]
    fn log_err(self, context: &Context) -> Result<T, E> {
        if let Err(e) = &self {
            let location = std::panic::Location::caller();

            // We are using Anyhow's .context() and to show the inner error, too, we need the {:#}:
            let full = format!(
                "{file}:{line}: {e:#}",
                file = location.file(),
                line = location.line(),
                e = e
            );
            // We can't use the warn!() macro here as the file!() and line!() macros
            // don't work with #[track_caller]
            tracing::event!(
                ::tracing::Level::WARN,
                account_id = context.get_id(),
                "{}",
                &full
            );
            context.emit_event(crate::EventType::Warning(full));
        };
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;

    use crate::test_utils::TestContext;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_last_error() -> Result<()> {
        let t = TestContext::new().await;

        assert_eq!(t.get_last_error(), "");

        error!(t, "foo-error");
        assert_eq!(t.get_last_error(), "foo-error");

        warn!(t, "foo-warning");
        assert_eq!(t.get_last_error(), "foo-error");

        info!(t, "foo-info");
        assert_eq!(t.get_last_error(), "foo-error");

        error!(t, "bar-error");
        error!(t, "baz-error");
        assert_eq!(t.get_last_error(), "baz-error");

        Ok(())
    }
}
