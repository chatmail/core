# Coding conventions

We format the code using `rustfmt`. Run `cargo fmt` prior to committing the code.
Run `scripts/clippy.sh` to check the code for common mistakes with [Clippy].

[Clippy]: https://doc.rust-lang.org/clippy/

## SQL

Multi-line SQL statements should be formatted using string literals,
for example
```
    sql.execute(
        "CREATE TABLE messages (
id INTEGER PRIMARY KEY AUTOINCREMENT,
text TEXT DEFAULT '' NOT NULL -- message text
) STRICT",
    )
    .await
    .context("CREATE TABLE messages")?;
```

Do not use macros like [`concat!`](https://doc.rust-lang.org/std/macro.concat.html)
or [`indoc!`](https://docs.rs/indoc).
Do not escape newlines like this:
```
    sql.execute(
        "CREATE TABLE messages ( \
id INTEGER PRIMARY KEY AUTOINCREMENT, \
text TEXT DEFAULT '' NOT NULL \
) STRICT",
    )
    .await
    .context("CREATE TABLE messages")?;
```
Escaping newlines
is prone to errors like this if space before backslash is missing:
```
"SELECT foo\
 FROM bar"
```
Literal above results in `SELECT fooFROM bar` string.
This style also does not allow using `--` comments.

---

Declare new SQL tables with [`STRICT`](https://sqlite.org/stricttables.html) keyword
to make SQLite check column types.

Declare primary keys with [`AUTOINCREMENT`](https://www.sqlite.org/autoinc.html) keyword.
This avoids reuse of the row IDs and can avoid dangerous bugs
like forwarding wrong message because the message was deleted
and another message took its row ID.

Declare all new columns as `NOT NULL`
and set the `DEFAULT` value if it is optional so the column can be skipped in `INSERT` statements.
Dealing with `NULL` values both in SQL and in Rust is tricky and we try to avoid it.
If column is already declared without `NOT NULL`, use `IFNULL` function to provide default value when selecting it.
Use `HAVING COUNT(*) > 0` clause
to [prevent aggregate functions such as `MIN` and `MAX` from returning `NULL`](https://stackoverflow.com/questions/66527856/aggregate-functions-max-etc-return-null-instead-of-no-rows).

Don't delete unused columns too early, but maybe after several months/releases, unused columns are
still used by older versions, so deleting them breaks downgrading the core or importing a backup in
an older version. Also don't change the column type, consider adding a new column with another name
instead. Finally, never change column semantics, this is especially dangerous because the `STRICT`
keyword doesn't help here.

Consider adding context to `anyhow` errors for SQL statements using `.context()` so that it's
possible to understand from logs which statement failed. See [Errors](#errors) for more info.

## Errors

Delta Chat core mostly uses [`anyhow`](https://docs.rs/anyhow/) errors.
When using [`Context`](https://docs.rs/anyhow/latest/anyhow/trait.Context.html),
capitalize it but do not add a full stop as the contexts will be separated by `:`.
For example:
```
.with_context(|| format!("Unable to trash message {msg_id}"))
```

All errors should be handled in one of these ways:
- With `if let Err() =` (incl. logging them into `warn!()`/`err!()`).
- With `.log_err().ok()`.
- Bubbled up with `?`.

When working with [async streams](https://docs.rs/futures/0.3.31/futures/stream/index.html),
prefer [`try_next`](https://docs.rs/futures/0.3.31/futures/stream/trait.TryStreamExt.html#method.try_next) over `next()`, e.g. do
```
while let Some(event) = stream.try_next().await? {
    todo!();
}
```
instead of
```
while let Some(event_res) = stream.next().await {
    todo!();
}
```
as it allows bubbling up the error early with `?`
with no way to accidentally skip error processing
with early `continue` or `break`.
Some streams reading from a connection
return infinite number of `Some(Err(_))`
items when connection breaks and not processing
errors may result in infinite loop.

`backtrace` feature is enabled for `anyhow` crate
and `debug = 1` option is set in the test profile.
This allows to run `RUST_BACKTRACE=1 cargo test`
and get a backtrace with line numbers in resultified tests
which return `anyhow::Result`.

`unwrap` and `expect` are not used in the library
because panics are difficult to debug on user devices.
However, in the tests `.expect` may be used.
Follow
<https://doc.rust-lang.org/core/error/index.html#common-message-styles>
for `.expect` message style.

## BTreeMap vs HashMap

Prefer [BTreeMap](https://doc.rust-lang.org/std/collections/struct.BTreeMap.html)
over [HashMap](https://doc.rust-lang.org/std/collections/struct.HashMap.html)
and [BTreeSet](https://doc.rust-lang.org/std/collections/struct.BTreeSet.html)
over [HashSet](https://doc.rust-lang.org/std/collections/struct.HashSet.html)
as iterating over these structures returns items in deterministic order.

Non-deterministic code may result in difficult to reproduce bugs,
flaky tests, regression tests that miss bugs
or different behavior on different devices when processing the same messages.

## Logging

For logging, use `info!`, `warn!` and `error!` macros.
Log messages should be capitalized and have a full stop in the end. For example:
```
info!(context, "Ignoring addition of {added_addr:?} to {chat_id}.");
```

Format anyhow errors with `{:#}` to print all the contexts like this:
```
error!(context, "Failed to set selfavatar timestamp: {err:#}.");
```

## Documentation comments

All public modules, methods and fields should be documented.
This is checked by [`missing_docs`](https://doc.rust-lang.org/rustdoc/lints.html#missing_docs) lint.

Private items do not have to be documented,
but CI uses `cargo doc --document-private-items`
to build the documentation,
so it is preferred that new items
are documented.

Follow Rust guidelines for the documentation comments:
<https://rust-lang.github.io/rfcs/1574-more-api-documentation-conventions.html#summary-sentence>
