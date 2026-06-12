use deltachat_jsonrpc::api::{write_qt_bindings, write_ts_bindings};
use std::path::Path;

fn main() {
    write_ts_bindings(Path::new("typescript/generated"));
    write_qt_bindings(Path::new("qt/generated"), "deltachat");
}
