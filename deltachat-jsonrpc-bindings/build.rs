use deltachat_jsonrpc::api::{generate_qt_bindings, generate_ts_bindings};

fn main() {
    generate_ts_bindings();
    generate_qt_bindings();
}
