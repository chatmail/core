use deltachat_jsonrpc::api::write_ts_bindings;
use std::path::Path;

fn main() {
    write_ts_bindings(Path::new("typescript/generated"));
}
