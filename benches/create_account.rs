#![recursion_limit = "256"]
use std::hint::black_box;
use std::path::PathBuf;

use criterion::{Criterion, criterion_group, criterion_main};
use deltachat::accounts::Accounts;
use tempfile::tempdir;

async fn create_accounts(n: u32) {
    let dir = tempdir().unwrap();
    let p: PathBuf = dir.path().join("accounts");

    let writable = true;
    let mut accounts = Accounts::new(p.clone(), writable).await.unwrap();

    for expected_id in 2..n {
        let id = accounts.add_account().await.unwrap();
        assert_eq!(id, expected_id);
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("create 1 account", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.to_async(&rt).iter(|| create_accounts(black_box(1)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
