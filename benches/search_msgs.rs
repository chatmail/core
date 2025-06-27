#![recursion_limit = "256"]
use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use deltachat::Events;
use deltachat::context::Context;
use deltachat::stock_str::StockStrings;

async fn search_benchmark(dbfile: impl AsRef<Path>) {
    let id = 100;
    let context = Context::new(dbfile.as_ref(), id, Events::new(), StockStrings::new())
        .await
        .unwrap();

    for _ in 0..10u32 {
        context.search_msgs(None, "hello").await.unwrap();
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    // To enable this benchmark, set `DELTACHAT_BENCHMARK_DATABASE` to some large database with many
    // messages, such as your primary account.
    if let Ok(path) = std::env::var("DELTACHAT_BENCHMARK_DATABASE") {
        let rt = tokio::runtime::Runtime::new().unwrap();

        c.bench_function("search hello", |b| {
            b.to_async(&rt).iter(|| search_benchmark(black_box(&path)))
        });
    } else {
        println!("env var not set: DELTACHAT_BENCHMARK_DATABASE");
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
