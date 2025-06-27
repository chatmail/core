#![recursion_limit = "256"]
use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use deltachat::Events;
use deltachat::chatlist::Chatlist;
use deltachat::context::Context;
use deltachat::stock_str::StockStrings;

async fn get_chat_list_benchmark(context: &Context) {
    Chatlist::try_load(context, 0, None, None).await.unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    // To enable this benchmark, set `DELTACHAT_BENCHMARK_DATABASE` to some large database with many
    // messages, such as your primary account.
    if let Ok(path) = std::env::var("DELTACHAT_BENCHMARK_DATABASE") {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let context = rt.block_on(async {
            Context::new(Path::new(&path), 100, Events::new(), StockStrings::new())
                .await
                .unwrap()
        });
        c.bench_function("chatlist:try_load (Get Chatlist)", |b| {
            b.to_async(&rt)
                .iter(|| get_chat_list_benchmark(black_box(&context)))
        });
    } else {
        println!("env var not set: DELTACHAT_BENCHMARK_DATABASE");
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
