#![recursion_limit = "256"]
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use deltachat::Events;
use deltachat::contact::Contact;
use deltachat::context::Context;
use deltachat::stock_str::StockStrings;
use tempfile::tempdir;

async fn address_book_benchmark(n: u32, read_count: u32) {
    let dir = tempdir().unwrap();
    let dbfile = dir.path().join("db.sqlite");
    let id = 100;
    let context = Context::new(&dbfile, id, Events::new(), StockStrings::new())
        .await
        .unwrap();

    let book = (0..n)
        .map(|i| format!("Name {i}\naddr{i}@example.org\n"))
        .collect::<Vec<String>>()
        .join("");

    Contact::add_address_book(&context, &book).await.unwrap();

    let query: Option<&str> = None;
    for _ in 0..read_count {
        Contact::get_all(&context, 0, query).await.unwrap();
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("create 500 contacts", |b| {
        b.to_async(&rt)
            .iter(|| async { address_book_benchmark(black_box(500), black_box(0)).await })
    });

    c.bench_function("create 100 contacts and read it 1000 times", |b| {
        b.to_async(&rt)
            .iter(|| async { address_book_benchmark(black_box(100), black_box(1000)).await })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
