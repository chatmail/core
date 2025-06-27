#![recursion_limit = "256"]
use std::hint::black_box;
use std::path::Path;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use deltachat::Events;
use deltachat::chat::{self, ChatId};
use deltachat::chatlist::Chatlist;
use deltachat::context::Context;
use deltachat::stock_str::StockStrings;
use futures_lite::future::block_on;
use tempfile::tempdir;

async fn marknoticed_chat_benchmark(context: &Context, chats: &[ChatId]) {
    for c in chats.iter().take(20) {
        chat::marknoticed_chat(context, *c).await.unwrap();
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    // To enable this benchmark, set `DELTACHAT_BENCHMARK_DATABASE` to some large database with many
    // messages, such as your primary account.
    if let Ok(path) = std::env::var("DELTACHAT_BENCHMARK_DATABASE") {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let chats: Vec<_> = rt.block_on(async {
            let context = Context::new(Path::new(&path), 100, Events::new(), StockStrings::new())
                .await
                .unwrap();
            let chatlist = Chatlist::try_load(&context, 0, None, None).await.unwrap();
            let len = chatlist.len();
            (1..len).map(|i| chatlist.get_chat_id(i).unwrap()).collect()
        });

        // This mainly tests the performance of marknoticed_chat()
        // when nothing has to be done
        c.bench_function(
            "chat::marknoticed_chat (mark 20 chats as noticed repeatedly)",
            |b| {
                let dir = tempdir().unwrap();
                let dir = dir.path();
                let new_db = dir.join("dc.db");
                std::fs::copy(&path, &new_db).unwrap();

                let context = block_on(async {
                    Context::new(Path::new(&new_db), 100, Events::new(), StockStrings::new())
                        .await
                        .unwrap()
                });

                b.to_async(&rt)
                    .iter(|| marknoticed_chat_benchmark(&context, black_box(&chats)))
            },
        );

        // If the first 20 chats contain fresh messages or reactions,
        // this tests the performance of marking them as noticed.
        c.bench_function(
            "chat::marknoticed_chat (mark 20 chats as noticed, resetting after every iteration)",
            |b| {
                b.to_async(&rt).iter_batched(
                    || {
                        let dir = tempdir().unwrap();
                        let new_db = dir.path().join("dc.db");
                        std::fs::copy(&path, &new_db).unwrap();

                        let context = block_on(async {
                            Context::new(
                                Path::new(&new_db),
                                100,
                                Events::new(),
                                StockStrings::new(),
                            )
                            .await
                            .unwrap()
                        });
                        (dir, context)
                    },
                    |(_dir, context)| {
                        let chats = &chats;
                        async move {
                            marknoticed_chat_benchmark(black_box(&context), black_box(chats)).await
                        }
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    } else {
        println!("env var not set: DELTACHAT_BENCHMARK_DATABASE");
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
