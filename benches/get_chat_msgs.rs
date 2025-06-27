#![recursion_limit = "256"]
use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use deltachat::Events;
use deltachat::chat::{self, ChatId};
use deltachat::chatlist::Chatlist;
use deltachat::context::Context;
use deltachat::stock_str::StockStrings;

async fn get_chat_msgs_benchmark(dbfile: &Path, chats: &[ChatId]) {
    let id = 100;
    let context = Context::new(dbfile, id, Events::new(), StockStrings::new())
        .await
        .unwrap();

    for c in chats.iter().take(10) {
        black_box(chat::get_chat_msgs(&context, *c).await.ok());
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
            (0..len).map(|i| chatlist.get_chat_id(i).unwrap()).collect()
        });

        c.bench_function("chat::get_chat_msgs (load messages from 10 chats)", |b| {
            b.to_async(&rt)
                .iter(|| get_chat_msgs_benchmark(black_box(path.as_ref()), black_box(&chats)))
        });
    } else {
        println!("env var not set: DELTACHAT_BENCHMARK_DATABASE");
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
