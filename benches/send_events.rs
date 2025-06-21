#![recursion_limit = "256"]
use criterion::{criterion_group, criterion_main, Criterion};

use deltachat::context::Context;
use deltachat::stock_str::StockStrings;
use deltachat::{Event, EventType, Events};
use tempfile::tempdir;

async fn send_events_benchmark(context: &Context) {
    let emitter = context.get_event_emitter();
    for _i in 0..1_000_000 {
        context.emit_event(EventType::Info("interesting event...".to_string()));
    }
    context.emit_event(EventType::Info("DONE".to_string()));

    loop {
        match emitter.recv().await.unwrap() {
            Event {
                typ: EventType::Info(info),
                ..
            } if info.contains("DONE") => {
                break;
            }
            _ => {}
        }
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let dbfile = dir.path().join("db.sqlite");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let context = rt.block_on(async {
        Context::new(&dbfile, 100, Events::new(), StockStrings::new())
            .await
            .expect("failed to create context")
    });
    let executor = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("Sending 1.000.000 events", |b| {
        b.to_async(&executor)
            .iter(|| send_events_benchmark(&context))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
