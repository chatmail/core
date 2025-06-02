#![recursion_limit = "256"]
use std::hint::black_box;
use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Criterion};
use deltachat::{
    config::Config,
    context::Context,
    imex::{imex, ImexMode},
    receive_imf::receive_imf,
    stock_str::StockStrings,
    Events,
};
use tempfile::tempdir;

async fn recv_all_emails(context: Context, iteration: u32) -> Context {
    for i in 0..100 {
        let imf_raw = format!(
            "Subject: Benchmark
Message-ID: Mr.{iteration}.{i}@testrun.org
Date: Sat, 07 Dec 2019 19:00:27 +0000
To: alice@example.com
From: sender@testrun.org
Chat-Version: 1.0
Chat-Disposition-Notification-To: sender@testrun.org
Chat-User-Avatar: 0
In-Reply-To: Mr.{iteration}.{i_dec}@testrun.org
MIME-Version: 1.0

Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

Hello {i}",
            i = i,
            i_dec = i - 1,
        );
        receive_imf(&context, black_box(imf_raw.as_bytes()), false)
            .await
            .unwrap();
    }
    context
}

/// Receive 100 emails that remove charlie@example.com and add
/// him back
async fn recv_groupmembership_emails(context: Context, iteration: u32) -> Context {
    for i in 0..50 {
        let imf_raw = format!(
            "Subject: Benchmark
Message-ID: Gr.{iteration}.ADD.{i}@testrun.org
Date: Sat, 07 Dec 2019 19:00:27 +0000
To: alice@example.com, b@example.com, c@example.com, d@example.com, e@example.com, f@example.com
From: sender@testrun.org
Chat-Version: 1.0
Chat-Disposition-Notification-To: sender@testrun.org
Chat-User-Avatar: 0
Chat-Group-Member-Added: charlie@example.com
In-Reply-To: Gr.{iteration}.REMOVE.{i_dec}@testrun.org
MIME-Version: 1.0

Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

Hello {i}",
            i_dec = i - 1,
        );
        receive_imf(&context, black_box(imf_raw.as_bytes()), false)
            .await
            .unwrap();

        let imf_raw = format!(
            "Subject: Benchmark
Message-ID: Gr.{iteration}.REMOVE.{i}@testrun.org
Date: Sat, 07 Dec 2019 19:00:27 +0000
To: alice@example.com, b@example.com, c@example.com, d@example.com, e@example.com, f@example.com
From: sender@testrun.org
Chat-Version: 1.0
Chat-Disposition-Notification-To: sender@testrun.org
Chat-User-Avatar: 0
Chat-Group-Member-Removed: charlie@example.com
In-Reply-To: Gr.{iteration}.ADD.{i}@testrun.org
MIME-Version: 1.0

Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

Hello {i}"
        );
        receive_imf(&context, black_box(imf_raw.as_bytes()), false)
            .await
            .unwrap();
    }
    context
}

async fn create_context() -> Context {
    let dir = tempdir().unwrap();
    let dbfile = dir.path().join("db.sqlite");
    let id = 100;
    let context = Context::new(dbfile.as_path(), id, Events::new(), StockStrings::new())
        .await
        .unwrap();

    let backup: PathBuf = std::env::current_dir()
        .unwrap()
        .join("delta-chat-backup.tar");

    if backup.exists() {
        println!("Importing backup");
        imex(&context, ImexMode::ImportBackup, backup.as_path(), None)
            .await
            .unwrap();
    }

    let addr = "alice@example.com";
    context.set_config(Config::Addr, Some(addr)).await.unwrap();
    context
        .set_config(Config::ConfiguredAddr, Some(addr))
        .await
        .unwrap();
    context
        .set_config(Config::Configured, Some("1"))
        .await
        .unwrap();
    context
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Receive messages");
    group.bench_function("Receive 100 simple text msgs", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let context = rt.block_on(create_context());
        let mut i = 0;

        b.to_async(&rt).iter(|| {
            let ctx = context.clone();
            i += 1;
            async move {
                recv_all_emails(black_box(ctx), i).await;
            }
        });
    });
    group.bench_function(
        "Receive 100 Chat-Group-Member-{Added|Removed} messages",
        |b| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let context = rt.block_on(create_context());
            let mut i = 0;

            b.to_async(&rt).iter(|| {
                let ctx = context.clone();
                i += 1;
                async move {
                    recv_groupmembership_emails(black_box(ctx), i).await;
                }
            });
        },
    );
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
