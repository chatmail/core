//! Benchmarks for message decryption,
//! comparing decryption of symmetrically-encrypted messages
//! to decryption of asymmetrically-encrypted messages.
//!
//! Call with
//!
//! ```text
//! cargo bench --bench decrypting --features="internals"
//! ```
//!
//! or, if you want to only run e.g. the 'Decrypt and parse a symmetrically encrypted message' benchmark:
//!
//! ```text
//! cargo bench --bench decrypting --features="internals" -- 'Decrypt and parse a symmetrically encrypted message'
//! ```
//!
//! You can also pass a substring:
//!
//! ```text
//! cargo bench --bench decrypting --features="internals" -- 'symmetrically'
//! ```
//!
//! Symmetric decryption has to try out all known secrets,
//! You can benchmark this by adapting the `NUM_SECRETS` variable.

use std::hint::black_box;
use std::sync::LazyLock;

use criterion::{Criterion, criterion_group, criterion_main};
use deltachat::internals_for_benches::create_broadcast_secret;
use deltachat::internals_for_benches::save_broadcast_secret;
use deltachat::securejoin::get_securejoin_qr;
use deltachat::{
    Events, chat::ChatId, config::Config, context::Context, internals_for_benches::key_from_asc,
    internals_for_benches::parse_and_get_text, internals_for_benches::store_self_keypair,
    pgp::KeyPair, stock_str::StockStrings,
};
use tempfile::tempdir;

static NUM_BROADCAST_SECRETS: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("NUM_BROADCAST_SECRETS")
        .unwrap_or("500".to_string())
        .parse()
        .unwrap()
});
static NUM_AUTH_TOKENS: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("NUM_AUTH_TOKENS")
        .unwrap_or("5000".to_string())
        .parse()
        .unwrap()
});

async fn create_context() -> Context {
    let dir = tempdir().unwrap();
    let dbfile = dir.path().join("db.sqlite");
    let context = Context::new(dbfile.as_path(), 100, Events::new(), StockStrings::new())
        .await
        .unwrap();

    context
        .set_config(Config::ConfiguredAddr, Some("bob@example.net"))
        .await
        .unwrap();
    let secret = key_from_asc(include_str!("../test-data/key/bob-secret.asc")).unwrap();
    let public = secret.to_public_key();
    let key_pair = KeyPair { public, secret };
    store_self_keypair(&context, &key_pair)
        .await
        .expect("Failed to save key");

    context
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decrypt");

    // ===========================================================================================
    // Benchmarks for the whole parsing pipeline, incl. decryption (but excl. receive_imf())
    // ===========================================================================================

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut secrets = generate_secrets();

    // "secret" is the shared secret that was used to encrypt text_symmetrically_encrypted.eml.
    // Put it into the middle of our secrets:
    secrets[*NUM_BROADCAST_SECRETS / 2] = "secret".to_string();

    let context = rt.block_on(async {
        let context = create_context().await;
        for (i, secret) in secrets.iter().enumerate() {
            save_broadcast_secret(&context, ChatId::new(10 + i as u32), secret)
                .await
                .unwrap();
        }
        for _i in 0..*NUM_AUTH_TOKENS {
            get_securejoin_qr(&context, None).await.unwrap();
        }
        println!("NUM_AUTH_TOKENS={}", *NUM_AUTH_TOKENS);
        context
    });

    group.bench_function("Decrypt and parse a symmetrically encrypted message", |b| {
        b.to_async(&rt).iter(|| {
            let ctx = context.clone();
            async move {
                let text = parse_and_get_text(
                    &ctx,
                    include_bytes!("../test-data/message/text_symmetrically_encrypted.eml"),
                )
                .await
                .unwrap();
                assert_eq!(black_box(text), "Symmetrically encrypted message");
            }
        });
    });

    group.bench_function("Decrypt and parse a public-key encrypted message", |b| {
        b.to_async(&rt).iter(|| {
            let ctx = context.clone();
            async move {
                let text = parse_and_get_text(
                    &ctx,
                    include_bytes!("../test-data/message/text_from_alice_encrypted.eml"),
                )
                .await
                .unwrap();
                assert_eq!(black_box(text), "hi");
            }
        });
    });

    group.finish();
}

fn generate_secrets() -> Vec<String> {
    let secrets: Vec<String> = (0..*NUM_BROADCAST_SECRETS)
        .map(|_| create_broadcast_secret())
        .collect();
    println!("NUM_BROADCAST_SECRETS={}", *NUM_BROADCAST_SECRETS);
    secrets
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
