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
//! or, if you want to only run e.g. the 'Decrypt a symmetrically encrypted message' benchmark:
//!
//! ```text
//! cargo bench --bench decrypting --features="internals" -- 'Decrypt a symmetrically encrypted message'
//! ```
//!
//! You can also pass a substring.
//! So, you can run all 'Decrypt and parse' benchmarks with:
//!
//! ```text
//! cargo bench --bench decrypting --features="internals" -- 'Decrypt and parse'
//! ```
//!
//! Symmetric decryption has to try out all known secrets,
//! You can benchmark this by adapting the `NUM_SECRETS` variable.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use deltachat::internals_for_benches::create_broadcast_secret;
use deltachat::internals_for_benches::create_dummy_keypair;
use deltachat::internals_for_benches::save_broadcast_secret;
use deltachat::{
    Events,
    chat::ChatId,
    config::Config,
    context::Context,
    internals_for_benches::key_from_asc,
    internals_for_benches::parse_and_get_text,
    internals_for_benches::store_self_keypair,
    pgp::{KeyPair, SeipdVersion, decrypt, pk_encrypt, symm_encrypt_message},
    stock_str::StockStrings,
};
use rand::{Rng, rng};
use tempfile::tempdir;

const NUM_SECRETS: usize = 500;

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
    let public = secret.signed_public_key();
    let key_pair = KeyPair { public, secret };
    store_self_keypair(&context, &key_pair)
        .await
        .expect("Failed to save key");

    context
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decrypt");

    // ===========================================================================================
    // Benchmarks for decryption only, without any other parsing
    // ===========================================================================================

    group.sample_size(10);

    group.bench_function("Decrypt a symmetrically encrypted message", |b| {
        let plain = generate_plaintext();
        let secrets = generate_secrets();
        let encrypted = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let secret = secrets[NUM_SECRETS / 2].clone();
            symm_encrypt_message(
                plain.clone(),
                create_dummy_keypair("alice@example.org").unwrap().secret,
                black_box(&secret),
                true,
            )
            .await
            .unwrap()
        });

        b.iter(|| {
            let mut msg =
                decrypt(encrypted.clone().into_bytes(), &[], black_box(&secrets)).unwrap();
            let decrypted = msg.as_data_vec().unwrap();

            assert_eq!(black_box(decrypted), plain);
        });
    });

    group.bench_function("Decrypt a public-key encrypted message", |b| {
        let plain = generate_plaintext();
        let key_pair = create_dummy_keypair("alice@example.org").unwrap();
        let secrets = generate_secrets();
        let encrypted = tokio::runtime::Runtime::new().unwrap().block_on(async {
            pk_encrypt(
                plain.clone(),
                vec![black_box(key_pair.public.clone())],
                key_pair.secret.clone(),
                true,
                true,
                SeipdVersion::V2,
            )
            .await
            .unwrap()
        });

        b.iter(|| {
            let mut msg = decrypt(
                encrypted.clone().into_bytes(),
                std::slice::from_ref(&key_pair.secret),
                black_box(&secrets),
            )
            .unwrap();
            let decrypted = msg.as_data_vec().unwrap();

            assert_eq!(black_box(decrypted), plain);
        });
    });

    // ===========================================================================================
    // Benchmarks for the whole parsing pipeline, incl. decryption (but excl. receive_imf())
    // ===========================================================================================

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut secrets = generate_secrets();

    // "secret" is the shared secret that was used to encrypt text_symmetrically_encrypted.eml.
    // Put it into the middle of our secrets:
    secrets[NUM_SECRETS / 2] = "secret".to_string();

    let context = rt.block_on(async {
        let context = create_context().await;
        for (i, secret) in secrets.iter().enumerate() {
            save_broadcast_secret(&context, ChatId::new(10 + i as u32), secret)
                .await
                .unwrap();
        }
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
                assert_eq!(text, "Symmetrically encrypted message");
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
                assert_eq!(text, "hi");
            }
        });
    });

    group.finish();
}

fn generate_secrets() -> Vec<String> {
    let secrets: Vec<String> = (0..NUM_SECRETS)
        .map(|_| create_broadcast_secret())
        .collect();
    secrets
}

fn generate_plaintext() -> Vec<u8> {
    let mut plain: Vec<u8> = vec![0; 500];
    rng().fill(&mut plain[..]);
    plain
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
