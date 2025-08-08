use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use deltachat::benchmark_internals::create_dummy_keypair;
use deltachat::benchmark_internals::save_broadcast_shared_secret;
use deltachat::{
    Events,
    benchmark_internals::key_from_asc,
    benchmark_internals::parse_and_get_text,
    benchmark_internals::store_self_keypair,
    chat::ChatId,
    config::Config,
    context::Context,
    pgp::{KeyPair, decrypt, encrypt_for_broadcast, pk_encrypt},
    stock_str::StockStrings,
    tools::create_broadcast_shared_secret_pub,
};
use rand::{Rng, thread_rng};
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
    let secret = key_from_asc(include_str!("../test-data/key/bob-secret.asc"))
        .unwrap()
        .0;
    let public = secret.signed_public_key();
    let key_pair = KeyPair { public, secret };
    store_self_keypair(&context, &key_pair)
        .await
        .expect("Failed to save key");

    context
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decrypt");
    group.sample_size(10);
    group.bench_function("Decrypt symmetrically encrypted", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut plain: Vec<u8> = vec![0; 500];
        thread_rng().fill(&mut plain[..]);
        let (secrets, encrypted) = rt.block_on(async {
            let secrets: Vec<String> = (0..NUM_SECRETS)
                .map(|_| create_broadcast_shared_secret_pub())
                .collect();
            let secret = secrets[NUM_SECRETS / 2].clone();
            let encrypted = encrypt_for_broadcast(
                plain.clone(),
                black_box(&secret),
                create_dummy_keypair("alice@example.org").unwrap().secret,
                true,
            )
            .await
            .unwrap();

            (secrets, encrypted)
        });

        b.iter(|| {
            let mut msg =
                decrypt(encrypted.clone().into_bytes(), &[], black_box(&secrets)).unwrap();
            let decrypted = msg.as_data_vec().unwrap();

            assert_eq!(black_box(decrypted), plain);
        });
    });
    group.bench_function("Decrypt pk encrypted", |b| {
        // TODO code duplication with previous benchmark
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut plain: Vec<u8> = vec![0; 500];
        thread_rng().fill(&mut plain[..]);
        let key_pair = create_dummy_keypair("alice@example.org").unwrap();
        let (secrets, encrypted) = rt.block_on(async {
            let secrets: Vec<String> = (0..NUM_SECRETS)
                .map(|_| create_broadcast_shared_secret_pub())
                .collect();
            let encrypted = pk_encrypt(
                plain.clone(),
                vec![black_box(key_pair.public.clone())],
                Some(key_pair.secret.clone()),
                true,
            )
            .await
            .unwrap();

            (secrets, encrypted)
        });

        b.iter(|| {
            let mut msg = decrypt(
                encrypted.clone().into_bytes(),
                &[key_pair.secret.clone()],
                black_box(&secrets),
            )
            .unwrap();
            let decrypted = msg.as_data_vec().unwrap();

            assert_eq!(black_box(decrypted), plain);
        });
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut secrets: Vec<String> = (0..NUM_SECRETS)
        .map(|_| create_broadcast_shared_secret_pub())
        .collect();

    // "secret" is the shared secret that was used to encrypt text_symmetrically_encrypted.eml:
    secrets[NUM_SECRETS / 2] = "secret".to_string();

    let context = rt.block_on(async {
        let context = create_context().await;
        for (i, secret) in secrets.iter().enumerate() {
            save_broadcast_shared_secret(&context, ChatId::new(10 + i as u32), &secret)
                .await
                .unwrap();
        }
        context
    });

    group.bench_function("Receive a public-key encrypted message", |b| {
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
    group.bench_function("Receive a symmetrically encrypted message", |b| {
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
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
