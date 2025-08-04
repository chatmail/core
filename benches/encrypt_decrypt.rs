use std::hint::black_box;
use std::path::PathBuf;

use criterion::{Criterion, criterion_group, criterion_main};
use deltachat::{
    Events,
    config::Config,
    context::Context,
    imex::{ImexMode, imex},
    pgp::{create_dummy_keypair, decrypt, encrypt_for_broadcast, pk_encrypt},
    receive_imf::receive_imf,
    stock_str::StockStrings,
    tools::create_broadcast_shared_secret_pub,
};
use rand::{Rng, thread_rng};
use tempfile::tempdir;

const NUM_SECRETS: usize = 500;

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
            let secret = secrets[thread_rng().gen_range::<usize, _>(0..NUM_SECRETS)].clone();
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
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
