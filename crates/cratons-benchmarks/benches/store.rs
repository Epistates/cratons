//! Content-addressed store benchmarks.
//!
//! Measures performance of:
//! - CAS insert operations with various file sizes
//! - CAS lookup operations
//! - Artifact store operations
//! - Blake3 hashing performance

use cratons_benchmarks::{FileSizes, generate_random_content};
use cratons_core::{ContentHash, HashAlgorithm, Hasher};
use cratons_store::{ContentAddressableStore, Store};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::fs;
use tempfile::TempDir;

/// Setup a temporary store for benchmarking.
fn setup_temp_store() -> (TempDir, Store) {
    let temp_dir = TempDir::new().unwrap();
    let store = Store::open(temp_dir.path()).unwrap();
    (temp_dir, store)
}

/// Setup a temporary CAS for benchmarking.
fn setup_temp_cas() -> (TempDir, ContentAddressableStore) {
    let temp_dir = TempDir::new().unwrap();
    let cas = ContentAddressableStore::new(temp_dir.path().join("cas"));
    fs::create_dir_all(temp_dir.path().join("cas")).unwrap();
    (temp_dir, cas)
}

/// Benchmark Blake3 hashing with various file sizes.
fn bench_blake3_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hashing");

    let sizes = vec![
        ("tiny_1kb", FileSizes::TINY),
        ("small_10kb", FileSizes::SMALL),
        ("medium_100kb", FileSizes::MEDIUM),
        ("large_1mb", FileSizes::LARGE),
        ("xlarge_10mb", FileSizes::XLARGE),
    ];

    for (name, size) in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("blake3", name), &size, |b, &size| {
            let content = generate_random_content(size);
            b.iter(|| {
                let hash = Hasher::hash_bytes(HashAlgorithm::Blake3, black_box(&content));
                black_box(hash);
            });
        });
    }

    group.finish();
}

/// Benchmark SHA-256 hashing for comparison.
fn bench_sha256_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_hashing");

    let sizes = vec![
        ("tiny_1kb", FileSizes::TINY),
        ("small_10kb", FileSizes::SMALL),
        ("medium_100kb", FileSizes::MEDIUM),
        ("large_1mb", FileSizes::LARGE),
    ];

    for (name, size) in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("sha256", name), &size, |b, &size| {
            let content = generate_random_content(size);
            b.iter(|| {
                let hash = Hasher::hash_bytes(HashAlgorithm::Sha256, black_box(&content));
                black_box(hash);
            });
        });
    }

    group.finish();
}

/// Benchmark CAS insert operations.
fn bench_cas_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("cas_insert");

    let sizes = vec![
        ("tiny_1kb", FileSizes::TINY),
        ("small_10kb", FileSizes::SMALL),
        ("medium_100kb", FileSizes::MEDIUM),
        ("large_1mb", FileSizes::LARGE),
    ];

    for (name, size) in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &size, |b, &size| {
            let content = generate_random_content(size);

            b.iter_batched(
                || setup_temp_cas(),
                |(_temp_dir, cas)| {
                    let hash = cas.store(black_box(&content)).unwrap();
                    black_box(hash);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark CAS lookup operations (cache hit).
fn bench_cas_lookup_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("cas_lookup_hit");

    let sizes = vec![
        ("tiny_1kb", FileSizes::TINY),
        ("small_10kb", FileSizes::SMALL),
        ("medium_100kb", FileSizes::MEDIUM),
    ];

    for (name, size) in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(name), &size, |b, &size| {
            let (_temp_dir, cas) = setup_temp_cas();
            let content = generate_random_content(size);
            let hash = cas.store(&content).unwrap();

            b.iter(|| {
                let result = cas.get(black_box(&hash));
                black_box(result);
            });
        });
    }

    group.finish();
}

/// Benchmark CAS lookup operations (cache miss).
fn bench_cas_lookup_miss(c: &mut Criterion) {
    c.bench_function("cas_lookup_miss", |b| {
        let (_temp_dir, cas) = setup_temp_cas();
        let fake_hash = ContentHash::blake3("nonexistent".to_string());

        b.iter(|| {
            let result = cas.get(black_box(&fake_hash));
            black_box(result);
        });
    });
}

/// Benchmark CAS read operations.
fn bench_cas_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("cas_read");

    let sizes = vec![
        ("tiny_1kb", FileSizes::TINY),
        ("small_10kb", FileSizes::SMALL),
        ("medium_100kb", FileSizes::MEDIUM),
        ("large_1mb", FileSizes::LARGE),
    ];

    for (name, size) in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &size, |b, &size| {
            let (_temp_dir, cas) = setup_temp_cas();
            let content = generate_random_content(size);
            let hash = cas.store(&content).unwrap();

            b.iter(|| {
                let data = cas.read(black_box(&hash)).unwrap();
                black_box(data);
            });
        });
    }

    group.finish();
}

/// Benchmark CAS contains check.
fn bench_cas_contains(c: &mut Criterion) {
    let (_temp_dir, cas) = setup_temp_cas();
    let content = generate_random_content(FileSizes::SMALL);
    let hash = cas.store(&content).unwrap();
    let missing_hash = ContentHash::blake3("nonexistent".to_string());

    let mut group = c.benchmark_group("cas_contains");

    group.bench_function("hit", |b| {
        b.iter(|| {
            let result = cas.contains(black_box(&hash));
            black_box(result);
        });
    });

    group.bench_function("miss", |b| {
        b.iter(|| {
            let result = cas.contains(black_box(&missing_hash));
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark store file operations.
fn bench_store_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_file");

    let sizes = vec![
        ("tiny_1kb", FileSizes::TINY),
        ("small_10kb", FileSizes::SMALL),
        ("medium_100kb", FileSizes::MEDIUM),
    ];

    for (name, size) in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &size, |b, &size| {
            b.iter_batched(
                || {
                    let temp = setup_temp_store();
                    let content = generate_random_content(size);
                    (temp, content)
                },
                |((_temp_dir, store), content)| {
                    let hash = store.store_file(black_box(&content)).unwrap();
                    black_box(hash);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark get file operations.
fn bench_get_file(c: &mut Criterion) {
    c.bench_function("get_file", |b| {
        let (_temp_dir, store) = setup_temp_store();
        let content = generate_random_content(FileSizes::MEDIUM);
        let hash = store.store_file(&content).unwrap();

        b.iter(|| {
            let path = store.get_file(black_box(&hash));
            black_box(path);
        });
    });
}

/// Benchmark multiple concurrent CAS insertions.
fn bench_cas_concurrent_inserts(c: &mut Criterion) {
    let mut group = c.benchmark_group("cas_concurrent_inserts");

    for count in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            b.iter_batched(
                || {
                    let cas_setup = setup_temp_cas();
                    let contents: Vec<_> = (0..count)
                        .map(|i| generate_random_content(FileSizes::SMALL + i * 100))
                        .collect();
                    (cas_setup, contents)
                },
                |((_temp_dir, cas), contents)| {
                    for content in &contents {
                        let hash = cas.store(black_box(content)).unwrap();
                        black_box(hash);
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark CAS deduplication (inserting same content multiple times).
fn bench_cas_deduplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("cas_deduplication");

    for size in [FileSizes::SMALL, FileSizes::MEDIUM, FileSizes::LARGE].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let content = generate_random_content(size);

            b.iter_batched(
                || setup_temp_cas(),
                |(_temp_dir, cas)| {
                    // Insert same content 10 times
                    for _ in 0..10 {
                        let hash = cas.store(black_box(&content)).unwrap();
                        black_box(hash);
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark CAS iteration over stored files.
fn bench_cas_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("cas_iteration");

    for count in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let (_temp_dir, cas) = setup_temp_cas();

            // Pre-populate CAS
            for i in 0..count {
                let content = generate_random_content(FileSizes::TINY + i * 10);
                cas.store(&content).unwrap();
            }

            b.iter(|| {
                let mut total = 0;
                for hash in cas.iter() {
                    if hash.is_ok() {
                        total += 1;
                    }
                }
                black_box(total);
            });
        });
    }

    group.finish();
}

/// Benchmark CAS size calculation.
fn bench_cas_size(c: &mut Criterion) {
    let (_temp_dir, cas) = setup_temp_cas();

    // Pre-populate with some files
    for i in 0..50 {
        let content = generate_random_content(FileSizes::SMALL + i * 100);
        cas.store(&content).unwrap();
    }

    c.bench_function("cas_size", |b| {
        b.iter(|| {
            let size = cas.size().unwrap();
            black_box(size);
        });
    });
}

/// Benchmark CAS count.
fn bench_cas_count(c: &mut Criterion) {
    let (_temp_dir, cas) = setup_temp_cas();

    // Pre-populate with some files
    for i in 0..50 {
        let content = generate_random_content(FileSizes::TINY + i * 10);
        cas.store(&content).unwrap();
    }

    c.bench_function("cas_count", |b| {
        b.iter(|| {
            let count = cas.count().unwrap();
            black_box(count);
        });
    });
}

/// Benchmark hash path computation.
fn bench_hash_path(c: &mut Criterion) {
    let (_temp_dir, cas) = setup_temp_cas();
    let content = generate_random_content(FileSizes::SMALL);
    let hash = Hasher::hash_bytes(HashAlgorithm::Blake3, &content);

    c.bench_function("hash_path", |b| {
        b.iter(|| {
            // Access through get which computes path
            let path = cas.get(black_box(&hash));
            black_box(path);
        });
    });
}

criterion_group!(
    benches,
    bench_blake3_hashing,
    bench_sha256_hashing,
    bench_cas_insert,
    bench_cas_lookup_hit,
    bench_cas_lookup_miss,
    bench_cas_read,
    bench_cas_contains,
    bench_store_file,
    bench_get_file,
    bench_cas_concurrent_inserts,
    bench_cas_deduplication,
    bench_cas_iteration,
    bench_cas_size,
    bench_cas_count,
    bench_hash_path,
);

criterion_main!(benches);
