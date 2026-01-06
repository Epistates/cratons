//! Lockfile parsing, serialization, and validation benchmarks.
//!
//! Measures performance of:
//! - TOML parsing for various lockfile sizes
//! - Lockfile serialization
//! - Package lookup operations
//! - Freshness checking
//! - Artifact cache operations

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use cratons_benchmarks::{generate_lockfile, generate_lockfile_toml};
use cratons_core::{ContentHash, Ecosystem};
use cratons_lockfile::{ArtifactCache, DependencyRef, LockedPackage, Lockfile};
use std::fs;
use tempfile::NamedTempFile;

/// Benchmark parsing a small lockfile.
fn bench_parse_small_lockfile(c: &mut Criterion) {
    let toml_content = generate_lockfile_toml(10);

    c.bench_function("parse_small_lockfile", |b| {
        b.iter(|| {
            let lockfile = Lockfile::from_str(black_box(&toml_content)).unwrap();
            black_box(lockfile);
        });
    });
}

/// Benchmark parsing a medium lockfile.
fn bench_parse_medium_lockfile(c: &mut Criterion) {
    let toml_content = generate_lockfile_toml(100);

    c.bench_function("parse_medium_lockfile", |b| {
        b.iter(|| {
            let lockfile = Lockfile::from_str(black_box(&toml_content)).unwrap();
            black_box(lockfile);
        });
    });
}

/// Benchmark parsing a large lockfile.
fn bench_parse_large_lockfile(c: &mut Criterion) {
    let toml_content = generate_lockfile_toml(500);

    c.bench_function("parse_large_lockfile", |b| {
        b.iter(|| {
            let lockfile = Lockfile::from_str(black_box(&toml_content)).unwrap();
            black_box(lockfile);
        });
    });
}

/// Benchmark parsing lockfiles of various sizes.
fn bench_parse_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_scaling");

    for count in [10, 50, 100, 250, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let toml_content = generate_lockfile_toml(count);
            b.iter(|| {
                let lockfile = Lockfile::from_str(black_box(&toml_content)).unwrap();
                black_box(lockfile);
            });
        });
    }

    group.finish();
}

/// Benchmark serializing a small lockfile.
fn bench_serialize_small_lockfile(c: &mut Criterion) {
    let lockfile = generate_lockfile(10);

    c.bench_function("serialize_small_lockfile", |b| {
        b.iter(|| {
            let toml = lockfile.to_toml_string().unwrap();
            black_box(toml);
        });
    });
}

/// Benchmark serializing a medium lockfile.
fn bench_serialize_medium_lockfile(c: &mut Criterion) {
    let lockfile = generate_lockfile(100);

    c.bench_function("serialize_medium_lockfile", |b| {
        b.iter(|| {
            let toml = lockfile.to_toml_string().unwrap();
            black_box(toml);
        });
    });
}

/// Benchmark serializing a large lockfile.
fn bench_serialize_large_lockfile(c: &mut Criterion) {
    let lockfile = generate_lockfile(500);

    c.bench_function("serialize_large_lockfile", |b| {
        b.iter(|| {
            let toml = lockfile.to_toml_string().unwrap();
            black_box(toml);
        });
    });
}

/// Benchmark serialization scaling.
fn bench_serialize_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize_scaling");

    for count in [10, 50, 100, 250, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        let lockfile = generate_lockfile(*count);

        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, _count| {
            b.iter(|| {
                let toml = lockfile.to_toml_string().unwrap();
                black_box(toml);
            });
        });
    }

    group.finish();
}

/// Benchmark loading lockfile from file.
fn bench_load_from_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_from_file");

    for count in [10, 50, 100, 250].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let toml_content = generate_lockfile_toml(count);
            let temp_file = NamedTempFile::new().unwrap();
            fs::write(temp_file.path(), &toml_content).unwrap();

            b.iter(|| {
                let lockfile = Lockfile::load(black_box(temp_file.path())).unwrap();
                black_box(lockfile);
            });
        });
    }

    group.finish();
}

/// Benchmark saving lockfile to file.
fn bench_save_to_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("save_to_file");

    for count in [10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let lockfile = generate_lockfile(count);

            b.iter_batched(
                || NamedTempFile::new().unwrap(),
                |temp_file| {
                    lockfile.save(temp_file.path()).unwrap();
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark package lookup by name.
fn bench_find_package(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_package");

    for count in [50, 100, 500, 1000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let lockfile = generate_lockfile(count);
            let search_idx = count / 2;
            let ecosystem = Ecosystem::Npm;
            let search_name = format!("package-{}-{}", ecosystem, search_idx);

            b.iter(|| {
                let result = lockfile.find_package(black_box(&search_name), black_box(ecosystem));
                black_box(result);
            });
        });
    }

    group.finish();
}

/// Benchmark getting packages for an ecosystem.
fn bench_packages_for_ecosystem(c: &mut Criterion) {
    let lockfile = generate_lockfile(500);

    let mut group = c.benchmark_group("packages_for_ecosystem");

    for ecosystem in Ecosystem::all() {
        group.bench_function(ecosystem.to_string(), |b| {
            b.iter(|| {
                let packages: Vec<_> = lockfile
                    .packages_for_ecosystem(black_box(*ecosystem))
                    .collect();
                black_box(packages.len());
            });
        });
    }

    group.finish();
}

/// Benchmark getting direct dependencies.
fn bench_direct_packages(c: &mut Criterion) {
    let mut group = c.benchmark_group("direct_packages");

    for count in [50, 100, 500].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let lockfile = generate_lockfile(count);

            b.iter(|| {
                let direct: Vec<_> = lockfile.direct_packages().collect();
                black_box(direct.len());
            });
        });
    }

    group.finish();
}

/// Benchmark lockfile freshness check.
fn bench_is_fresh(c: &mut Criterion) {
    let manifest_hash = ContentHash::blake3("test-manifest".to_string());
    let lockfile = generate_lockfile(100);

    let mut group = c.benchmark_group("is_fresh");

    group.bench_function("match", |b| {
        b.iter(|| {
            let result = lockfile.is_fresh(black_box(&manifest_hash));
            black_box(result);
        });
    });

    group.bench_function("mismatch", |b| {
        let different_hash = ContentHash::blake3("different-manifest".to_string());
        b.iter(|| {
            let result = lockfile.is_fresh(black_box(&different_hash));
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark adding packages to lockfile.
fn bench_add_package(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_package");

    for count in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            b.iter(|| {
                let manifest_hash = ContentHash::blake3("test".to_string());
                let mut lockfile = Lockfile::new(manifest_hash);

                for i in 0..count {
                    lockfile.add_package(LockedPackage {
                        name: format!("package-{}", i),
                        version: format!("1.{}.0", i),
                        ecosystem: Ecosystem::Npm,
                        source: format!("https://registry.npmjs.org/package-{}", i),
                        integrity: format!("sha256-{:064x}", i),
                        resolved_hash: ContentHash::blake3(format!("pkg-{}", i)),
                        direct: i < 10,
                        features: vec![],
                        dependencies: vec![],
                    });
                }
                black_box(lockfile);
            });
        });
    }

    group.finish();
}

/// Benchmark artifact cache operations.
fn bench_artifact_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("artifact_cache");

    // Add artifacts
    group.bench_function("add_artifact", |b| {
        b.iter(|| {
            let manifest_hash = ContentHash::blake3("test".to_string());
            let mut lockfile = Lockfile::new(manifest_hash);

            for i in 0..50 {
                let input_hash = format!("input-hash-{}", i);
                let output_hash = ContentHash::blake3(format!("output-{}", i));
                let cache = ArtifactCache::new(output_hash);
                lockfile.update_artifact_cache(input_hash, cache);
            }
            black_box(lockfile);
        });
    });

    // Lookup artifact
    group.bench_function("lookup_artifact", |b| {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        for i in 0..100 {
            let input_hash = format!("input-hash-{}", i);
            let output_hash = ContentHash::blake3(format!("output-{}", i));
            let cache = ArtifactCache::new(output_hash);
            lockfile.update_artifact_cache(input_hash, cache);
        }

        b.iter(|| {
            let result = lockfile.get_artifact_cache(black_box("input-hash-50"));
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark package count.
fn bench_package_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("package_count");

    for count in [50, 100, 500, 1000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let lockfile = generate_lockfile(count);

            b.iter(|| {
                let count = lockfile.package_count();
                black_box(count);
            });
        });
    }

    group.finish();
}

/// Benchmark iterating over all packages.
fn bench_iterate_packages(c: &mut Criterion) {
    let mut group = c.benchmark_group("iterate_packages");

    for count in [50, 100, 500].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let lockfile = generate_lockfile(count);

            b.iter(|| {
                let mut total = 0;
                for pkg in &lockfile.packages {
                    total += pkg.name.len();
                }
                black_box(total);
            });
        });
    }

    group.finish();
}

/// Benchmark parsing integrity hashes.
fn bench_parse_integrity(c: &mut Criterion) {
    let pkg = LockedPackage {
        name: "test-pkg".to_string(),
        version: "1.0.0".to_string(),
        ecosystem: Ecosystem::Npm,
        source: "https://registry.npmjs.org/test-pkg".to_string(),
        integrity: "sha256-abcdef1234567890".to_string(),
        resolved_hash: ContentHash::blake3("test".to_string()),
        direct: true,
        features: vec![],
        dependencies: vec![],
    };

    c.bench_function("parse_integrity", |b| {
        b.iter(|| {
            let hash = pkg.parse_integrity().unwrap();
            black_box(hash);
        });
    });
}

/// Benchmark creating dependency references.
fn bench_dependency_ref(c: &mut Criterion) {
    let mut group = c.benchmark_group("dependency_ref");

    for count in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            b.iter(|| {
                let mut refs = Vec::new();
                for i in 0..count {
                    refs.push(DependencyRef::new(
                        format!("dep-{}", i),
                        format!("1.{}.0", i),
                    ));
                }
                black_box(refs);
            });
        });
    }

    group.finish();
}

/// Benchmark round-trip (parse -> serialize -> parse).
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    for count in [10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let toml_content = generate_lockfile_toml(count);

            b.iter(|| {
                // Parse
                let lockfile = Lockfile::from_str(black_box(&toml_content)).unwrap();
                // Serialize
                let serialized = lockfile.to_toml_string().unwrap();
                // Parse again
                let lockfile2 = Lockfile::from_str(&serialized).unwrap();
                black_box(lockfile2);
            });
        });
    }

    group.finish();
}

/// Benchmark filtering packages by condition.
fn bench_filter_packages(c: &mut Criterion) {
    let lockfile = generate_lockfile(500);

    c.bench_function("filter_packages", |b| {
        b.iter(|| {
            let filtered: Vec<_> = lockfile
                .packages
                .iter()
                .filter(|pkg| pkg.direct && pkg.ecosystem == Ecosystem::Npm)
                .collect();
            black_box(filtered.len());
        });
    });
}

criterion_group!(
    benches,
    bench_parse_small_lockfile,
    bench_parse_medium_lockfile,
    bench_parse_large_lockfile,
    bench_parse_scaling,
    bench_serialize_small_lockfile,
    bench_serialize_medium_lockfile,
    bench_serialize_large_lockfile,
    bench_serialize_scaling,
    bench_load_from_file,
    bench_save_to_file,
    bench_find_package,
    bench_packages_for_ecosystem,
    bench_direct_packages,
    bench_is_fresh,
    bench_add_package,
    bench_artifact_cache,
    bench_package_count,
    bench_iterate_packages,
    bench_parse_integrity,
    bench_dependency_ref,
    bench_roundtrip,
    bench_filter_packages,
);

criterion_main!(benches);
