//! Manifest parsing and serialization benchmarks.
//!
//! Measures performance of:
//! - TOML parsing for various manifest sizes
//! - Manifest validation
//! - Dependency resolution from manifest
//! - TOML serialization

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use cratons_benchmarks::{
    generate_complex_manifest, generate_large_manifest, generate_manifest_toml,
    generate_medium_manifest, generate_small_manifest,
};
use cratons_core::Ecosystem;
use cratons_manifest::{Dependencies, Dependency, Manifest};
use std::fs;
use tempfile::NamedTempFile;

/// Benchmark parsing a small manifest.
fn bench_parse_small_manifest(c: &mut Criterion) {
    let toml_content = generate_manifest_toml(10);

    c.bench_function("parse_small_manifest", |b| {
        b.iter(|| {
            let manifest: Manifest = toml::from_str(black_box(&toml_content)).unwrap();
            black_box(manifest);
        });
    });
}

/// Benchmark parsing a medium manifest.
fn bench_parse_medium_manifest(c: &mut Criterion) {
    let toml_content = generate_manifest_toml(100);

    c.bench_function("parse_medium_manifest", |b| {
        b.iter(|| {
            let manifest: Manifest = toml::from_str(black_box(&toml_content)).unwrap();
            black_box(manifest);
        });
    });
}

/// Benchmark parsing a large manifest.
fn bench_parse_large_manifest(c: &mut Criterion) {
    let toml_content = generate_manifest_toml(500);

    c.bench_function("parse_large_manifest", |b| {
        b.iter(|| {
            let manifest: Manifest = toml::from_str(black_box(&toml_content)).unwrap();
            black_box(manifest);
        });
    });
}

/// Benchmark parsing manifest with various dependency counts.
fn bench_parse_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_scaling");

    for count in [5, 10, 50, 100, 250, 500].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let toml_content = generate_manifest_toml(count);
            b.iter(|| {
                let manifest: Manifest = toml::from_str(black_box(&toml_content)).unwrap();
                black_box(manifest);
            });
        });
    }

    group.finish();
}

/// Benchmark serializing a small manifest.
fn bench_serialize_small_manifest(c: &mut Criterion) {
    let manifest = generate_small_manifest();

    c.bench_function("serialize_small_manifest", |b| {
        b.iter(|| {
            let toml = toml::to_string_pretty(black_box(&manifest)).unwrap();
            black_box(toml);
        });
    });
}

/// Benchmark serializing a medium manifest.
fn bench_serialize_medium_manifest(c: &mut Criterion) {
    let manifest = generate_medium_manifest();

    c.bench_function("serialize_medium_manifest", |b| {
        b.iter(|| {
            let toml = toml::to_string_pretty(black_box(&manifest)).unwrap();
            black_box(toml);
        });
    });
}

/// Benchmark serializing a large manifest.
fn bench_serialize_large_manifest(c: &mut Criterion) {
    let manifest = generate_large_manifest();

    c.bench_function("serialize_large_manifest", |b| {
        b.iter(|| {
            let toml = toml::to_string_pretty(black_box(&manifest)).unwrap();
            black_box(toml);
        });
    });
}

/// Benchmark serialization scaling.
fn bench_serialize_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize_scaling");

    for count in [10, 50, 100, 250, 500].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        let manifest = cratons_benchmarks::generate_manifest_with_deps(*count);

        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, _count| {
            b.iter(|| {
                let toml = toml::to_string_pretty(black_box(&manifest)).unwrap();
                black_box(toml);
            });
        });
    }

    group.finish();
}

/// Benchmark loading manifest from file.
fn bench_load_from_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_from_file");

    for count in [10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let toml_content = generate_manifest_toml(count);
            let temp_file = NamedTempFile::new().unwrap();
            fs::write(temp_file.path(), &toml_content).unwrap();

            b.iter(|| {
                let manifest = Manifest::load(black_box(temp_file.path())).unwrap();
                black_box(manifest);
            });
        });
    }

    group.finish();
}

/// Benchmark iterating over dependencies.
fn bench_iterate_dependencies(c: &mut Criterion) {
    let mut group = c.benchmark_group("iterate_dependencies");

    let manifests = vec![
        ("small", generate_small_manifest()),
        ("medium", generate_medium_manifest()),
        ("complex", generate_complex_manifest()),
    ];

    for (name, manifest) in manifests {
        group.bench_function(name, |b| {
            b.iter(|| {
                let mut count = 0;
                for (_ecosystem, name, _dep) in manifest.dependencies.iter() {
                    count += name.len();
                }
                black_box(count);
            });
        });
    }

    group.finish();
}

/// Benchmark getting dependencies for specific ecosystem.
fn bench_get_ecosystem_deps(c: &mut Criterion) {
    let manifest = generate_large_manifest();

    let mut group = c.benchmark_group("get_ecosystem_deps");

    for ecosystem in Ecosystem::all() {
        group.bench_function(ecosystem.to_string(), |b| {
            b.iter(|| {
                let deps = manifest.dependencies.for_ecosystem(black_box(*ecosystem));
                black_box(deps.len());
            });
        });
    }

    group.finish();
}

/// Benchmark dependency count calculation.
fn bench_dependency_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("dependency_count");

    let manifests = vec![
        ("small", generate_small_manifest()),
        ("medium", generate_medium_manifest()),
        ("large", generate_large_manifest()),
    ];

    for (name, manifest) in manifests {
        group.bench_function(name, |b| {
            b.iter(|| {
                let count = black_box(&manifest).dependencies.len();
                black_box(count);
            });
        });
    }

    group.finish();
}

/// Benchmark creating a new manifest.
fn bench_create_manifest(c: &mut Criterion) {
    c.bench_function("create_manifest", |b| {
        b.iter(|| {
            let manifest = Manifest::default();
            black_box(manifest);
        });
    });
}

/// Benchmark adding dependencies to manifest.
fn bench_add_dependencies(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_dependencies");

    for count in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            b.iter(|| {
                let mut deps = Dependencies::default();
                for i in 0..count {
                    deps.npm.insert(
                        format!("package-{}", i),
                        Dependency::Version(format!("^{}.0.0", i % 10)),
                    );
                }
                black_box(deps);
            });
        });
    }

    group.finish();
}

/// Benchmark complex dependency structures.
fn bench_complex_dependencies(c: &mut Criterion) {
    c.bench_function("complex_dependencies", |b| {
        b.iter(|| {
            let manifest = generate_complex_manifest();
            // Iterate and count complex dependencies
            let mut complex_count = 0;
            for (_ecosystem, _name, dep) in manifest.dependencies.iter() {
                if matches!(dep, Dependency::Detailed(_)) {
                    complex_count += 1;
                }
            }
            black_box(complex_count);
        });
    });
}

/// Benchmark manifest validation.
fn bench_validate_manifest(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_manifest");

    let manifests = vec![
        ("small", generate_small_manifest()),
        ("medium", generate_medium_manifest()),
        ("complex", generate_complex_manifest()),
    ];

    for (name, manifest) in manifests {
        group.bench_function(name, |b| {
            b.iter(|| {
                // Validation happens during load, but we can check structure
                let valid = manifest.package.name.is_some()
                    && manifest.package.version.is_some()
                    && !manifest.dependencies.is_empty();
                black_box(valid);
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
            let toml_content = generate_manifest_toml(count);

            b.iter(|| {
                // Parse
                let manifest: Manifest = toml::from_str(black_box(&toml_content)).unwrap();
                // Serialize
                let serialized = toml::to_string_pretty(&manifest).unwrap();
                // Parse again
                let manifest2: Manifest = toml::from_str(&serialized).unwrap();
                black_box(manifest2);
            });
        });
    }

    group.finish();
}

/// Benchmark dependency lookup by name.
fn bench_dependency_lookup(c: &mut Criterion) {
    let manifest = generate_large_manifest();

    c.bench_function("dependency_lookup", |b| {
        b.iter(|| {
            // Look up a specific dependency
            let deps = manifest.dependencies.for_ecosystem(Ecosystem::Npm);
            let result = deps.get(black_box("package-npm-5"));
            black_box(result);
        });
    });
}

/// Benchmark filtering dependencies.
fn bench_filter_dependencies(c: &mut Criterion) {
    let manifest = generate_large_manifest();

    c.bench_function("filter_dependencies", |b| {
        b.iter(|| {
            let mut count = 0;
            for (_ecosystem, _name, dep) in manifest.dependencies.iter() {
                if let Dependency::Version(version) = dep {
                    if version.starts_with('^') {
                        count += 1;
                    }
                }
            }
            black_box(count);
        });
    });
}

criterion_group!(
    benches,
    bench_parse_small_manifest,
    bench_parse_medium_manifest,
    bench_parse_large_manifest,
    bench_parse_scaling,
    bench_serialize_small_manifest,
    bench_serialize_medium_manifest,
    bench_serialize_large_manifest,
    bench_serialize_scaling,
    bench_load_from_file,
    bench_iterate_dependencies,
    bench_get_ecosystem_deps,
    bench_dependency_count,
    bench_create_manifest,
    bench_add_dependencies,
    bench_complex_dependencies,
    bench_validate_manifest,
    bench_roundtrip,
    bench_dependency_lookup,
    bench_filter_dependencies,
);

criterion_main!(benches);
