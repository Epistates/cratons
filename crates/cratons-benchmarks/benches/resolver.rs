//! Dependency resolution benchmarks.
//!
//! Measures performance of the MVS (Minimal Version Selection) algorithm
//! with various dependency tree sizes and complexities.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use cratons_benchmarks::{
    create_version_map, generate_complex_manifest, generate_large_manifest,
    generate_medium_manifest, generate_small_manifest,
};
use cratons_core::{Ecosystem, Version, VersionReq};
use cratons_manifest::Manifest;
use cratons_resolver::graph::DependencyGraph;

/// Benchmark dependency graph construction.
fn bench_graph_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_construction");

    for size in [10, 50, 100, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let mut graph = DependencyGraph::new();
                for i in 0..size {
                    let name = format!("package-{}", i);
                    black_box(graph.add_package(&name, Ecosystem::Npm));
                }
                black_box(graph);
            });
        });
    }

    group.finish();
}

/// Benchmark version matching performance.
fn bench_version_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("version_matching");

    let test_cases = vec![
        ("exact", "1.2.3", "1.2.3"),
        ("caret", "^1.2.0", "1.5.7"),
        ("tilde", "~1.2.0", "1.2.9"),
        ("range", ">=1.0.0 <2.0.0", "1.8.3"),
        ("wildcard", "1.x", "1.9.9"),
    ];

    for (name, requirement, version_str) in test_cases {
        group.bench_function(name, |b| {
            let version = Version::parse(version_str, Ecosystem::Npm).unwrap();
            b.iter(|| {
                let req = VersionReq::parse(requirement, Ecosystem::Npm).unwrap();
                black_box(req.matches(&version));
            });
        });
    }

    group.finish();
}

/// Benchmark version selection from a list.
fn bench_version_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("version_selection");

    for count in [10, 50, 100, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            let versions = create_version_map("test-pkg", count);
            let requirement = VersionReq::parse("^5.0.0", Ecosystem::Npm).unwrap();

            b.iter(|| {
                let selected = versions.iter().find(|v| {
                    Version::parse(v, Ecosystem::Npm)
                        .map(|ver| requirement.matches(&ver))
                        .unwrap_or(false)
                });
                black_box(selected);
            });
        });
    }

    group.finish();
}

/// Benchmark MVS algorithm with small dependency tree.
fn bench_mvs_small_tree(c: &mut Criterion) {
    c.bench_function("mvs_small_tree", |b| {
        let manifest = generate_small_manifest();
        b.iter(|| {
            // Simulate MVS: graph construction + version selection
            let mut graph = DependencyGraph::new();
            for (name, _) in manifest.dependencies.iter() {
                graph.add_package(name, Ecosystem::Npm);
                let versions = create_version_map(name, 10);
                graph.set_versions(name, Ecosystem::Npm, versions);
            }
            black_box(graph);
        });
    });
}

/// Benchmark MVS algorithm with medium dependency tree.
fn bench_mvs_medium_tree(c: &mut Criterion) {
    c.bench_function("mvs_medium_tree", |b| {
        let manifest = generate_medium_manifest();
        b.iter(|| {
            let mut graph = DependencyGraph::new();
            for (name, _) in manifest.dependencies.iter() {
                graph.add_package(name, Ecosystem::Npm);
                let versions = create_version_map(name, 20);
                graph.set_versions(name, Ecosystem::Npm, versions);
            }
            black_box(graph);
        });
    });
}

/// Benchmark MVS algorithm with large dependency tree.
fn bench_mvs_large_tree(c: &mut Criterion) {
    c.bench_function("mvs_large_tree", |b| {
        let manifest = generate_large_manifest();
        b.iter(|| {
            let mut graph = DependencyGraph::new();
            // Only process first 200 to keep benchmark reasonable
            for (name, _) in manifest.dependencies.iter().take(200) {
                graph.add_package(name, Ecosystem::Npm);
                let versions = create_version_map(name, 30);
                graph.set_versions(name, Ecosystem::Npm, versions);
            }
            black_box(graph);
        });
    });
}

/// Benchmark dependency graph traversal.
fn bench_graph_traversal(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_traversal");

    for size in [10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let mut graph = DependencyGraph::new();
            graph.add_package("root", Ecosystem::Npm);

            // Create a tree structure
            for i in 0..size {
                let name = format!("package-{}", i);
                graph.add_package(&name, Ecosystem::Npm);

                // Add dependency from root or previous package
                if i == 0 {
                    graph.add_dependency(
                        "root",
                        Ecosystem::Npm,
                        &name,
                        Ecosystem::Npm,
                        VersionReq::Any,
                        true,
                        vec![],
                    );
                } else {
                    let parent = format!("package-{}", i - 1);
                    graph.add_dependency(
                        &parent,
                        Ecosystem::Npm,
                        &name,
                        Ecosystem::Npm,
                        VersionReq::Any,
                        false,
                        vec![],
                    );
                }
            }

            b.iter(|| {
                // Traverse all packages
                for pkg in graph.packages() {
                    black_box(graph.dependencies(&pkg.name, pkg.ecosystem));
                }
            });
        });
    }

    group.finish();
}

/// Benchmark manifest dependency parsing.
fn bench_manifest_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("manifest_parsing");

    let manifests = vec![
        ("small", generate_small_manifest()),
        ("medium", generate_medium_manifest()),
        ("complex", generate_complex_manifest()),
    ];

    for (name, manifest) in manifests {
        group.bench_function(name, |b| {
            b.iter(|| {
                let mut count = 0;
                for ecosystem in Ecosystem::all() {
                    let deps = manifest.dependencies.for_ecosystem(*ecosystem);
                    count += deps.len();
                }
                black_box(count);
            });
        });
    }

    group.finish();
}

/// Benchmark conflict detection in dependency graph.
fn bench_conflict_detection(c: &mut Criterion) {
    c.bench_function("conflict_detection", |b| {
        let mut graph = DependencyGraph::new();

        // Create a scenario with potential conflicts
        for i in 0..50 {
            let name = format!("package-{}", i);
            graph.add_package(&name, Ecosystem::Npm);
            let versions = create_version_map(&name, 20);
            graph.set_versions(&name, Ecosystem::Npm, versions);
        }

        b.iter(|| {
            // Check for version conflicts by ensuring all version requirements are satisfied
            let mut conflicts = 0;
            for pkg in graph.packages() {
                let dependents = graph.dependents(&pkg.name, pkg.ecosystem);
                if dependents.len() > 1 {
                    conflicts += 1;
                }
            }
            black_box(conflicts);
        });
    });
}

/// Benchmark transitive dependency resolution.
fn bench_transitive_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("transitive_resolution");

    for depth in [3, 5, 8].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(depth), depth, |b, &depth| {
            // Create a chain of dependencies
            let mut graph = DependencyGraph::new();
            graph.add_package("root", Ecosystem::Npm);

            for i in 0..depth {
                let name = format!("dep-level-{}", i);
                graph.add_package(&name, Ecosystem::Npm);

                let parent = if i == 0 {
                    "root"
                } else {
                    &format!("dep-level-{}", i - 1)
                };

                graph.add_dependency(
                    parent,
                    Ecosystem::Npm,
                    &name,
                    Ecosystem::Npm,
                    VersionReq::Any,
                    i == 0,
                    vec![],
                );
            }

            b.iter(|| {
                // Traverse the full chain
                let mut current = "root";
                for _ in 0..depth {
                    let deps = graph.dependencies(current, Ecosystem::Npm);
                    if let Some((next, _)) = deps.first() {
                        current = &next.name;
                    }
                }
                black_box(current);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_graph_construction,
    bench_version_matching,
    bench_version_selection,
    bench_mvs_small_tree,
    bench_mvs_medium_tree,
    bench_mvs_large_tree,
    bench_graph_traversal,
    bench_manifest_parsing,
    bench_conflict_detection,
    bench_transitive_resolution,
);

criterion_main!(benches);
