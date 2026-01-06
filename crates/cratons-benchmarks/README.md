# cratons-benchmarks

Comprehensive benchmark suite for the Cratons package manager using [Criterion.rs](https://github.com/bheisler/criterion.rs).

## Overview

This crate provides performance benchmarks for all critical components of Cratons:

- **Resolver Benchmarks** - Dependency resolution, MVS algorithm, version matching
- **Store Benchmarks** - Content-addressed storage, Blake3 hashing, file operations
- **Manifest Benchmarks** - TOML parsing/serialization, dependency iteration
- **Lockfile Benchmarks** - Lockfile parsing/serialization, package lookups, freshness checks

## Running Benchmarks

### Run all benchmarks
```bash
cargo bench -p cratons-benchmarks
```

### Run specific benchmark suite
```bash
cargo bench -p cratons-benchmarks --bench resolver
cargo bench -p cratons-benchmarks --bench store
cargo bench -p cratons-benchmarks --bench manifest
cargo bench -p cratons-benchmarks --bench lockfile
```

### Run specific benchmark function
```bash
cargo bench -p cratons-benchmarks --bench resolver mvs_small_tree
cargo bench -p cratons-benchmarks --bench store blake3_hashing
```

### Generate HTML reports
```bash
cargo bench -p cratons-benchmarks
# Reports are saved to target/criterion/report/index.html
```

## Benchmark Suites

### Resolver Benchmarks (`benches/resolver.rs`)

Tests dependency resolution performance:

- **Graph Construction** - Building dependency graphs (10-1000 packages)
- **Version Matching** - Testing version requirement matching (exact, caret, tilde, range)
- **Version Selection** - Finding versions from lists (10-1000 versions)
- **MVS Algorithm** - Complete resolution with small/medium/large trees
- **Graph Traversal** - Walking dependency relationships
- **Conflict Detection** - Identifying version conflicts
- **Transitive Resolution** - Resolving multi-level dependencies

### Store Benchmarks (`benches/store.rs`)

Tests content-addressed storage performance:

- **Blake3 Hashing** - Hash computation for various file sizes (1KB - 10MB)
- **SHA-256 Hashing** - Comparison with SHA-256
- **CAS Insert** - Storing files in content-addressed storage
- **CAS Lookup** - Finding files by hash (cache hit/miss)
- **CAS Read** - Reading stored content
- **Deduplication** - Handling duplicate content efficiently
- **Concurrent Operations** - Multiple simultaneous inserts
- **Store Iteration** - Walking all stored files

### Manifest Benchmarks (`benches/manifest.rs`)

Tests manifest parsing and manipulation:

- **Parse Scaling** - TOML parsing with 5-500 dependencies
- **Serialize Scaling** - TOML serialization with 10-1000 packages
- **File I/O** - Loading from and saving to disk
- **Dependency Iteration** - Walking dependency lists
- **Ecosystem Filtering** - Getting dependencies per ecosystem
- **Complex Dependencies** - Handling detailed dependency specs
- **Round-trip** - Parse → Serialize → Parse integrity
- **Validation** - Checking manifest correctness

### Lockfile Benchmarks (`benches/lockfile.rs`)

Tests lockfile operations:

- **Parse Scaling** - TOML parsing with 10-1000 packages
- **Serialize Scaling** - TOML serialization with 10-1000 packages
- **Package Lookup** - Finding packages by name/ecosystem
- **Freshness Checks** - Comparing manifest hashes
- **Artifact Cache** - Build cache operations
- **Direct Dependencies** - Filtering direct vs transitive deps
- **Round-trip** - Parse → Serialize → Parse integrity
- **Iteration** - Walking all locked packages

## Benchmark Configuration

The benchmarks are configured with:

- **Statistical rigor** - Multiple samples with outlier detection
- **HTML reports** - Visual charts and comparisons
- **Async support** - Tokio runtime for async operations
- **Throughput metrics** - Operations per second where applicable

## Fixture Generation

The `src/lib.rs` module provides helper functions for generating test data:

- `generate_small_manifest()` - 10 dependencies
- `generate_medium_manifest()` - 100 dependencies
- `generate_large_manifest()` - 1000 dependencies
- `generate_complex_manifest()` - Various dependency types
- `generate_lockfile(count)` - Lockfile with N packages
- `generate_random_content(size)` - Random bytes for CAS tests

## Performance Targets

Expected performance characteristics (on modern hardware):

### Resolver
- Small tree (10 packages): < 1ms
- Medium tree (100 packages): < 50ms
- Large tree (1000 packages): < 500ms

### Store
- Blake3 hashing (1MB): < 1ms
- CAS insert (1MB): < 5ms
- CAS lookup (cache hit): < 100ns

### Manifest
- Parse (100 deps): < 1ms
- Serialize (100 deps): < 2ms

### Lockfile
- Parse (1000 packages): < 10ms
- Serialize (1000 packages): < 20ms

## Best Practices

Based on [Criterion.rs best practices (2025)](https://docs.rs/criterion/latest/criterion/):

1. **Use release mode** - Benchmarks automatically compile with optimizations
2. **Minimize noise** - Close unnecessary applications when benchmarking
3. **Multiple runs** - Criterion automatically handles statistical analysis
4. **Baseline comparisons** - Use `--save-baseline` to track performance over time
5. **Async overhead** - Prefer sync benchmarks where possible for accuracy

## References

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Async Benchmarking](https://bheisler.github.io/criterion.rs/book/user_guide/benchmarking_async.html)
- [Criterion Statistics Guide](https://bheisler.github.io/criterion.rs/book/user_guide/advanced_configuration.html)

## Contributing

When adding new benchmarks:

1. Use descriptive function names prefixed with `bench_`
2. Add appropriate throughput metrics (`Throughput::Elements` or `Throughput::Bytes`)
3. Test multiple input sizes to show scaling behavior
4. Document expected performance in comments
5. Use `black_box()` to prevent compiler optimizations from skewing results

## License

MIT OR Apache-2.0
