# AGENTS.md

## Build
```bash
cargo build --release
```

## Test
```bash
cargo test
```

## Lint / Typecheck
```bash
cargo check
cargo clippy -- -D warnings
```

## Format
```bash
cargo fmt --check
```

## Script validation
```bash
bash -n setup
bash -n uninstall
bash -n build
bash -n update
```
