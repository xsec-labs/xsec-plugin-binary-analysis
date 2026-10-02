#!/usr/bin/env sh
set -eu

target="${1:?Rust target is required}"
output="${2:?output path is required}"
cargo build --release --locked --target "$target" -p binary-analysis-mcp
mkdir -p "$(dirname "$output")"
cp "target/$target/release/binary-analysis-mcp" "$output"
