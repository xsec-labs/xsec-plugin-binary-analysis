# XSEC Binary Analysis

`com.xsec.binary-analysis` is the first-party, on-demand binary-analysis plugin
for XSEC Desktop. It keeps authorization, sample intake, debug process lifecycle,
approval, signing keys and audit records in the Desktop Host. The plugin owns only
its portable skill, isolated frontend, structured stdio MCP server and analysis cache
inside `PLUGIN_DATA`.

## Engines

- **Full analysis** is the default and requires the reviewed radare2 6.2.2 and
  r2ghidra 6.2.2 bundle supplied by the release artifact.
- **Fast analysis** is explicit-only and uses Recurse's Apache-2.0 native/WASM
  analysis abstraction pinned in `Cargo.toml`.

Every MCP response uses hexadecimal address strings and includes a coverage/truncation
indicator. The server never exposes arbitrary engine commands, shell text, filesystem
paths or signer's secret material.

## Workbench

The context-bound frontend exposes sample paging, full/fast analysis, function
inspection, references, annotations, evidence creation, local debugging, patch
draft/export and signer configuration. Debugger control and writes, patch export,
and signer configuration are sent through the Host approval and audit boundary.
Complex operations use JSON objects validated by the MCP schema; the panel accepts
no engine or shell command text.

## Development

```sh
rtk cargo test --workspace --locked
rtk python3 -m unittest discover -s tests -v
rtk cargo clippy --workspace --all-targets -- -D warnings
rtk sh scripts/build-native-sidecar.sh <rust-target> bin/binary-analysis-mcp
rtk pnpm --dir ../desktop plugin validate "$PWD"
rtk pnpm --dir ../desktop plugin build "$PWD"
```

For frontend or Sidecar work, follow XSEC Desktop's real-host logging checklist in
`desktop/docs/plugins/development-logging.md`; the preview command is not a Host test.
