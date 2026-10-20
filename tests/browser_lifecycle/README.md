# Binary frontend lifecycle browser checks

These checks load the actual frontend module in a real browser and read an
isolated SQLite database through Desktop's production `xsec-storage::Repository`.
The small Rust utility calls the real migration, project creation, sample insert
and sample list methods. The HTTP component maps those real rows into the sample
read response consumed by the frontend. It accepts only sample-list reads;
attempts to import, analyze, debug or sign are rejected.

The component does not implement Desktop authorization or the MCP transport.
Native Host loading/logging, analysis job polling, result paging, debugger actions,
patch export and signing require separate real Host acceptance.

The six cases cover a context update, disposal during a pending read, context
update during a pending read, initial read failure, an old control used after
disposal, and a late failed read after context update. The failure cases temporarily
rename the isolated sample table and observe a real Repository error. Every case
runs in its own iframe. The baseline is the committed frontend from
`6fb5ee8de16761768f9ad06705e198f5bae88d78`; all six fail on that revision and pass
with this change.

## Run

Use the workspace build resource controller for the Rust build and HTTP server.
Generate a temporary Cargo manifest outside the checkout with a binary pointing
at `storage/main.rs` and dependencies on the selected Desktop `xsec-storage` path,
its pinned `anyhow` and `serde_json` versions. Start from that Desktop Cargo.lock
and reuse its external-disk target and dependency cache. Build with `--offline`.

Create `seed-inputs.json` in an external evidence directory. It contains two
project entries with typed `NewBinarySample` inputs describing real test input
files and their SHA-256; `project_id` is replaced with the project created by
Repository. Keep the fields and input files as evidence. Create `baseline.js`
with `git show` for the exact baseline above.

The governed Python server command is:

```sh
rtk python3 tests/browser_lifecycle/serve.py \
  --root /absolute/path/to/xsec-plugin-binary-analysis \
  --evidence /Volumes/xsec-build/evidence/binary-lifecycle \
  --helper /absolute/path/to/xsec-binary-browser-read-model \
  --baseline /Volumes/xsec-build/evidence/binary-lifecycle/baseline.js \
  --database /Volumes/xsec-build/evidence/binary-lifecycle/browser.sqlite
```

The database must be new. Open the printed loopback URL in a real browser and
click the run button once. The server records `browser-results.json` and exits
when the cases finish. Preserve its result and resource reports, input hashes and
the final page screenshot. A case has a 25-second deadline; failures stay visible
and are not rerun automatically.
