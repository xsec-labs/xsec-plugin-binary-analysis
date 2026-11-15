//! The binary speaks MCP over stdio. A discovery probe is refused with
//! "method not found", after which the legacy handshake and tool listing work
//! and the process exits cleanly at end of input.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

#[test]
fn discovery_probe_is_refused_and_the_legacy_handshake_still_works() {
    let data = tempfile::tempdir().expect("plugin data directory");
    let mut child = Command::new(env!("CARGO_BIN_EXE_binary-analysis-mcp"))
        .env_clear()
        .env("PLUGIN_DATA", data.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn binary-analysis-mcp");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));

    let answer = exchange(
        &mut stdin,
        &mut stdout,
        json!({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}),
    );
    assert_eq!(answer["id"], json!(1));
    assert_eq!(answer["error"]["code"], json!(-32601));

    let answer = exchange(
        &mut stdin,
        &mut stdout,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"}
            }
        }),
    );
    assert_eq!(answer["id"], json!(2));
    assert!(answer["result"]["capabilities"].is_object(), "{answer}");

    write_line(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    let answer = exchange(
        &mut stdin,
        &mut stdout,
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}),
    );
    assert_eq!(answer["id"], json!(3));
    assert!(
        answer["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "{answer}"
    );

    drop(stdin);
    let mut rest = String::new();
    stdout
        .read_to_string(&mut rest)
        .expect("read until end of output");
    assert!(
        rest.is_empty(),
        "unexpected output after end of input: {rest}"
    );
    let status = child.wait().expect("wait for binary-analysis-mcp");
    assert!(status.success(), "binary-analysis-mcp exited with {status}");
}

fn exchange(stdin: &mut impl Write, stdout: &mut impl BufRead, request: Value) -> Value {
    write_line(stdin, request);
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read a reply");
    serde_json::from_str(&line)
        .unwrap_or_else(|error| panic!("reply {line:?} is not JSON: {error}"))
}

fn write_line(stdin: &mut impl Write, message: Value) {
    let mut bytes = serde_json::to_vec(&message).expect("serialize a request");
    bytes.push(b'\n');
    stdin.write_all(&bytes).expect("write a request");
    stdin.flush().expect("flush a request");
}
