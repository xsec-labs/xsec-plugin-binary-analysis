//! Stdio transport that answers the SEP-2575 discovery probe.
//!
//! Desktop's MCP client (go-sdk 1.8 and later) sends `server/discover` as the
//! first message to every stdio server. It falls back to the legacy
//! `initialize` handshake only when the server answers that probe with a
//! JSON-RPC error. rmcp 2.x treats any first message other than `initialize`
//! as a fatal protocol error, so the process exited and the client reported a
//! closed connection during `initialize`. This transport answers the probe with
//! "method not found", which is the legacy answer, and passes every other line
//! to rmcp unchanged.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use serde_json::{json, Value};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const DISCOVER_METHOD: &[u8] = b"server/discover";
const METHOD_NOT_FOUND: i64 = -32601;
const FORWARD_BUFFER_BYTES: usize = 64 * 1024;

/// Starts the transport: the reader and writer for rmcp, and the session that
/// must be finished once the service has ended. Must run inside a Tokio runtime.
pub fn start() -> (DuplexStream, OutboundWriter, Session) {
    let (outbound, replies) = mpsc::unbounded_channel();
    let stdout = tokio::spawn(write_stdout(replies));
    let (forward, reader) = tokio::io::duplex(FORWARD_BUFFER_BYTES);
    let pump = tokio::spawn(pump(
        BufReader::new(tokio::io::stdin()),
        forward,
        outbound.clone(),
    ));
    (
        reader,
        OutboundWriter { outbound },
        Session { pump, stdout },
    )
}

/// The tasks behind a started transport.
pub struct Session {
    pump: JoinHandle<()>,
    stdout: JoinHandle<()>,
}

impl Session {
    /// Stops reading stdin and waits until every reply has reached stdout.
    pub async fn finish(self) {
        self.pump.abort();
        let _ = self.pump.await;
        let _ = self.stdout.await;
    }
}

/// What rmcp writes to stdout. Writes are queued in order, so the discovery
/// replies and rmcp's own responses cannot interleave.
pub struct OutboundWriter {
    outbound: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncWrite for OutboundWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.outbound.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stdout writer has stopped",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn write_stdout(mut replies: mpsc::UnboundedReceiver<Vec<u8>>) {
    let mut stdout = tokio::io::stdout();
    while let Some(bytes) = replies.recv().await {
        if stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err() {
            break;
        }
    }
}

/// Forwards stdin to rmcp line by line and answers discovery probes itself.
/// When the input ends, `forward` is dropped and rmcp sees end of input.
async fn pump<R>(mut input: R, mut forward: DuplexStream, replies: mpsc::UnboundedSender<Vec<u8>>)
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        line.clear();
        match input.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        match discovery_probe(&line) {
            Some(Probe::Request(id)) => {
                if replies.send(method_not_found(id)).is_err() {
                    break;
                }
            }
            Some(Probe::Notification) => {}
            None => {
                if forward.write_all(&line).await.is_err() {
                    break;
                }
            }
        }
    }
}

enum Probe {
    /// A `server/discover` request. Its id is echoed in the answer.
    Request(Value),
    /// A `server/discover` notification, which takes no answer.
    Notification,
}

fn discovery_probe(line: &[u8]) -> Option<Probe> {
    if !contains(line, DISCOVER_METHOD) {
        return None;
    }
    let message: Value = serde_json::from_slice(line).ok()?;
    if message.get("method").and_then(Value::as_str) != Some("server/discover") {
        return None;
    }
    Some(match message.get("id") {
        Some(id) => Probe::Request(id.clone()),
        None => Probe::Notification,
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn method_not_found(id: Value) -> Vec<u8> {
    let mut reply = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": METHOD_NOT_FOUND, "message": "Method not found" },
    }))
    .expect("a JSON-RPC error reply serializes");
    reply.push(b'\n');
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    const DISCOVER: &str = r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}"#;
    const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;

    /// Runs the pump over `input` to its end and returns what rmcp would read and
    /// what the client would receive on stdout.
    async fn run(input: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let (forward, mut received) = tokio::io::duplex(FORWARD_BUFFER_BYTES);
        let (replies_tx, mut replies_rx) = mpsc::unbounded_channel();
        pump(BufReader::new(input), forward, replies_tx).await;
        let mut forwarded = Vec::new();
        received
            .read_to_end(&mut forwarded)
            .await
            .expect("read forwarded input");
        let mut replies = Vec::new();
        while let Ok(reply) = replies_rx.try_recv() {
            replies.push(reply);
        }
        (forwarded, replies)
    }

    fn json_lines(lines: &[Vec<u8>]) -> Vec<Value> {
        lines
            .iter()
            .map(|line| serde_json::from_slice(line).expect("reply is JSON"))
            .collect()
    }

    #[tokio::test]
    async fn discovery_request_gets_method_not_found_and_is_not_forwarded() {
        let input = format!("{DISCOVER}\n");
        let (forwarded, replies) = run(input.as_bytes()).await;
        assert!(forwarded.is_empty());
        assert!(replies[0].ends_with(b"\n"));
        assert_eq!(
            json_lines(&replies),
            vec![json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": -32601, "message": "Method not found" },
            })]
        );
    }

    #[tokio::test]
    async fn discovery_request_keeps_a_string_id() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":\"probe-7\",\"method\":\"server/discover\"}\n";
        let (forwarded, replies) = run(input).await;
        assert!(forwarded.is_empty());
        assert_eq!(json_lines(&replies)[0]["id"], json!("probe-7"));
    }

    #[tokio::test]
    async fn discovery_notification_gets_no_answer() {
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"server/discover\"}\n";
        let (forwarded, replies) = run(input).await;
        assert!(forwarded.is_empty());
        assert!(replies.is_empty());
    }

    #[tokio::test]
    async fn discovery_then_initialize_forwards_only_initialize() {
        let input = format!("{DISCOVER}\n{INITIALIZE}\n");
        let (forwarded, replies) = run(input.as_bytes()).await;
        assert_eq!(forwarded, format!("{INITIALIZE}\n").into_bytes());
        assert_eq!(json_lines(&replies)[0]["id"], json!(1));
    }

    #[tokio::test]
    async fn other_messages_pass_through_byte_for_byte() {
        let input =
            format!("{INITIALIZE}\n{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}}\n");
        let (forwarded, replies) = run(input.as_bytes()).await;
        assert_eq!(forwarded, input.as_bytes());
        assert!(replies.is_empty());
    }

    #[tokio::test]
    async fn text_that_only_mentions_discovery_is_forwarded() {
        let input = b"server/discover is not JSON\n";
        let (forwarded, replies) = run(input).await;
        assert_eq!(forwarded, input);
        assert!(replies.is_empty());
    }

    #[tokio::test]
    async fn last_line_without_newline_is_forwarded() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}";
        let (forwarded, replies) = run(input).await;
        assert_eq!(forwarded, input);
        assert!(replies.is_empty());
    }
}
