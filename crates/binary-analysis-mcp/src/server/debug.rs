use serde_json::Value;

use crate::model::{DebugAttach, DebugControl, DebugLaunch, DebugWrite, SignConfigure};

use super::host_rpc::{display_error, host_value};
use super::BinaryAnalysisServer;

pub(super) async fn debug_launch(
    server: &BinaryAnalysisServer,
    handle: &str,
    input: DebugLaunch,
) -> Result<Value, String> {
    host_value(
        server,
        handle,
        "binary_debug_launch",
        serde_json::to_value(input).map_err(display_error)?,
    )
    .await
}
pub(super) async fn debug_attach(
    server: &BinaryAnalysisServer,
    handle: &str,
    input: DebugAttach,
) -> Result<Value, String> {
    host_value(
        server,
        handle,
        "binary_debug_attach",
        serde_json::to_value(input).map_err(display_error)?,
    )
    .await
}
pub(super) async fn debug_control(
    server: &BinaryAnalysisServer,
    handle: &str,
    input: DebugControl,
) -> Result<Value, String> {
    host_value(
        server,
        handle,
        "binary_debug_control",
        serde_json::to_value(input).map_err(display_error)?,
    )
    .await
}
pub(super) async fn debug_write(
    server: &BinaryAnalysisServer,
    handle: &str,
    input: DebugWrite,
) -> Result<Value, String> {
    host_value(
        server,
        handle,
        "binary_debug_write",
        serde_json::to_value(input).map_err(display_error)?,
    )
    .await
}

pub(super) async fn sign_configure(
    server: &BinaryAnalysisServer,
    handle: &str,
    input: SignConfigure,
) -> Result<Value, String> {
    host_value(
        server,
        handle,
        "binary_sign_configure",
        serde_json::to_value(input).map_err(display_error)?,
    )
    .await
}
