use rmcp::model::{CallToolResult, ContentBlock, ErrorData as McpError};
use rmcp::service::{RequestContext, RoleServer};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::store::PageResult;

use super::BinaryAnalysisServer;

const CONTEXT_HANDLE_META_KEY: &str = "com.xsec.desktop/contextHandle";
const RESPONSE_BUDGET_BYTES: usize = 48 * 1024;

pub(super) async fn host_value(
    server: &BinaryAnalysisServer,
    handle: &str,
    tool: &str,
    params: Value,
) -> Result<Value, String> {
    host_typed(
        server,
        handle,
        &format!("xsec.binary-analysis.{tool}"),
        params,
    )
    .await
}

pub(super) async fn host_typed<T: DeserializeOwned>(
    server: &BinaryAnalysisServer,
    handle: &str,
    method: &str,
    params: Value,
) -> Result<T, String> {
    server
        .host
        .request(Some(handle), method, params)
        .await
        .map_err(display_error)
}

pub(super) fn context_handle(context: &RequestContext<RoleServer>) -> Option<&str> {
    context
        .meta
        .0
        .get(CONTEXT_HANDLE_META_KEY)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

pub(super) fn parse<T: DeserializeOwned>(arguments: Value) -> Result<T, String> {
    serde_json::from_value(arguments)
        .map_err(|error| format!("invalid binary analysis arguments: {error}"))
}

pub(super) fn bounded_page(page: PageResult, offset: usize) -> Result<Value, String> {
    let mut value = serde_json::to_value(page).map_err(display_error)?;
    while serialized_size(&value)? > RESPONSE_BUDGET_BYTES {
        let Some(items) = value.get_mut("items").and_then(Value::as_array_mut) else {
            return Err("binary analysis page exceeds the 48 KiB response budget".into());
        };
        if items.len() <= 1 {
            return Err(
                "one binary analysis item exceeds the 48 KiB response budget; narrow the query"
                    .into(),
            );
        }
        items.pop();
        let cursor = offset
            .checked_add(items.len())
            .ok_or("binary page cursor overflows")?;
        value["nextCursor"] = Value::String(cursor.to_string());
        value["truncated"] = Value::Bool(true);
    }
    Ok(value)
}

pub(super) fn bounded_value(mut value: Value) -> Result<Value, String> {
    while serialized_size(&value)? > RESPONSE_BUDGET_BYTES {
        let Some(items) = value.get_mut("items").and_then(Value::as_array_mut) else {
            return Err(
                "binary analysis result exceeds the 48 KiB response budget; narrow the query"
                    .into(),
            );
        };
        if items.pop().is_none() {
            return Err(
                "binary analysis result exceeds the 48 KiB response budget; narrow the query"
                    .into(),
            );
        }
        value["truncated"] = Value::Bool(true);
    }
    Ok(value)
}

fn serialized_size(value: &Value) -> Result<usize, String> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(display_error)
}
pub(super) fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub(super) fn tool_result(payload: Value) -> Result<CallToolResult, McpError> {
    let content = ContentBlock::json(payload).map_err(|error| {
        McpError::internal_error(format!("serialize binary MCP response: {error}"), None)
    })?;
    Ok(CallToolResult::success(vec![content]))
}
pub(super) fn tool_error(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(
        json!({ "error": message }).to_string(),
    )])
}
