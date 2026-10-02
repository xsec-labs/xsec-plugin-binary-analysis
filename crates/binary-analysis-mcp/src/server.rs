mod analysis;
mod debug;
mod host_rpc;
mod patch;

use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ErrorData as McpError, Implementation, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::Value;

use crate::host::{HostClient, HostContext};
use crate::jobs::JobCoordinator;
use crate::store::Store;
use crate::tool_schema::tools;

const SERVER_NAME: &str = "xsec-binary-analysis-mcp";

pub struct BinaryAnalysisServer {
    store: Arc<Store>,
    host: HostClient,
    jobs: JobCoordinator,
}

impl BinaryAnalysisServer {
    pub fn new(store: Arc<Store>, host: HostClient, jobs: JobCoordinator) -> Self {
        Self { store, host, jobs }
    }

    async fn execute(
        &self,
        request: CallToolRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> Result<Value, String> {
        let name = request.name.to_string();
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let handle = host_rpc::context_handle(context)
            .ok_or_else(|| "binary analysis requires an opaque context handle".to_string())?;
        let context = self
            .host
            .context(Some(handle), &name)
            .await
            .map_err(host_rpc::display_error)?;
        dispatch(self, &context, handle, &name, arguments).await
    }
}

impl ServerHandler for BinaryAnalysisServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_06_18)
            .with_server_info(Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION")))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match self.execute(request, &context).await {
            Ok(payload) => host_rpc::tool_result(payload),
            Err(error) => Ok(host_rpc::tool_error(error)),
        }
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        tools().into_iter().find(|tool| tool.name == name)
    }
}

async fn dispatch(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    handle: &str,
    name: &str,
    arguments: Value,
) -> Result<Value, String> {
    match name {
        "binary_sample_import" => host_rpc::host_value(server, handle, name, arguments).await,
        "binary_samples_list" => host_rpc::host_value(server, handle, name, arguments).await,
        "binary_sample_info" => host_rpc::host_value(server, handle, name, arguments).await,
        "binary_analysis_start" => {
            analysis::analysis_start(server, context, handle, host_rpc::parse(arguments)?).await
        }
        "binary_job_get" => analysis::job_get(server, context, host_rpc::parse(arguments)?),
        "binary_functions_list" => {
            analysis::page(server, context, host_rpc::parse(arguments)?, "functions")
        }
        "binary_strings_list" => {
            analysis::page(server, context, host_rpc::parse(arguments)?, "strings")
        }
        "binary_imports_list" => {
            analysis::page(server, context, host_rpc::parse(arguments)?, "imports")
        }
        "binary_disassemble" => {
            analysis::disassemble(server, context, handle, host_rpc::parse(arguments)?).await
        }
        "binary_cfg" => analysis::cfg(server, context, handle, host_rpc::parse(arguments)?).await,
        "binary_references_list" => {
            analysis::references(server, context, handle, host_rpc::parse(arguments)?).await
        }
        "binary_decompile" => {
            analysis::decompile(server, context, handle, host_rpc::parse(arguments)?).await
        }
        "binary_annotation_upsert" => {
            analysis::annotation(server, context, host_rpc::parse(arguments)?)
        }
        "binary_evidence_create" => {
            analysis::evidence(server, context, handle, host_rpc::parse(arguments)?).await
        }
        "binary_debug_launch" => {
            debug::debug_launch(server, handle, host_rpc::parse(arguments)?).await
        }
        "binary_debug_attach" => {
            debug::debug_attach(server, handle, host_rpc::parse(arguments)?).await
        }
        "binary_debug_control" => {
            debug::debug_control(server, handle, host_rpc::parse(arguments)?).await
        }
        "binary_debug_snapshot" => host_rpc::host_value(server, handle, name, arguments).await,
        "binary_debug_write" => {
            debug::debug_write(server, handle, host_rpc::parse(arguments)?).await
        }
        "binary_patch_draft" => patch::patch_draft(server, context, host_rpc::parse(arguments)?),
        "binary_patch_export" => {
            patch::patch_export(server, context, handle, host_rpc::parse(arguments)?).await
        }
        "binary_sign_configure" => {
            debug::sign_configure(server, handle, host_rpc::parse(arguments)?).await
        }
        _ => Err(format!("unknown binary analysis MCP tool: {name}")),
    }
}
