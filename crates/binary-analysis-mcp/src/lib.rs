mod host;
mod jobs;
mod model;
mod server;
mod store;
mod tool_schema;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use rmcp::ServiceExt;
use xsec_binary_analysis_core::EngineBundle;

use crate::host::HostClient;
use crate::jobs::JobCoordinator;
use crate::server::BinaryAnalysisServer;
use crate::store::Store;

const PLUGIN_DATA_ENV: &str = "PLUGIN_DATA";
const PLUGIN_ROOT_ENV: &str = "PLUGIN_ROOT";

/// Start the structured stdio MCP service. stdout stays owned by rmcp; all
/// diagnostics go to stderr so a malformed log entry cannot corrupt JSON-RPC.
pub async fn run_stdio() -> Result<()> {
    let data_dir = required_path(PLUGIN_DATA_ENV)?;
    let store = Arc::new(Store::open(&data_dir)?);
    let host = HostClient::from_environment()?;
    let bundle = engine_bundle(&data_dir)?;
    let jobs = JobCoordinator::new(store.clone(), bundle);
    let server = BinaryAnalysisServer::new(store, host, jobs);
    eprintln!("binary_analysis_mcp.started mode=embedded-required");
    let running = server.serve(rmcp::transport::stdio()).await?;
    running.waiting().await?;
    Ok(())
}

fn required_path(name: &str) -> Result<PathBuf> {
    let value = std::env::var_os(name).with_context(|| format!("{name} is required"))?;
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty() {
        anyhow::bail!("{name} cannot be empty");
    }
    Ok(path)
}

fn engine_bundle(plugin_data: &Path) -> Result<Option<EngineBundle>> {
    let root = match std::env::var_os(PLUGIN_ROOT_ENV) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        Some(_) => anyhow::bail!("PLUGIN_ROOT cannot be empty"),
        None => return Ok(None),
    };
    EngineBundle::from_plugin_root(&root, plugin_data).map(Some)
}
