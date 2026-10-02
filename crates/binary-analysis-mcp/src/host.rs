use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;

const HOST_RPC_ENDPOINT_ENV: &str = "XSEC_PLUGIN_HOST_RPC_ENDPOINT";
const CONTEXT_METHOD: &str = "xsec.binary-analysis.context";

#[derive(Clone)]
pub struct HostClient {
    endpoint: Option<String>,
    client: Client,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostContext {
    pub assignment_id: String,
    #[allow(dead_code)]
    pub project_id: Option<String>,
    pub lease_generation: i64,
    pub role: String,
    pub artifact_sha256: Option<String>,
    pub capability_hash: Option<String>,
    pub allowed_tools: Vec<String>,
}

#[derive(Deserialize)]
struct HostRpcResponse<T> {
    result: Option<T>,
    error: Option<HostRpcError>,
}

#[derive(Deserialize)]
struct HostRpcError {
    message: String,
}

impl HostClient {
    pub fn from_environment() -> Result<Self> {
        let endpoint = match std::env::var(HOST_RPC_ENDPOINT_ENV) {
            Ok(value) => Some(validate_endpoint(&value)?),
            Err(std::env::VarError::NotPresent) => None,
            Err(error) => return Err(error).context("read XSEC_PLUGIN_HOST_RPC_ENDPOINT"),
        };
        Ok(Self {
            endpoint,
            client: Client::builder().build()?,
        })
    }

    pub async fn context(&self, handle: Option<&str>, tool: &str) -> Result<HostContext> {
        let context: HostContext = self
            .request(handle, CONTEXT_METHOD, json!({ "tool": tool }))
            .await?;
        context.validate(tool)?;
        Ok(context)
    }

    pub async fn request<T: DeserializeOwned>(
        &self,
        handle: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<T> {
        let endpoint = self
            .endpoint
            .as_deref()
            .context("binary analysis requires an XSEC Desktop Host RPC endpoint")?;
        let handle = handle
            .filter(|value| !value.trim().is_empty())
            .context("binary analysis requires an opaque context handle")?;
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(handle)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .context("request XSEC binary Host RPC")?;
        let status = response.status();
        let payload: HostRpcResponse<T> = response
            .json()
            .await
            .context("parse XSEC binary Host RPC response")?;
        if !status.is_success() {
            bail!("XSEC binary Host RPC returned HTTP {status}");
        }
        if let Some(error) = payload.error {
            bail!("XSEC binary Host RPC rejected request: {}", error.message);
        }
        payload
            .result
            .context("XSEC binary Host RPC returned no result")
    }
}

impl HostContext {
    fn validate(&self, tool: &str) -> Result<()> {
        if self.assignment_id.trim().is_empty()
            || self.lease_generation < 0
            || self.role != "parent" && self.role != "sub"
        {
            bail!("binary analysis Host context is incomplete");
        }
        if self.artifact_sha256.as_deref().map_or(true, str::is_empty)
            || self.capability_hash.as_deref().map_or(true, str::is_empty)
        {
            bail!("binary analysis Host context is missing frozen artifact identity");
        }
        if !self.allowed_tools.iter().any(|allowed| allowed == tool) {
            bail!("binary analysis MCP tool is absent from the frozen allowlist");
        }
        Ok(())
    }
}

fn validate_endpoint(value: &str) -> Result<String> {
    let endpoint = Url::parse(value).context("parse binary Host RPC endpoint")?;
    let valid = endpoint.scheme() == "http"
        && endpoint.host_str() == Some("127.0.0.1")
        && endpoint.port().is_some_and(|port| port != 0)
        && endpoint.path() == "/plugin-host-rpc"
        && endpoint.query().is_none()
        && endpoint.fragment().is_none()
        && endpoint.username().is_empty()
        && endpoint.password().is_none();
    if !valid {
        bail!("binary Host RPC endpoint must be the local /plugin-host-rpc route");
    }
    Ok(value.to_string())
}
