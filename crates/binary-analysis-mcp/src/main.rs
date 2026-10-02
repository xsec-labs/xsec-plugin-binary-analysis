#[tokio::main]
async fn main() -> anyhow::Result<()> {
    binary_analysis_mcp::run_stdio().await
}
