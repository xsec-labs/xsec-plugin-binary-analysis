use serde::{Deserialize, Serialize};
use xsec_binary_analysis_core::{AnalysisMode, BinaryAddress, Page, ReferenceDirection};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisStart {
    pub sample_id: String,
    #[serde(default = "full_analysis_mode")]
    pub mode: AnalysisMode,
}

fn full_analysis_mode() -> AnalysisMode {
    AnalysisMode::Full
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobGet {
    pub job_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevisionPage {
    pub revision_id: String,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Disassemble {
    pub revision_id: String,
    pub address: BinaryAddress,
    pub count: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddressQuery {
    pub revision_id: String,
    pub address: BinaryAddress,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct References {
    pub revision_id: String,
    pub address: BinaryAddress,
    pub direction: ReferenceDirection,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Annotation {
    pub revision_id: String,
    pub address: BinaryAddress,
    pub text: String,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceCreate {
    pub revision_id: String,
    pub start: BinaryAddress,
    pub end: Option<BinaryAddress>,
    pub summary: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatchOp {
    pub rva: String,
    pub file_offset: String,
    pub expected_bytes: String,
    pub replacement_bytes: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatchDraft {
    pub revision_id: String,
    pub sample_sha256: String,
    pub slice: Option<String>,
    pub operations: Vec<PatchOp>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatchExport {
    pub patch_set_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugLaunch {
    pub sample_id: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugAttach {
    pub pid: u32,
    pub sample_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugControl {
    pub action: DebugAction,
    pub expected_stop_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DebugAction {
    Continue,
    Pause,
    StepIn,
    StepOver,
    StepOut,
    Detach,
    Terminate,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugWrite {
    pub kind: DebugWriteKind,
    pub expected_stop_revision: u64,
    pub register: Option<String>,
    pub value: Option<String>,
    pub address: Option<BinaryAddress>,
    pub expected_bytes: Option<String>,
    pub bytes: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DebugWriteKind {
    Register,
    Memory,
    SoftwareBreakpoint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignConfigure {
    pub kind: SignerKind,
    pub identity: String,
    pub external_tool_path: Option<String>,
    pub external_tool_sha256: Option<String>,
    pub argument_template: Option<Vec<String>>,
    pub verification_command_path: Option<String>,
    pub verification_command_sha256: Option<String>,
    pub verification_template: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SignerKind {
    MacosKeychain,
    WindowsExternal,
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use xsec_binary_analysis_core::AnalysisMode;

    use super::AnalysisStart;

    #[test]
    fn omitted_mode_defaults_to_full_analysis() {
        let input: AnalysisStart =
            serde_json::from_value(json!({ "sampleId": "sample-1" })).unwrap();

        assert_eq!(input.mode, AnalysisMode::Full);
    }

    #[test]
    fn explicit_fast_mode_is_preserved() {
        let input: AnalysisStart =
            serde_json::from_value(json!({ "sampleId": "sample-1", "mode": "fast" })).unwrap();

        assert_eq!(input.mode, AnalysisMode::Fast);
    }
}
