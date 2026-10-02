use serde_json::{json, Value};

use crate::host::HostContext;
use crate::model::{PatchDraft, PatchExport};

use super::host_rpc::{display_error, host_value};
use super::BinaryAnalysisServer;

pub(super) fn patch_draft(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    input: PatchDraft,
) -> Result<Value, String> {
    let revision = server
        .store
        .snapshot(&input.revision_id, &context.assignment_id)
        .map_err(display_error)?;
    if revision.snapshot.revision.sample_sha256 != input.sample_sha256
        || revision.snapshot.revision.slice != input.slice
    {
        return Err(
            "patch draft digest or slice does not match its immutable analysis revision".into(),
        );
    }
    let id = server
        .store
        .create_patch_set(&context.assignment_id, &input)
        .map_err(display_error)?;
    Ok(json!({ "patchSetId": id, "state": "draft" }))
}

pub(super) async fn patch_export(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    handle: &str,
    input: PatchExport,
) -> Result<Value, String> {
    let patch = server
        .store
        .patch_set(&input.patch_set_id, &context.assignment_id)
        .map_err(display_error)?;
    host_value(server, handle, "binary_patch_export", patch).await
}
