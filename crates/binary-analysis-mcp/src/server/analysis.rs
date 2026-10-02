use serde_json::{json, Value};
use xsec_binary_analysis_core::{query, ManagedSample, Query};

use super::host_rpc::{bounded_page, bounded_value, display_error, host_typed, host_value};
use super::BinaryAnalysisServer;
use crate::host::HostContext;
use crate::model::{
    AddressQuery, AnalysisStart, Annotation, Disassemble, EvidenceCreate, JobGet, References,
    RevisionPage,
};

pub(super) async fn analysis_start(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    handle: &str,
    input: AnalysisStart,
) -> Result<Value, String> {
    let sample: ManagedSample = host_typed(
        server,
        handle,
        "xsec.binary-analysis.sample.get",
        json!({ "sampleId": input.sample_id }),
    )
    .await?;
    let sample = server
        .store
        .prepare_analysis_sample(&sample)
        .map_err(display_error)?;
    let job = server
        .jobs
        .start_analysis(context.clone(), sample, input.mode)
        .map_err(display_error)?;
    Ok(json!({ "jobId": job.id, "state": job.state }))
}

pub(super) fn job_get(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    input: JobGet,
) -> Result<Value, String> {
    serde_json::to_value(
        server
            .store
            .job(&input.job_id, &context.assignment_id)
            .map_err(display_error)?,
    )
    .map_err(display_error)
}

pub(super) fn page(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    input: RevisionPage,
    kind: &str,
) -> Result<Value, String> {
    let (offset, _) = input.page.normalized().map_err(display_error)?;
    let value = server
        .store
        .page(
            &input.revision_id,
            &context.assignment_id,
            kind,
            &input.page,
        )
        .map_err(display_error)?;
    bounded_page(value, offset)
}

pub(super) async fn disassemble(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    handle: &str,
    input: Disassemble,
) -> Result<Value, String> {
    run_query(
        server,
        context,
        handle,
        &input.revision_id,
        Query::Disassemble {
            address: input.address,
            count: input.count,
        },
    )
    .await
}

pub(super) async fn cfg(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    handle: &str,
    input: AddressQuery,
) -> Result<Value, String> {
    run_query(
        server,
        context,
        handle,
        &input.revision_id,
        Query::Cfg {
            address: input.address,
        },
    )
    .await
}

pub(super) async fn references(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    handle: &str,
    input: References,
) -> Result<Value, String> {
    run_query(
        server,
        context,
        handle,
        &input.revision_id,
        Query::References {
            address: input.address,
            direction: input.direction,
        },
    )
    .await
}

pub(super) async fn decompile(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    handle: &str,
    input: AddressQuery,
) -> Result<Value, String> {
    run_query(
        server,
        context,
        handle,
        &input.revision_id,
        Query::Decompile {
            address: input.address,
        },
    )
    .await
}

async fn run_query(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    handle: &str,
    revision_id: &str,
    request: Query,
) -> Result<Value, String> {
    let stored = server
        .store
        .snapshot(revision_id, &context.assignment_id)
        .map_err(display_error)?;
    let sample = sample_for_revision(server, handle, &stored.sample_id).await?;
    let result = query(
        &sample,
        &stored.snapshot.revision,
        &request,
        server.jobs.engine_bundle(),
    )
    .map_err(display_error)?;
    bounded_value(
        json!({ "item": result.item, "coverage": result.coverage, "truncated": result.truncated }),
    )
}

async fn sample_for_revision(
    server: &BinaryAnalysisServer,
    handle: &str,
    sample_id: &str,
) -> Result<ManagedSample, String> {
    let sample = host_typed(
        server,
        handle,
        "xsec.binary-analysis.sample.get",
        json!({ "sampleId": sample_id }),
    )
    .await?;
    server
        .store
        .prepare_analysis_sample(&sample)
        .map_err(display_error)
}

pub(super) fn annotation(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    input: Annotation,
) -> Result<Value, String> {
    server
        .store
        .snapshot(&input.revision_id, &context.assignment_id)
        .map_err(display_error)?;
    if input.text.trim().is_empty() {
        return Err("annotation text cannot be empty".into());
    }
    server
        .store
        .upsert_annotation(&context.assignment_id, &input)
        .map_err(display_error)?;
    Ok(json!({ "saved": true }))
}

pub(super) async fn evidence(
    server: &BinaryAnalysisServer,
    context: &HostContext,
    handle: &str,
    input: EvidenceCreate,
) -> Result<Value, String> {
    let stored = server
        .store
        .snapshot(&input.revision_id, &context.assignment_id)
        .map_err(display_error)?;
    if input.start.sample_sha256 != stored.snapshot.revision.sample_sha256 {
        return Err("evidence address does not belong to the analysis sample".into());
    }
    host_value(server, handle, "binary_evidence_create", json!({ "sampleSha256": stored.snapshot.revision.sample_sha256, "analysisRevision": stored.snapshot.revision.id, "start": input.start, "end": input.end, "summary": input.summary, "coverage": stored.snapshot.revision.coverage, "toolSource": stored.snapshot.revision.engine_version })).await
}
