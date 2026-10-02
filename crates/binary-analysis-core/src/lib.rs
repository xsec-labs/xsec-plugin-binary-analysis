//! Structured analysis façade over the pinned Recurse native engine and the
//! reviewed radare2/r2ghidra release bundle.

mod address;
mod engine_env;
mod fast;
mod full;
mod macho_slice;
mod macho_slice_format;
mod mapping;
mod model;

pub use address::{parse_hex_address, AddressSpace, BinaryAddress};
pub use fast::{fast_analysis, fast_query};
pub use full::{full_analysis, full_query, EngineBundle};
pub use macho_slice::prepare_sample_for_analysis;
pub use mapping::resolve_static_address;
pub use model::{
    AnalysisMode, AnalysisRevision, AnalysisSnapshot, Coverage, ManagedSample, Page, Query,
    QueryResult, ReferenceDirection,
};

use anyhow::Result;

/// Perform one analysis run. Full mode deliberately never falls back to fast
/// mode: a missing or failed release engine is an explicit failure.
pub fn analyze(
    sample: &ManagedSample,
    mode: AnalysisMode,
    bundle: Option<&EngineBundle>,
) -> Result<AnalysisSnapshot> {
    match mode {
        AnalysisMode::Fast => fast_analysis(sample),
        AnalysisMode::Full => full_analysis(
            sample,
            bundle.ok_or_else(|| {
                anyhow::anyhow!("full analysis requires the reviewed engine bundle")
            })?,
        ),
    }
}

/// Query a completed analysis with a fixed operation set. `Query` cannot carry
/// an engine command or a filesystem path.
pub fn query(
    sample: &ManagedSample,
    revision: &AnalysisRevision,
    request: &Query,
    bundle: Option<&EngineBundle>,
) -> Result<QueryResult> {
    match revision.mode {
        AnalysisMode::Fast => fast_query(sample, request),
        AnalysisMode::Full => full_query(
            sample,
            request,
            bundle.ok_or_else(|| {
                anyhow::anyhow!("full analysis requires the reviewed engine bundle")
            })?,
        ),
    }
}
