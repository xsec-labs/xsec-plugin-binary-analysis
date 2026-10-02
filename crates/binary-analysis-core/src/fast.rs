use anyhow::{Context, Result};
use librecurse::engine::{Engine, Target, XrefDirection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    resolve_static_address, AnalysisMode, AnalysisRevision, AnalysisSnapshot, BinaryAddress,
    Coverage, ManagedSample, Query, QueryResult, ReferenceDirection,
};

const RECURSE_ENGINE_VERSION: &str = "recurse-59e38d503c91ff160fe013f20719714272d22184";

pub fn fast_analysis(sample: &ManagedSample) -> Result<AnalysisSnapshot> {
    let engine = open_engine(sample)?;
    engine.analyze().map_err(anyhow::Error::msg)?;
    let coverage = fast_coverage(engine.indexing());
    let revision = revision(sample, coverage.clone());
    let summary = sanitize_summary(engine.summary().map_err(anyhow::Error::msg)?);
    let functions = engine.functions().map_err(anyhow::Error::msg)?;
    let strings = engine.strings().map_err(anyhow::Error::msg)?;
    let imports = engine.imports().map_err(anyhow::Error::msg)?;
    Ok(AnalysisSnapshot {
        revision,
        summary,
        functions: functions
            .iter()
            .map(|item| function_value(sample, item))
            .collect(),
        strings: strings
            .iter()
            .map(|item| string_value(sample, item))
            .collect(),
        imports: imports.iter().map(import_value).collect(),
    })
}

pub fn fast_query(sample: &ManagedSample, request: &Query) -> Result<QueryResult> {
    let engine = open_engine(sample)?;
    engine.analyze().map_err(anyhow::Error::msg)?;
    let coverage = fast_coverage(engine.indexing());
    let item = match request {
        Query::Disassemble { address, count } => {
            disassembly_value(sample, &*engine, address, *count)?
        }
        Query::Cfg { address } => cfg_value(sample, &*engine, address)?,
        Query::References { address, direction } => {
            references_value(sample, &*engine, address, *direction)?
        }
        Query::Decompile { .. } => {
            anyhow::bail!("fast analysis does not provide decompilation; start a full analysis")
        }
    };
    Ok(QueryResult {
        item,
        coverage,
        truncated: false,
    })
}

fn open_engine(sample: &ManagedSample) -> Result<Box<dyn Engine>> {
    librecurse::native::open(&sample.managed_path)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("open managed sample {}", sample.sample_sha256))
}

fn revision(sample: &ManagedSample, coverage: Coverage) -> AnalysisRevision {
    let digest = revision_digest(sample, RECURSE_ENGINE_VERSION);
    AnalysisRevision {
        id: format!("fast-{}", hex::encode(&digest[..12])),
        sample_sha256: sample.sample_sha256.clone(),
        slice: sample.slice.clone(),
        mode: AnalysisMode::Fast,
        engine_version: RECURSE_ENGINE_VERSION.into(),
        config_sha256: hex::encode(digest),
        coverage,
    }
}

fn revision_digest(sample: &ManagedSample, engine: &str) -> sha2::digest::Output<Sha256> {
    Sha256::digest(format!(
        "sample={};slice={};mode=fast;engine={engine}",
        sample.sample_sha256,
        sample.slice.as_deref().unwrap_or("default")
    ))
}

fn fast_coverage(indexing: bool) -> Coverage {
    Coverage {
        state: if indexing { "partial" } else { "complete" }.into(),
        indexed: !indexing,
        truncated: false,
        detail: if indexing {
            "Recurse lazy function index is still expanding"
        } else {
            "Recurse native/WASM index completed"
        }
        .into(),
    }
}

fn sanitize_summary(mut summary: Value) -> Value {
    if let Some(object) = summary.as_object_mut() {
        object.remove("path");
    }
    summary
}

fn function_value(sample: &ManagedSample, item: &librecurse::engine::FunctionInfo) -> Value {
    json!({ "address": address(sample, item.addr), "name": item.name, "size": item.size, "basicBlockCount": item.nbbs, "edgeCount": item.edges, "signature": item.signature })
}

fn string_value(sample: &ManagedSample, item: &librecurse::engine::StringRef) -> Value {
    json!({ "address": address(sample, item.addr), "text": item.string, "kind": item.kind })
}

fn import_value(item: &librecurse::engine::Import) -> Value {
    json!({ "name": item.name, "plt": item.plt.map(format_hex), "binding": item.bind, "kind": item.kind })
}

fn disassembly_value(
    sample: &ManagedSample,
    engine: &dyn Engine,
    requested_address: &BinaryAddress,
    count: Option<usize>,
) -> Result<Value> {
    let value = resolve_static_address(sample, requested_address)?;
    let disassembly = engine
        .disassemble(&Target::Addr(value), count)
        .map_err(anyhow::Error::msg)?;
    let ops = disassembly.ops.iter().map(|op| json!({ "address": address(sample, op.addr), "text": op.disasm, "bytes": op.bytes, "kind": op.kind, "jump": op.jump.map(format_hex), "fail": op.fail.map(format_hex) })).collect::<Vec<_>>();
    Ok(
        json!({ "address": address(sample, disassembly.addr), "name": disassembly.name, "size": disassembly.size, "operations": ops }),
    )
}

fn cfg_value(
    sample: &ManagedSample,
    engine: &dyn Engine,
    requested_address: &BinaryAddress,
) -> Result<Value> {
    let value = resolve_static_address(sample, requested_address)?;
    let graph = engine.function_graph(value).map_err(anyhow::Error::msg)?;
    let blocks = graph.blocks.iter().map(|block| json!({ "address": address(sample, block.addr), "instructionCount": block.ninstr, "jump": block.jump.map(format_hex), "fail": block.fail.map(format_hex), "targets": block.targets.iter().copied().map(format_hex).collect::<Vec<_>>() })).collect::<Vec<_>>();
    Ok(json!({ "address": address(sample, graph.addr), "name": graph.name, "blocks": blocks }))
}

fn references_value(
    sample: &ManagedSample,
    engine: &dyn Engine,
    requested_address: &BinaryAddress,
    direction: ReferenceDirection,
) -> Result<Value> {
    let value = resolve_static_address(sample, requested_address)?;
    let direction = match direction {
        ReferenceDirection::To => XrefDirection::To,
        ReferenceDirection::From => XrefDirection::From,
    };
    let references = engine
        .xrefs(&Target::Addr(value), direction)
        .map_err(anyhow::Error::msg)?;
    let items = references.iter().map(|item| json!({ "from": address(sample, item.from), "kind": item.kind, "to": item.to.map(format_hex), "functionName": item.fcn_name, "opcode": item.opcode })).collect::<Vec<_>>();
    Ok(json!({ "items": items }))
}

fn address(sample: &ManagedSample, value: u64) -> BinaryAddress {
    BinaryAddress::static_va(sample.sample_sha256.clone(), sample.slice.clone(), value)
}

fn format_hex(value: u64) -> String {
    format!("0x{value:x}")
}
