use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::engine_env::set_engine_library_search_path;
use crate::{
    resolve_static_address, AnalysisMode, AnalysisRevision, AnalysisSnapshot, BinaryAddress,
    Coverage, ManagedSample, Query, QueryResult, ReferenceDirection,
};

const ENGINE_VERSION: &str = "radare2-6.2.2+r2ghidra-6.2.2";
const R2_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Locations are release-artifact-owned, canonicalized and never accepted from
/// an MCP argument. The Factory validates this layout before publication.
#[derive(Clone, Debug)]
pub struct EngineBundle {
    pub engine_root: PathBuf,
    pub r2: PathBuf,
    pub r2_prefix: PathBuf,
    pub plugin_dir: PathBuf,
    pub sleigh_dir: PathBuf,
    pub r2_home: PathBuf,
}

impl EngineBundle {
    pub fn from_plugin_root(plugin_root: &Path, plugin_data: &Path) -> Result<Self> {
        let root = plugin_root
            .canonicalize()
            .context("canonicalize plugin root")?;
        let engine_root = checked_child(&root, "engine")?;
        let executable = if cfg!(windows) {
            "radare2/bin/r2.exe"
        } else {
            "radare2/bin/r2"
        };
        let r2 = checked_child(&engine_root, executable)?;
        let r2_prefix = checked_child(&engine_root, "radare2")?;
        let plugin_dir = checked_child(&r2_prefix, "plugins")?;
        let sleigh_dir = checked_child(&engine_root, "sleigh")?;
        if !r2.is_file() || !plugin_dir.is_dir() || !sleigh_dir.is_dir() {
            bail!("reviewed radare2/r2ghidra engine bundle is incomplete");
        }
        if !contains_ghidra_plugin(&plugin_dir)? {
            bail!("reviewed radare2 engine bundle has no core_ghidra plugin");
        }
        Ok(Self {
            engine_root,
            r2,
            r2_prefix,
            plugin_dir,
            sleigh_dir,
            r2_home: plugin_data.join("r2-home"),
        })
    }
}

pub fn full_analysis(sample: &ManagedSample, bundle: &EngineBundle) -> Result<AnalysisSnapshot> {
    let summary = r2_json(bundle, sample, "aaaa;ij")?;
    let functions = r2_array(bundle, sample, "aaaa;aflj")?;
    let strings = r2_array(bundle, sample, "aaaa;izj")?;
    let imports = r2_array(bundle, sample, "aaaa;iij")?;
    let revision = full_revision(sample, bundle)?;
    Ok(AnalysisSnapshot {
        revision,
        summary: normalize_json(sample, summary),
        functions: json_array(functions)?
            .into_iter()
            .map(|item| normalize_json(sample, item))
            .collect(),
        strings: json_array(strings)?
            .into_iter()
            .map(|item| normalize_json(sample, item))
            .collect(),
        imports: json_array(imports)?
            .into_iter()
            .map(|item| normalize_json(sample, item))
            .collect(),
    })
}

pub fn full_query(
    sample: &ManagedSample,
    request: &Query,
    bundle: &EngineBundle,
) -> Result<QueryResult> {
    let item = match request {
        Query::Disassemble { address, count } => r2_array(
            bundle,
            sample,
            &disassemble_script(sample, address, *count)?,
        )?,
        Query::Cfg { address } => {
            r2_array(bundle, sample, &address_script(sample, address, "agfj")?)?
        }
        Query::References { address, direction } => r2_array(
            bundle,
            sample,
            &references_script(sample, address, *direction)?,
        )?,
        Query::Decompile { address } => {
            r2_json(bundle, sample, &address_script(sample, address, "pdgj")?)?
        }
    };
    Ok(QueryResult {
        item: normalize_json(sample, item),
        coverage: full_coverage(),
        truncated: false,
    })
}

fn full_revision(sample: &ManagedSample, bundle: &EngineBundle) -> Result<AnalysisRevision> {
    let engine_config = engine_config_digest(bundle)?;
    let digest = Sha256::digest(format!(
        "sample={};slice={};mode=full;engine={ENGINE_VERSION};config={engine_config}",
        sample.sample_sha256,
        sample.slice.as_deref().unwrap_or("default")
    ));
    Ok(AnalysisRevision {
        id: format!("full-{}", hex::encode(&digest[..12])),
        sample_sha256: sample.sample_sha256.clone(),
        slice: sample.slice.clone(),
        mode: AnalysisMode::Full,
        engine_version: ENGINE_VERSION.into(),
        config_sha256: engine_config,
        coverage: full_coverage(),
    })
}

fn engine_config_digest(bundle: &EngineBundle) -> Result<String> {
    let mut files = Vec::new();
    append_engine_files(&bundle.engine_root, &mut files)?;
    files.sort();
    let mut digest = Sha256::new();
    digest.update(ENGINE_VERSION.as_bytes());
    for path in files {
        let relative = path
            .strip_prefix(&bundle.engine_root)
            .context("resolve reviewed engine-relative path")?;
        digest.update(relative.to_string_lossy().as_bytes());
        digest.update(
            fs::read(&path)
                .with_context(|| format!("read reviewed engine file {}", path.display()))?,
        );
    }
    Ok(hex::encode(digest.finalize()))
}

fn append_engine_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("read reviewed engine path {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "reviewed engine bundle contains a symbolic link: {}",
            path.display()
        );
    }
    if metadata.is_file() {
        files.push(path.to_path_buf());
    } else if metadata.is_dir() {
        for entry in fs::read_dir(path)
            .with_context(|| format!("read reviewed engine directory {}", path.display()))?
        {
            append_engine_files(&entry.context("read reviewed engine entry")?.path(), files)?;
        }
    } else {
        bail!(
            "reviewed engine bundle contains a non-regular entry: {}",
            path.display()
        );
    }
    Ok(())
}

fn contains_ghidra_plugin(plugin_dir: &Path) -> Result<bool> {
    for entry in fs::read_dir(plugin_dir).context("read reviewed r2 plugin directory")? {
        let entry = entry.context("read reviewed r2 plugin entry")?;
        if entry
            .file_type()
            .context("read reviewed r2 plugin type")?
            .is_file()
            && entry
                .file_name()
                .to_string_lossy()
                .starts_with("core_ghidra")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn full_coverage() -> Coverage {
    Coverage {
        state: "complete".into(),
        indexed: true,
        truncated: false,
        detail: "radare2 full analysis completed".into(),
    }
}

fn disassemble_script(
    sample: &ManagedSample,
    address: &BinaryAddress,
    count: Option<usize>,
) -> Result<String> {
    let count = count.unwrap_or(64).clamp(1, 512);
    Ok(format!(
        "aaaa;s {};pdj {count}",
        parse_address(sample, address)?
    ))
}

fn references_script(
    sample: &ManagedSample,
    address: &BinaryAddress,
    direction: ReferenceDirection,
) -> Result<String> {
    let command = match direction {
        ReferenceDirection::To => "axtj",
        ReferenceDirection::From => "axfj",
    };
    address_script(sample, address, command)
}

fn address_script(
    sample: &ManagedSample,
    address: &BinaryAddress,
    command: &str,
) -> Result<String> {
    Ok(format!(
        "aaaa;s {};{command}",
        parse_address(sample, address)?
    ))
}

fn parse_address(sample: &ManagedSample, address: &BinaryAddress) -> Result<String> {
    let value = resolve_static_address(sample, address)?;
    Ok(format!("0x{value:x}"))
}

fn r2_array(bundle: &EngineBundle, sample: &ManagedSample, script: &str) -> Result<Value> {
    let value = r2_json(bundle, sample, script)?;
    if !value.is_array() {
        bail!("reviewed radare2 command returned a non-array result");
    }
    Ok(value)
}

fn json_array(value: Value) -> Result<Vec<Value>> {
    value
        .as_array()
        .cloned()
        .context("reviewed radare2 returned a non-array result")
}

fn r2_json(bundle: &EngineBundle, sample: &ManagedSample, script: &str) -> Result<Value> {
    let stdout = run_r2(bundle, sample, script)?;
    serde_json::from_str(stdout.trim_matches('\0').trim())
        .context("parse structured radare2 result")
}

fn run_r2(bundle: &EngineBundle, sample: &ManagedSample, script: &str) -> Result<String> {
    let mut command = Command::new(&bundle.r2);
    command
        .args(["-2", "-q0", "-c", script])
        .arg(&sample.managed_path)
        .env_clear()
        .env("R2_PREFIX", &bundle.r2_prefix)
        .env("R2_HOME", &bundle.r2_home)
        .env("R2_LIBR_PLUGINS", &bundle.plugin_dir)
        .env("SLEIGHHOME", &bundle.sleigh_dir)
        .stdin(Stdio::null());
    set_engine_library_search_path(&mut command, &bundle.r2_prefix, &bundle.plugin_dir)?;
    let mut child = command
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("start reviewed radare2")?;
    let started = Instant::now();
    while child.try_wait()?.is_none() {
        if started.elapsed() > R2_TIMEOUT {
            child.kill().context("terminate timed-out radare2")?;
            let _ = child.wait();
            bail!(
                "radare2 analysis timed out after {} seconds",
                R2_TIMEOUT.as_secs()
            );
        }
        thread::sleep(POLL_INTERVAL);
    }
    let output = child.wait_with_output().context("collect radare2 output")?;
    if !output.status.success() {
        bail!(
            "radare2 analysis failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("radare2 emitted non-UTF-8 JSON")
}

fn normalize_json(sample: &ManagedSample, value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| normalize_json(sample, item))
                .collect(),
        ),
        Value::Object(mut object) => {
            normalize_address_fields(sample, &mut object);
            Value::Object(
                object
                    .into_iter()
                    .map(|(key, value)| (key, normalize_json(sample, value)))
                    .collect(),
            )
        }
        other => other,
    }
}

fn normalize_address_fields(sample: &ManagedSample, object: &mut serde_json::Map<String, Value>) {
    for key in [
        "addr", "offset", "vaddr", "from", "to", "jump", "fail", "plt",
    ] {
        let Some(value) = object.remove(key) else {
            continue;
        };
        let converted = value
            .as_u64()
            .map(|number| {
                json!(BinaryAddress::static_va(
                    sample.sample_sha256.clone(),
                    sample.slice.clone(),
                    number
                ))
            })
            .unwrap_or(value);
        object.insert(
            if key == "addr" {
                "address".into()
            } else {
                key.into()
            },
            converted,
        );
    }
}

fn checked_child(root: &Path, relative: &str) -> Result<PathBuf> {
    let child = root
        .join(relative)
        .canonicalize()
        .with_context(|| format!("canonicalize engine path {relative}"))?;
    if !child.starts_with(root) {
        bail!("engine path escapes the plugin artifact");
    }
    Ok(child)
}
