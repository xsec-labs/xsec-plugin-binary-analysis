use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;
use xsec_binary_analysis_core::{
    prepare_sample_for_analysis, AnalysisSnapshot, Coverage, ManagedSample, Page,
};

use crate::model::{Annotation, PatchDraft, PatchOp};

pub struct Store {
    connection: Mutex<Connection>,
    data_dir: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobRecord {
    pub id: String,
    pub state: String,
    pub kind: String,
    pub error: Option<String>,
    pub revision_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct StoredSnapshot {
    pub sample_id: String,
    pub snapshot: AnalysisSnapshot,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageResult {
    pub items: Vec<Value>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
    pub coverage: Coverage,
}

impl Store {
    pub fn open(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir).context("create PLUGIN_DATA directory")?;
        let connection = Connection::open(data_dir.join("binary-analysis.sqlite"))
            .context("open binary analysis SQLite")?;
        let store = Self {
            connection: Mutex::new(connection),
            data_dir: data_dir.to_path_buf(),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn create_job(&self, assignment_id: &str, kind: &str) -> Result<JobRecord> {
        let record = JobRecord {
            id: Uuid::new_v4().to_string(),
            state: "running".into(),
            kind: kind.into(),
            error: None,
            revision_id: None,
            created_at: now()?,
            updated_at: now()?,
        };
        self.with_connection(|connection| {
            connection.execute("INSERT INTO jobs(id, assignment_id, state, kind, error, revision_id, created_at, updated_at) VALUES(?1, ?2, ?3, ?4, NULL, NULL, ?5, ?6)", params![record.id, assignment_id, record.state, record.kind, record.created_at, record.updated_at])?;
            Ok(())
        })?;
        Ok(record)
    }

    pub fn prepare_analysis_sample(&self, sample: &ManagedSample) -> Result<ManagedSample> {
        prepare_sample_for_analysis(sample, &self.data_dir.join("sample-slices"))
    }

    pub fn complete_job(
        &self,
        job_id: &str,
        assignment_id: &str,
        sample_id: &str,
        snapshot: &AnalysisSnapshot,
    ) -> Result<()> {
        let snapshot_json =
            serde_json::to_string(snapshot).context("serialize analysis snapshot")?;
        self.with_connection(|connection| {
            let transaction = connection.unchecked_transaction().context("begin analysis completion")?;
            let existing = transaction.query_row(
                "SELECT sample_id, snapshot_json FROM snapshots WHERE assignment_id=?1 AND revision_id=?2",
                params![assignment_id, snapshot.revision.id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ).optional().context("read immutable analysis result")?;
            if let Some((stored_sample, stored_json)) = existing {
                let stored: Value = serde_json::from_str(&stored_json).context("parse immutable analysis result")?;
                let current = serde_json::to_value(snapshot).context("compare immutable analysis result")?;
                if stored_sample != sample_id || stored != current {
                    bail!("analysis revision conflicts with the stored immutable result");
                }
            } else {
                transaction.execute("INSERT INTO snapshots(revision_id, assignment_id, sample_id, snapshot_json, created_at) VALUES(?1, ?2, ?3, ?4, ?5)", params![snapshot.revision.id, assignment_id, sample_id, snapshot_json, now()?]).context("persist analysis result")?;
            }
            update_job(&transaction, job_id, assignment_id, "completed", None, Some(&snapshot.revision.id))?;
            transaction.commit().context("commit analysis result and job completion")
        })
    }

    pub fn fail_job(&self, job_id: &str, assignment_id: &str, error: &str) -> Result<()> {
        update_job_in_store(self, job_id, assignment_id, "failed", Some(error), None)
    }

    pub fn job(&self, job_id: &str, assignment_id: &str) -> Result<JobRecord> {
        let row = self.with_connection(|connection| Ok(connection.query_row("SELECT id, state, kind, error, revision_id, created_at, updated_at FROM jobs WHERE id=?1 AND assignment_id=?2", params![job_id, assignment_id], map_job).optional()?))?;
        row.context("binary analysis job is not authorized for this task")
    }

    pub fn snapshot(&self, revision_id: &str, assignment_id: &str) -> Result<StoredSnapshot> {
        let row = self.with_connection(|connection| Ok(connection.query_row("SELECT sample_id, snapshot_json FROM snapshots WHERE revision_id=?1 AND assignment_id=?2", params![revision_id, assignment_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).optional()?))?;
        row.map(|(sample_id, text)| decode_snapshot(sample_id, text))
            .transpose()?
            .context("analysis revision is not authorized for this task")
    }

    pub fn page(
        &self,
        revision_id: &str,
        assignment_id: &str,
        kind: &str,
        page: &Page,
    ) -> Result<PageResult> {
        let snapshot = self.snapshot(revision_id, assignment_id)?;
        let items = match kind {
            "functions" => snapshot.snapshot.functions,
            "strings" => snapshot.snapshot.strings,
            "imports" => snapshot.snapshot.imports,
            _ => bail!("unsupported binary analysis page kind"),
        };
        let (offset, limit) = page.normalized()?;
        Ok(page_items(
            items,
            snapshot.snapshot.revision.coverage,
            offset,
            limit,
        ))
    }

    pub fn upsert_annotation(&self, assignment_id: &str, input: &Annotation) -> Result<()> {
        let address_json =
            serde_json::to_string(&input.address).context("serialize annotation address")?;
        let tags_json = serde_json::to_string(&input.tags).context("serialize annotation tags")?;
        self.with_connection(|connection| {
            connection.execute("INSERT INTO annotations(assignment_id, revision_id, address_json, text, tags_json, updated_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(assignment_id, revision_id, address_json) DO UPDATE SET text=excluded.text, tags_json=excluded.tags_json, updated_at=excluded.updated_at", params![assignment_id, input.revision_id, address_json, input.text, tags_json, now()?])?;
            Ok(())
        })
    }

    pub fn create_patch_set(&self, assignment_id: &str, draft: &PatchDraft) -> Result<String> {
        validate_patch_draft(draft)?;
        let id = Uuid::new_v4().to_string();
        let operations =
            serde_json::to_string(&draft.operations).context("serialize patch operations")?;
        self.with_connection(|connection| {
            connection.execute("INSERT INTO patch_sets(id, assignment_id, revision_id, sample_sha256, slice, operations_json, created_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![id, assignment_id, draft.revision_id, draft.sample_sha256, draft.slice, operations, now()?])?;
            Ok(())
        })?;
        Ok(id)
    }

    pub fn patch_set(&self, id: &str, assignment_id: &str) -> Result<Value> {
        let row = self.with_connection(|connection| Ok(connection.query_row("SELECT revision_id, sample_sha256, slice, operations_json FROM patch_sets WHERE id=?1 AND assignment_id=?2", params![id, assignment_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, String>(3)?))).optional()?))?;
        row.map(|(revision, digest, slice, operations)| Ok::<Value, anyhow::Error>(json!({ "patchSetId": id, "analysisRevision": revision, "sampleSha256": digest, "slice": slice, "operations": serde_json::from_str::<Value>(&operations).context("parse stored patch operations")? }))).transpose()?.context("patch set is not authorized for this task")
    }

    fn migrate(&self) -> Result<()> {
        self.with_connection(|connection| {
            connection.execute_batch("PRAGMA foreign_keys=ON;").context("enable SQLite foreign keys")?;
            let transaction = connection.unchecked_transaction().context("begin binary analysis migration")?;
            transaction.execute_batch("CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, assignment_id TEXT NOT NULL, state TEXT NOT NULL, kind TEXT NOT NULL, error TEXT, revision_id TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS snapshots(revision_id TEXT NOT NULL, assignment_id TEXT NOT NULL, sample_id TEXT NOT NULL, snapshot_json TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(assignment_id, revision_id)); CREATE TABLE IF NOT EXISTS annotations(assignment_id TEXT NOT NULL, revision_id TEXT NOT NULL, address_json TEXT NOT NULL, text TEXT NOT NULL, tags_json TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(assignment_id, revision_id, address_json)); CREATE TABLE IF NOT EXISTS patch_sets(id TEXT PRIMARY KEY, assignment_id TEXT NOT NULL, revision_id TEXT NOT NULL, sample_sha256 TEXT NOT NULL, slice TEXT, operations_json TEXT NOT NULL, created_at INTEGER NOT NULL);").context("create binary analysis tables")?;
            let keys = {
                let mut statement = transaction.prepare("SELECT name FROM pragma_table_info('snapshots') WHERE pk>0 ORDER BY pk").context("inspect analysis result primary key")?;
                let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            if keys == ["revision_id"] {
                transaction.execute_batch("CREATE TABLE snapshots_scoped(revision_id TEXT NOT NULL, assignment_id TEXT NOT NULL, sample_id TEXT NOT NULL, snapshot_json TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(assignment_id, revision_id)); INSERT INTO snapshots_scoped SELECT revision_id, assignment_id, sample_id, snapshot_json, created_at FROM snapshots; DROP TABLE snapshots; ALTER TABLE snapshots_scoped RENAME TO snapshots;").context("scope existing analysis results by assignment")?;
            } else if keys != ["assignment_id", "revision_id"] {
                bail!("binary analysis SQLite has an unsupported result primary key");
            }
            transaction.commit().context("commit binary analysis migration")
        })
    }

    fn with_connection<T>(&self, operation: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("binary analysis SQLite lock poisoned"))?;
        operation(&connection)
    }
}

fn update_job_in_store(
    store: &Store,
    job_id: &str,
    assignment_id: &str,
    state: &str,
    error: Option<&str>,
    revision_id: Option<&str>,
) -> Result<()> {
    store.with_connection(|connection| {
        update_job(connection, job_id, assignment_id, state, error, revision_id)
    })
}

fn update_job(
    connection: &Connection,
    job_id: &str,
    assignment_id: &str,
    state: &str,
    error: Option<&str>,
    revision_id: Option<&str>,
) -> Result<()> {
    let updated = connection.execute("UPDATE jobs SET state=?1, error=?2, revision_id=?3, updated_at=?4 WHERE id=?5 AND assignment_id=?6 AND state='running'", params![state, error, revision_id, now()?, job_id, assignment_id])?;
    if updated != 1 {
        bail!("binary analysis job is not authorized for this task or is no longer running");
    }
    Ok(())
}

fn map_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRecord> {
    Ok(JobRecord {
        id: row.get(0)?,
        state: row.get(1)?,
        kind: row.get(2)?,
        error: row.get(3)?,
        revision_id: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn decode_snapshot(sample_id: String, text: String) -> Result<StoredSnapshot> {
    Ok(StoredSnapshot {
        sample_id,
        snapshot: serde_json::from_str(&text).context("parse stored analysis snapshot")?,
    })
}

fn page_items(items: Vec<Value>, coverage: Coverage, offset: usize, limit: usize) -> PageResult {
    let end = offset.saturating_add(limit).min(items.len());
    let next_cursor = (end < items.len()).then(|| end.to_string());
    let truncated = next_cursor.is_some();
    PageResult {
        items: items.into_iter().skip(offset).take(limit).collect(),
        next_cursor,
        truncated,
        coverage,
    }
}

fn validate_patch_draft(draft: &PatchDraft) -> Result<()> {
    if draft.operations.is_empty() {
        bail!("patch draft requires at least one operation");
    }
    let mut ranges = draft
        .operations
        .iter()
        .map(validated_range)
        .collect::<Result<Vec<_>>>()?;
    ranges.sort_unstable();
    if ranges.windows(2).any(|window| window[0].1 > window[1].0) {
        bail!("patch operations overlap");
    }
    Ok(())
}

fn validated_range(operation: &PatchOp) -> Result<(u64, u64)> {
    let offset = xsec_binary_analysis_core::parse_hex_address(&operation.file_offset)?;
    let expected = decode_patch_hex(&operation.expected_bytes)?;
    let replacement = decode_patch_hex(&operation.replacement_bytes)?;
    if expected.len() != replacement.len() {
        bail!("patch replacements must be equal-length");
    }
    let end = offset
        .checked_add(expected.len() as u64)
        .context("patch range overflow")?;
    Ok((offset, end))
}

fn decode_patch_hex(value: &str) -> Result<Vec<u8>> {
    let text = value
        .strip_prefix("0x")
        .context("patch bytes must be 0x-prefixed hex")?;
    if text.is_empty() {
        bail!("patch byte sequence cannot be empty");
    }
    hex::decode(text).context("patch bytes must be even-length hex")
}

fn now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system clock")?
        .as_millis()
        .try_into()
        .context("system clock exceeds SQLite timestamp range")
}
