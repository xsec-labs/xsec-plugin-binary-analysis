use std::sync::{Arc, OnceLock};

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use xsec_binary_analysis_core::{analyze, AnalysisMode, AnalysisSnapshot, ManagedSample};

use super::complete_analysis;
use crate::store::Store;

fn real_analysis() -> &'static (ManagedSample, AnalysisSnapshot) {
    static ANALYSIS: OnceLock<(ManagedSample, AnalysisSnapshot)> = OnceLock::new();
    ANALYSIS.get_or_init(|| {
        let executable = std::env::current_exe().expect("current native test executable");
        let digest = Sha256::digest(std::fs::read(&executable).expect("read executable"));
        let sample = ManagedSample {
            sample_id: "real-native-executable".into(),
            sample_sha256: hex::encode(digest),
            format: "native".into(),
            architecture: None,
            slice: None,
            managed_path: executable,
        };
        let snapshot = analyze(&sample, AnalysisMode::Fast, None).expect("real fast analysis");
        (sample, snapshot)
    })
}

fn database(dir: &TempDir) -> Connection {
    Connection::open(dir.path().join("binary-analysis.sqlite")).expect("real SQLite connection")
}

fn worker(store: Arc<Store>, assignment: &str, job: &str) -> anyhow::Result<()> {
    complete_analysis(
        store,
        None,
        assignment.into(),
        job.into(),
        real_analysis().0.clone(),
        AnalysisMode::Fast,
    )
}

#[test]
fn repeated_real_analysis_completes_and_reuses_immutable_snapshot() {
    let dir = TempDir::new().expect("isolated database");
    let store = Arc::new(Store::open(dir.path()).expect("open store"));
    let first = store
        .create_job("assignment-a", "analysis")
        .expect("first job");
    worker(store.clone(), "assignment-a", &first.id).expect("first real analysis");
    let before = store
        .snapshot(&real_analysis().1.revision.id, "assignment-a")
        .expect("first snapshot");
    let second = store
        .create_job("assignment-a", "analysis")
        .expect("second job");
    worker(store.clone(), "assignment-a", &second.id).expect("repeated real analysis");
    for job in [&first, &second] {
        let stored = store.job(&job.id, "assignment-a").expect("completed job");
        assert_eq!(stored.state, "completed");
        assert_eq!(
            stored.revision_id.as_deref(),
            Some(real_analysis().1.revision.id.as_str())
        );
    }
    let after = store
        .snapshot(&real_analysis().1.revision.id, "assignment-a")
        .expect("reused snapshot");
    assert_eq!(
        serde_json::to_value(before.snapshot).unwrap(),
        serde_json::to_value(after.snapshot).unwrap()
    );
    let count: i64 = database(&dir)
        .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn identical_revision_is_isolated_by_assignment() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (sample, snapshot) = real_analysis();
    for assignment in ["assignment-a", "assignment-b"] {
        let job = store.create_job(assignment, "analysis").unwrap();
        store
            .complete_job(&job.id, assignment, &sample.sample_id, snapshot)
            .expect("assignment-scoped revision");
        assert_eq!(store.job(&job.id, assignment).unwrap().state, "completed");
        assert_eq!(
            store
                .snapshot(&snapshot.revision.id, assignment)
                .unwrap()
                .sample_id,
            sample.sample_id
        );
    }
    assert!(store
        .snapshot(&snapshot.revision.id, "assignment-c")
        .is_err());
    let count: i64 = database(&dir)
        .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn unauthorized_completion_rolls_back_snapshot() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (sample, snapshot) = real_analysis();
    let job = store.create_job("assignment-a", "analysis").unwrap();
    assert!(store
        .complete_job(&job.id, "assignment-b", &sample.sample_id, snapshot)
        .is_err());
    assert_eq!(store.job(&job.id, "assignment-a").unwrap().state, "running");
    let count: i64 = database(&dir)
        .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0, "transaction must not leave unauthorized results");
}

#[test]
fn conflicting_stored_result_is_preserved_and_job_fails() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let (sample, snapshot) = real_analysis();
    let first = store.create_job("assignment-a", "analysis").unwrap();
    store
        .complete_job(&first.id, "assignment-a", &sample.sample_id, snapshot)
        .unwrap();
    // Actual SQLite corruption exercises the immutable-result boundary.
    let db = database(&dir);
    db.execute("UPDATE snapshots SET sample_id='corrupted-sample-id'", [])
        .unwrap();
    let second = store.create_job("assignment-a", "analysis").unwrap();
    let error =
        worker(store.clone(), "assignment-a", &second.id).expect_err("conflicting result fails");
    assert!(format!("{error:#}").contains("conflicts with the stored immutable result"));
    let failed = store.job(&second.id, "assignment-a").unwrap();
    assert_eq!(failed.state, "failed");
    assert!(failed
        .error
        .unwrap()
        .contains("conflicts with the stored immutable result"));
    assert_eq!(
        store
            .snapshot(&snapshot.revision.id, "assignment-a")
            .unwrap()
            .sample_id,
        "corrupted-sample-id"
    );
}

#[test]
fn sqlite_insert_failure_marks_real_analysis_failed() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    database(&dir).execute_batch("CREATE TRIGGER reject_result BEFORE INSERT ON snapshots BEGIN SELECT RAISE(ABORT, 'result persistence blocked'); END;").unwrap();
    let job = store.create_job("assignment-a", "analysis").unwrap();
    let error = worker(store.clone(), "assignment-a", &job.id).expect_err("actual SQLite failure");
    assert!(format!("{error:#}").contains("result persistence blocked"));
    let failed = store.job(&job.id, "assignment-a").unwrap();
    assert_eq!(failed.state, "failed");
    assert!(failed.error.unwrap().contains("result persistence blocked"));
    assert!(failed.revision_id.is_none());
}

#[test]
fn original_and_failure_persistence_errors_both_propagate() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    database(&dir).execute_batch("CREATE TRIGGER reject_result BEFORE INSERT ON snapshots BEGIN SELECT RAISE(ABORT, 'result persistence blocked'); END; CREATE TRIGGER reject_failure BEFORE UPDATE ON jobs WHEN NEW.state='failed' BEGIN SELECT RAISE(ABORT, 'failure persistence blocked'); END;").unwrap();
    let job = store.create_job("assignment-a", "analysis").unwrap();
    let error =
        worker(store.clone(), "assignment-a", &job.id).expect_err("two real database failures");
    let detail = format!("{error:#}");
    assert!(detail.contains("result persistence blocked"));
    assert!(detail.contains("failure persistence blocked"));
}

#[test]
fn old_database_migrates_atomically_and_preserves_existing_records() {
    let dir = TempDir::new().unwrap();
    let (sample, snapshot) = real_analysis();
    let db = database(&dir);
    db.execute_batch("CREATE TABLE snapshots(revision_id TEXT PRIMARY KEY, assignment_id TEXT NOT NULL, sample_id TEXT NOT NULL, snapshot_json TEXT NOT NULL, created_at INTEGER NOT NULL);").unwrap();
    db.execute(
        "INSERT INTO snapshots VALUES(?1, 'assignment-a', ?2, ?3, 123)",
        params![
            snapshot.revision.id,
            sample.sample_id,
            serde_json::to_string(snapshot).unwrap()
        ],
    )
    .unwrap();
    drop(db);
    let store = Store::open(dir.path()).expect("migrate baseline database");
    let stored = store
        .snapshot(&snapshot.revision.id, "assignment-a")
        .unwrap();
    assert_eq!(
        serde_json::to_value(stored.snapshot).unwrap(),
        serde_json::to_value(snapshot).unwrap()
    );
    let job = store.create_job("assignment-b", "analysis").unwrap();
    store
        .complete_job(&job.id, "assignment-b", &sample.sample_id, snapshot)
        .expect("same revision in second assignment after migration");
    drop(store);
    let reopened = Store::open(dir.path()).expect("idempotent schema detection");
    assert_eq!(
        reopened.job(&job.id, "assignment-b").unwrap().state,
        "completed"
    );
    let created: i64 = database(&dir)
        .query_row(
            "SELECT created_at FROM snapshots WHERE assignment_id='assignment-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(created, 123);
}

#[test]
fn migration_failure_rolls_back_schema_and_keeps_old_result() {
    let dir = TempDir::new().unwrap();
    let (sample, snapshot) = real_analysis();
    let db = database(&dir);
    db.execute_batch("CREATE TABLE snapshots(revision_id TEXT PRIMARY KEY, assignment_id TEXT NOT NULL, sample_id TEXT NOT NULL, snapshot_json TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE TABLE snapshots_scoped(marker TEXT);").unwrap();
    let text = serde_json::to_string(snapshot).unwrap();
    db.execute(
        "INSERT INTO snapshots VALUES(?1, 'assignment-a', ?2, ?3, 123)",
        params![snapshot.revision.id, sample.sample_id, text],
    )
    .unwrap();
    assert!(Store::open(dir.path()).is_err());
    let stored: String = db
        .query_row("SELECT snapshot_json FROM snapshots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored, text);
    let key: String = db
        .query_row(
            "SELECT name FROM pragma_table_info('snapshots') WHERE pk=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(key, "revision_id");
    let jobs: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='jobs'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(jobs, 0, "failed migration rolls back newly created tables");
}

#[test]
fn real_engine_failure_reaches_failed_job() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let job = store.create_job("assignment-a", "analysis").unwrap();
    let error = complete_analysis(
        store.clone(),
        None,
        "assignment-a".into(),
        job.id.clone(),
        real_analysis().0.clone(),
        AnalysisMode::Full,
    )
    .expect_err("missing reviewed engine is a real analysis failure");
    assert!(format!("{error:#}").contains("requires the reviewed engine bundle"));
    let failed = store.job(&job.id, "assignment-a").unwrap();
    assert_eq!(failed.state, "failed");
    assert!(failed
        .error
        .unwrap()
        .contains("requires the reviewed engine bundle"));
}

#[test]
fn completed_job_cannot_be_rewritten_by_late_failure() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (sample, snapshot) = real_analysis();
    let job = store.create_job("assignment-a", "analysis").unwrap();
    store
        .complete_job(&job.id, "assignment-a", &sample.sample_id, snapshot)
        .unwrap();
    assert!(store
        .fail_job(&job.id, "assignment-a", "late failure")
        .is_err());
    assert_eq!(
        store.job(&job.id, "assignment-a").unwrap().state,
        "completed"
    );
}
