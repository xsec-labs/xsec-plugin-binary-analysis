use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::task;
use xsec_binary_analysis_core::{analyze, AnalysisMode, EngineBundle, ManagedSample};

use crate::host::HostContext;
use crate::store::{JobRecord, Store};

const MAX_ACTIVE_ANALYSIS_WORKERS: usize = 2;

#[derive(Clone)]
pub struct JobCoordinator {
    store: Arc<Store>,
    bundle: Option<EngineBundle>,
    worker_slots: Arc<Semaphore>,
}

impl JobCoordinator {
    pub fn new(store: Arc<Store>, bundle: Option<EngineBundle>) -> Self {
        Self {
            store,
            bundle,
            worker_slots: Arc::new(Semaphore::new(MAX_ACTIVE_ANALYSIS_WORKERS)),
        }
    }

    pub fn engine_bundle(&self) -> Option<&EngineBundle> {
        self.bundle.as_ref()
    }

    pub fn start_analysis(
        &self,
        context: HostContext,
        sample: ManagedSample,
        mode: AnalysisMode,
    ) -> Result<JobRecord> {
        let permit = self
            .worker_slots
            .clone()
            .try_acquire_owned()
            .context("both binary analysis workers are busy")?;
        let job = self.store.create_job(&context.assignment_id, "analysis")?;
        let store = self.store.clone();
        let bundle = self.bundle.clone();
        let assignment_id = context.assignment_id;
        let job_id = job.id.clone();
        task::spawn_blocking(move || {
            let _permit = permit;
            if let Err(error) =
                complete_analysis(store, bundle, assignment_id, job_id, sample, mode)
            {
                eprintln!("binary analysis worker failed: {error:#}");
            }
        });
        Ok(job)
    }
}

fn complete_analysis(
    store: Arc<Store>,
    bundle: Option<EngineBundle>,
    assignment_id: String,
    job_id: String,
    sample: ManagedSample,
    mode: AnalysisMode,
) -> Result<()> {
    match analyze(&sample, mode, bundle.as_ref()) {
        Ok(snapshot) => store
            .complete_job(&job_id, &assignment_id, &sample.sample_id, &snapshot)
            .map(|_| ()),
        Err(error) => {
            let detail = format!("{error:#}");
            store
                .fail_job(&job_id, &assignment_id, &detail)
                .map_err(|failure| {
                    anyhow::anyhow!("{detail}; failed to persist job failure: {failure:#}")
                })
        }
    }
}
