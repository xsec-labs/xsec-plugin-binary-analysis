use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::BinaryAddress;

pub const DEFAULT_PAGE_SIZE: usize = 50;
pub const MAX_PAGE_SIZE: usize = 200;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisMode {
    Full,
    Fast,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedSample {
    pub sample_id: String,
    pub sample_sha256: String,
    pub format: String,
    pub architecture: Option<String>,
    pub slice: Option<String>,
    /// This location is a Host-created, content-addressed, read-only sample
    /// copy. It is never supplied by an MCP caller.
    pub managed_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRevision {
    pub id: String,
    pub sample_sha256: String,
    pub slice: Option<String>,
    pub mode: AnalysisMode,
    pub engine_version: String,
    pub config_sha256: String,
    pub coverage: Coverage,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub state: String,
    pub indexed: bool,
    pub truncated: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisSnapshot {
    pub revision: AnalysisRevision,
    pub summary: Value,
    pub functions: Vec<Value>,
    pub strings: Vec<Value>,
    pub imports: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum Query {
    Disassemble {
        address: BinaryAddress,
        count: Option<usize>,
    },
    Cfg {
        address: BinaryAddress,
    },
    References {
        address: BinaryAddress,
        direction: ReferenceDirection,
    },
    Decompile {
        address: BinaryAddress,
    },
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReferenceDirection {
    To,
    From,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResult {
    pub item: Value,
    pub coverage: Coverage,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Page {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

impl Page {
    pub fn normalized(&self) -> Result<(usize, usize)> {
        let offset = self
            .cursor
            .as_deref()
            .map(str::parse::<usize>)
            .transpose()
            .map_err(|_| anyhow::anyhow!("binary page cursor is invalid"))?
            .unwrap_or(0);
        let limit = self.limit.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            anyhow::bail!("binary page limit must be between 1 and {MAX_PAGE_SIZE}");
        }
        Ok((offset, limit))
    }
}

#[cfg(test)]
mod tests {
    use super::Page;

    #[test]
    fn rejects_invalid_cursors_and_out_of_range_limits() {
        assert!(Page {
            cursor: Some("broken".into()),
            limit: Some(50),
        }
        .normalized()
        .is_err());
        assert!(Page {
            cursor: None,
            limit: Some(0),
        }
        .normalized()
        .is_err());
        assert_eq!(
            Page {
                cursor: Some("12".into()),
                limit: Some(25),
            }
            .normalized()
            .expect("valid page"),
            (12, 25)
        );
    }
}
