use std::{env, fs, path::Path};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use xsec_storage::{db::Database, models::NewBinarySample, repo::ProjectInput, Repository};

// This read-model utility exercises the real Desktop Repository on an isolated
// database. It does not implement Desktop authorization or the MCP transport.
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        bail!("expected command and isolated database path");
    }
    let repo = Repository::new(Database::open(Path::new(&args[2]))?);
    let result = match args[1].as_str() {
        "seed" => {
            let inputs: Value = serde_json::from_slice(&fs::read(args.get(3).context("missing seed input")?)?)?;
            let mut projects = Vec::new();
            for input in inputs.as_array().context("seed input must be an array")? {
                let name = input["name"].as_str().context("seed project name is missing")?;
                let project = repo.create_project(&ProjectInput {
                    name: name.into(), code: name.into(), client_name: None,
                    description: Some("isolated browser lifecycle input".into()),
                    prompt: None, folder_path: None,
                    status: serde_json::from_value(json!("active"))?, start_at: None, end_at: None,
                })?;
                let mut sample: NewBinarySample = serde_json::from_value(input["sample"].clone())?;
                sample.project_id = project.id.clone();
                let inserted = repo.insert_binary_sample(&sample)?;
                projects.push(json!({"name":name,"projectId":project.id,"sampleId":inserted.id,
                    "sampleSha256":inserted.sample_sha256}));
            }
            json!({"projects":projects})
        }
        "samples" => {
            let project = args.get(3).context("missing project id")?;
            let offset: i64 = args.get(4).context("missing cursor")?.parse()?;
            let limit: i64 = args.get(5).context("missing limit")?.parse()?;
            if offset < 0 || !(1..=50).contains(&limit) { bail!("invalid sample page"); }
            let rows = repo.list_binary_samples(project, offset, limit)?;
            let next = if rows.len() == limit as usize { Some((offset + limit).to_string()) } else { None };
            let items: Vec<Value> = rows.into_iter().map(|sample| json!({
                "sampleId":sample.id,"sampleSha256":sample.sample_sha256,"format":sample.format,
                "architecture":sample.architecture,"slice":sample.slice,"sizeBytes":sample.size_bytes,
                "importedAt":sample.imported_at,
            })).collect();
            json!({"items":items,"nextCursor":next,"truncated":next.is_some()})
        }
        "make-unavailable" => {
            repo.db.with_conn(|db| db.execute_batch("ALTER TABLE binary_samples RENAME TO lifecycle_unavailable_samples"))?;
            json!({"unavailable":true})
        }
        "restore" => {
            repo.db.with_conn(|db| db.execute_batch("ALTER TABLE lifecycle_unavailable_samples RENAME TO binary_samples"))?;
            json!({"restored":true})
        }
        _ => bail!("unknown read-model operation"),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
