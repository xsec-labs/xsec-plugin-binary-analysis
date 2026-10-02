use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::macho_slice_format::{parse_slice_table, FatSlice};
use crate::ManagedSample;

const COPY_BUFFER_BYTES: usize = 1024 * 1024;

pub fn prepare_sample_for_analysis(
    sample: &ManagedSample,
    cache_root: &Path,
) -> Result<ManagedSample> {
    if sample.format == "macho-fat" && sample.slice.is_none() {
        bail!("select a Fat Mach-O architecture slice before analysis");
    }
    let Some(identity) = sample.slice.as_deref() else {
        return Ok(sample.clone());
    };
    if sample.format != "macho" {
        bail!("only selected Mach-O slices can be materialized for analysis");
    }
    let mut source = open_verified_container(sample)?;
    let size = source.metadata()?.len();
    let slice = find_selected_slice(&mut source, size, identity)?;
    let destination = cache_path(cache_root, sample, identity);
    let created = materialize_slice(&mut source, slice, &destination)?;
    if created {
        eprintln!(
            "binary_analysis.slice_cache.ready architecture={} bytes={}",
            sample.architecture.as_deref().unwrap_or("unknown"),
            slice.size
        );
    }
    let mut prepared = sample.clone();
    prepared.managed_path = destination;
    Ok(prepared)
}

fn open_verified_container(sample: &ManagedSample) -> Result<File> {
    let metadata =
        fs::symlink_metadata(&sample.managed_path).context("read managed Fat Mach-O metadata")?;
    if !metadata.file_type().is_file() {
        bail!("managed Fat Mach-O sample is not a regular file");
    }
    let mut file = File::open(&sample.managed_path).context("open managed Fat Mach-O sample")?;
    let digest = hash_reader(&mut file)?;
    if hex::encode(digest) != sample.sample_sha256 {
        bail!("managed Fat Mach-O sample digest changed");
    }
    Ok(file)
}

fn find_selected_slice(file: &mut File, size: u64, identity: &str) -> Result<FatSlice> {
    let slices = parse_slice_table(file, size)?;
    slices
        .into_iter()
        .find(|slice| slice.identity() == identity)
        .context("selected Fat Mach-O slice is absent from the managed sample")
}

fn cache_path(root: &Path, sample: &ManagedSample, identity: &str) -> PathBuf {
    let key = hex::encode(Sha256::digest(identity.as_bytes()));
    root.join(&sample.sample_sha256)
        .join(format!("{key}.macho"))
}

fn materialize_slice(file: &mut File, slice: FatSlice, destination: &Path) -> Result<bool> {
    let expected_digest = hash_range(file, slice.offset, slice.size)?;
    if destination.exists() {
        verify_cached_slice(destination, slice.size, &expected_digest)?;
        return Ok(false);
    }
    let parent = destination
        .parent()
        .context("Mach-O cache path has no parent")?;
    fs::create_dir_all(parent).context("create PLUGIN_DATA Mach-O slice cache")?;
    let staging = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let result = copy_slice(file, slice, &staging, destination, &expected_digest);
    let cleanup = fs::remove_file(&staging);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(true),
        (Ok(()), Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error).context("remove Mach-O slice staging file"),
    }
}

fn copy_slice(
    source: &mut File,
    slice: FatSlice,
    staging: &Path,
    destination: &Path,
    expected_digest: &[u8],
) -> Result<()> {
    source.seek(SeekFrom::Start(slice.offset))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staging)
        .context("create Mach-O slice cache staging file")?;
    let mut hasher = Sha256::new();
    let mut remaining = slice.size;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))?;
        source.read_exact(&mut buffer[..limit])?;
        hasher.update(&buffer[..limit]);
        output.write_all(&buffer[..limit])?;
        remaining -= limit as u64;
    }
    output.sync_all().context("sync Mach-O slice cache")?;
    if hasher.finalize().as_slice() != expected_digest {
        bail!("Fat Mach-O sample changed while its selected slice was copied");
    }
    match fs::hard_link(staging, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_cached_slice(destination, slice.size, expected_digest)
        }
        Err(error) => Err(error).context("install Mach-O slice cache entry"),
    }
}

fn verify_cached_slice(path: &Path, size: u64, expected_digest: &[u8]) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("read cached Mach-O slice metadata")?;
    if !metadata.file_type().is_file() || metadata.len() != size {
        bail!("cached Mach-O slice has an invalid file identity");
    }
    let mut file = File::open(path).context("open cached Mach-O slice")?;
    if hash_reader(&mut file)?.as_slice() != expected_digest {
        bail!("cached Mach-O slice digest does not match the container");
    }
    Ok(())
}

fn hash_reader(reader: &mut File) -> Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_vec())
}

fn hash_range(file: &mut File, offset: u64, size: u64) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut remaining = size;
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))?;
        file.read_exact(&mut buffer[..limit])?;
        hasher.update(&buffer[..limit]);
        remaining -= limit as u64;
    }
    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
#[path = "macho_slice_tests.rs"]
mod tests;
