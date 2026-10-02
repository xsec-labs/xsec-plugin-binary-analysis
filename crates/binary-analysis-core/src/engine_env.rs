use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

#[cfg(target_os = "windows")]
const LIBRARY_PATH_VARIABLE: &str = "PATH";
#[cfg(target_os = "macos")]
const LIBRARY_PATH_VARIABLE: &str = "DYLD_LIBRARY_PATH";
#[cfg(all(unix, not(target_os = "macos")))]
const LIBRARY_PATH_VARIABLE: &str = "LD_LIBRARY_PATH";

pub(crate) fn set_engine_library_search_path(
    command: &mut Command,
    engine_prefix: &Path,
    plugin_dir: &Path,
) -> Result<()> {
    let search_paths = [
        engine_prefix.join("bin"),
        engine_prefix.join("lib"),
        plugin_dir.to_path_buf(),
    ];
    let joined = std::env::join_paths(search_paths)
        .context("assemble reviewed engine library search path")?;
    command.env(LIBRARY_PATH_VARIABLE, joined);
    Ok(())
}
