#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::io::Write;
use std::path::Path;

#[cfg(target_os = "macos")]
use object::read::File as ObjectFile;
#[cfg(target_os = "macos")]
use object::read::ReadCache;
#[cfg(target_os = "macos")]
use sha2::Digest;

use crate::macho_slice::prepare_sample_for_analysis;
use crate::ManagedSample;

#[test]
fn requires_an_explicit_architecture_slice_for_fat_macho() {
    let sample = ManagedSample {
        sample_id: "fat-container".into(),
        sample_sha256: "a".repeat(64),
        format: "macho-fat".into(),
        architecture: None,
        slice: None,
        managed_path: Path::new("unresolved-fat-container").into(),
    };
    assert!(prepare_sample_for_analysis(&sample, Path::new("plugin-data")).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn extracts_a_real_host_macho_image_from_a_fat_container() {
    let executable = std::env::current_exe().expect("resolve running Mach-O test executable");
    let thin = std::fs::read(&executable).expect("read running Mach-O test executable");
    let (cpu_type, cpu_subtype, alignment) = thin_architecture(&thin);
    let offset = 4096_usize;
    let mut fat = vec![0_u8; offset];
    fat[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    fat[4..8].copy_from_slice(&1_u32.to_be_bytes());
    fat[8..12].copy_from_slice(&cpu_type.to_be_bytes());
    fat[12..16].copy_from_slice(&cpu_subtype.to_be_bytes());
    fat[16..20].copy_from_slice(&(offset as u32).to_be_bytes());
    fat[20..24].copy_from_slice(&(thin.len() as u32).to_be_bytes());
    fat[24..28].copy_from_slice(&alignment.to_be_bytes());
    fat.extend_from_slice(&thin);
    let directory = tempfile::tempdir().expect("create real Fat Mach-O test directory");
    let container = directory.path().join("universal-test-image");
    File::create(&container)
        .expect("create Fat Mach-O test image")
        .write_all(&fat)
        .expect("write Fat Mach-O test image");
    let digest = hex::encode(sha2::Sha256::digest(&fat));
    let sample = ManagedSample {
        sample_id: "host-test-macho-slice".into(),
        sample_sha256: digest,
        format: "macho".into(),
        architecture: Some(if cfg!(target_arch = "aarch64") {
            "arm64".into()
        } else {
            "x86_64".into()
        }),
        slice: Some(format!(
            "fat-macho-v1:{cpu_type:08x}:{cpu_subtype:08x}:{offset:x}:{:x}:{alignment:x}",
            thin.len()
        )),
        managed_path: container,
    };
    let prepared = prepare_sample_for_analysis(&sample, &directory.path().join("plugin-data"))
        .expect("extract selected thin image");
    assert_ne!(prepared.managed_path, sample.managed_path);
    let reader = ReadCache::new(File::open(prepared.managed_path).expect("open cached slice"));
    ObjectFile::parse(&reader).expect("parse extracted real Mach-O image");
}

#[cfg(target_os = "macos")]
#[test]
fn extracts_every_slice_from_a_real_universal_system_binary() {
    let container = Path::new("/usr/bin/true");
    let mut file = File::open(container).expect("open universal system binary");
    let container_size = file
        .metadata()
        .expect("read universal binary metadata")
        .len();
    let slices = crate::macho_slice_format::parse_slice_table(&mut file, container_size)
        .expect("parse universal system binary slices");
    let container_bytes = std::fs::read(container).expect("read universal system binary");
    let sample_sha256 = hex::encode(sha2::Sha256::digest(&container_bytes));
    let directory = tempfile::tempdir().expect("create real universal slice cache");
    assert!(slices.len() >= 2);

    for (index, slice) in slices.iter().enumerate() {
        let sample = ManagedSample {
            sample_id: format!("universal-system-slice-{index}"),
            sample_sha256: sample_sha256.clone(),
            format: "macho".into(),
            architecture: None,
            slice: Some(slice.identity()),
            managed_path: container.into(),
        };
        let prepared = prepare_sample_for_analysis(&sample, &directory.path().join("plugin-data"))
            .expect("materialize selected universal slice");
        assert_eq!(
            std::fs::metadata(&prepared.managed_path)
                .expect("read materialized slice metadata")
                .len(),
            slice.size
        );
        let reader = ReadCache::new(File::open(prepared.managed_path).expect("open cached slice"));
        ObjectFile::parse(&reader).expect("parse materialized universal slice");
    }
}

#[cfg(target_os = "macos")]
fn thin_architecture(bytes: &[u8]) -> (u32, u32, u32) {
    let little_endian = matches!(bytes.get(..4), Some([0xcf, 0xfa, 0xed, 0xfe]));
    let read = |range: std::ops::Range<usize>| {
        let value: [u8; 4] = bytes[range].try_into().expect("Mach-O architecture field");
        if little_endian {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        }
    };
    (read(4..8), read(8..12), 12)
}
