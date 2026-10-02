use std::fs::File;

use anyhow::{bail, Context, Result};
use object::read::{Object, ObjectSegment, ReadCache};
use object::BinaryFormat;

use crate::{parse_hex_address, AddressSpace, BinaryAddress, ManagedSample};

#[derive(Clone, Copy)]
struct LoadSegment {
    file_offset: u64,
    file_size: u64,
    virtual_address: u64,
    memory_size: u64,
}

struct AddressMap {
    image_base: u64,
    segments: Vec<LoadSegment>,
}

pub fn resolve_static_address(sample: &ManagedSample, address: &BinaryAddress) -> Result<u64> {
    address.validate_identity(&sample.sample_sha256, sample.slice.as_deref())?;
    let value = parse_hex_address(&address.value)?;
    match address.address_space {
        AddressSpace::Va => Ok(value),
        AddressSpace::FileOffset => AddressMap::open(sample)?.file_offset_to_va(value),
        AddressSpace::Rva => AddressMap::open(sample)?.rva_to_va(value),
        AddressSpace::RuntimeVa => bail!("runtime VA requires an authorized debugger context"),
    }
}

impl AddressMap {
    fn open(sample: &ManagedSample) -> Result<Self> {
        let reader = ReadCache::new(
            File::open(&sample.managed_path).context("open managed sample for address mapping")?,
        );
        let file = object::read::File::parse(&reader).context("parse managed object segments")?;
        require_sample_format(sample, file.format())?;
        let segments = file
            .segments()
            .map(|segment| {
                let (file_offset, file_size) = segment.file_range();
                LoadSegment {
                    file_offset,
                    file_size,
                    virtual_address: segment.address(),
                    memory_size: segment.size(),
                }
            })
            .filter(|segment| segment.memory_size > 0)
            .collect::<Vec<_>>();
        let image_base = image_base(file.format(), file.relative_address_base(), &segments)?;
        Ok(Self {
            image_base,
            segments,
        })
    }

    fn file_offset_to_va(&self, file_offset: u64) -> Result<u64> {
        let matches = self
            .segments
            .iter()
            .filter_map(|segment| {
                let delta = file_offset.checked_sub(segment.file_offset)?;
                (delta < segment.file_size.min(segment.memory_size))
                    .then(|| segment.virtual_address.checked_add(delta))
                    .flatten()
            })
            .collect::<Vec<_>>();
        unique_address(
            matches,
            "file offset is not uniquely mapped to a load segment",
        )
    }

    fn rva_to_va(&self, rva: u64) -> Result<u64> {
        let address = self
            .image_base
            .checked_add(rva)
            .context("RVA overflows the virtual address range")?;
        if !self
            .segments
            .iter()
            .any(|segment| contains_va(*segment, address))
        {
            bail!("RVA does not map to a loadable segment");
        }
        Ok(address)
    }
}

fn image_base(format: BinaryFormat, relative_base: u64, segments: &[LoadSegment]) -> Result<u64> {
    if format == BinaryFormat::Pe {
        return Ok(relative_base);
    }
    segments
        .iter()
        .filter(|segment| segment.file_size > 0)
        .map(|segment| segment.virtual_address)
        .min()
        .context("object file has no file-backed load segment")
}

fn require_sample_format(sample: &ManagedSample, format: BinaryFormat) -> Result<()> {
    let matches = matches!(
        (sample.format.as_str(), format),
        ("pe", BinaryFormat::Pe) | ("elf", BinaryFormat::Elf) | ("macho", BinaryFormat::MachO)
    );
    if !matches {
        bail!("sample format does not match the parsed address map");
    }
    Ok(())
}

fn contains_va(segment: LoadSegment, address: u64) -> bool {
    address
        .checked_sub(segment.virtual_address)
        .is_some_and(|offset| offset < segment.memory_size)
}

fn unique_address(matches: Vec<u64>, message: &str) -> Result<u64> {
    match matches.as_slice() {
        [address] => Ok(*address),
        [] => bail!("{message}"),
        _ => bail!("{message}"),
    }
}

#[cfg(test)]
mod tests {
    use super::AddressMap;
    use crate::{resolve_static_address, AddressSpace, BinaryAddress, ManagedSample};

    #[test]
    fn resolves_file_offsets_and_rvas_on_the_real_test_executable() {
        let sample = current_executable_sample();
        let map = AddressMap::open(&sample).expect("parse real test executable");
        let segment = map
            .segments
            .iter()
            .find(|segment| segment.file_size > 8)
            .expect("test executable has a file-backed load segment");
        let file_offset = segment.file_offset + 1;
        let virtual_address = segment.virtual_address + 1;
        let rva = virtual_address - map.image_base;
        assert_eq!(
            resolve(&sample, AddressSpace::FileOffset, file_offset),
            virtual_address
        );
        assert_eq!(resolve(&sample, AddressSpace::Rva, rva), virtual_address);
    }

    #[test]
    fn rejects_rvas_outside_loadable_memory_and_runtime_addresses() {
        let sample = current_executable_sample();
        let invalid = address(&sample, AddressSpace::Rva, u64::MAX);
        assert!(resolve_static_address(&sample, &invalid).is_err());
        let runtime = address(&sample, AddressSpace::RuntimeVa, 0x1000);
        assert!(resolve_static_address(&sample, &runtime).is_err());
    }

    #[test]
    fn rejects_addresses_from_other_samples_and_slices() {
        let sample = current_executable_sample();
        let mut wrong_sample = address(&sample, AddressSpace::Va, 0x1000);
        wrong_sample.sample_sha256 = "b".repeat(64);
        assert!(resolve_static_address(&sample, &wrong_sample).is_err());
        let mut wrong_slice = address(&sample, AddressSpace::Va, 0x1000);
        wrong_slice.slice = Some("other-architecture".into());
        assert!(resolve_static_address(&sample, &wrong_slice).is_err());
    }

    fn resolve(sample: &ManagedSample, space: AddressSpace, value: u64) -> u64 {
        resolve_static_address(sample, &address(sample, space, value)).expect("resolve address")
    }

    fn address(sample: &ManagedSample, space: AddressSpace, value: u64) -> BinaryAddress {
        BinaryAddress {
            sample_sha256: sample.sample_sha256.clone(),
            slice: sample.slice.clone(),
            address_space: space,
            value: format!("0x{value:x}"),
            debug_session_id: None,
            module_identity: None,
            load_base: None,
            rva: None,
        }
    }

    fn current_executable_sample() -> ManagedSample {
        let format = if cfg!(target_os = "windows") {
            "pe"
        } else if cfg!(target_os = "macos") {
            "macho"
        } else {
            "elf"
        };
        ManagedSample {
            sample_id: "real-test-executable".into(),
            sample_sha256: "a".repeat(64),
            format: format.into(),
            architecture: None,
            slice: None,
            managed_path: std::env::current_exe().expect("current executable"),
        }
    }
}
