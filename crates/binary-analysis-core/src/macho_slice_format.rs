use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use anyhow::{bail, Context, Result};

const MAX_FAT_ARCHITECTURES: u32 = 128;
const SLICE_ID_PREFIX: &str = "fat-macho-v1";
const FAT_MAGIC_OFFSET: u64 = 0;
const FAT_ARCH_COUNT_OFFSET: u64 = 4;
const FAT_HEADER_SIZE: u64 = 8;
const FAT32_ARCH_SIZE: u64 = 20;
const FAT64_ARCH_SIZE: u64 = 32;
const CPU_TYPE_OFFSET: u64 = 0;
const CPU_SUBTYPE_OFFSET: u64 = 4;
const FAT32_SLICE_OFFSET_FIELD: u64 = 8;
const FAT32_SLICE_SIZE_FIELD: u64 = 12;
const FAT32_ALIGNMENT_FIELD: u64 = 16;
const FAT64_SLICE_OFFSET_FIELD: u64 = 8;
const FAT64_SLICE_SIZE_FIELD: u64 = 16;
const FAT64_ALIGNMENT_FIELD: u64 = 24;
const FAT64_RESERVED_FIELD: u64 = 28;
const MACHO_MAGIC_SIZE: usize = 4;
const MACHO_HEADER32_SIZE: usize = 28;
const MACHO_HEADER64_SIZE: usize = 32;
const MACHO_CPU_TYPE_START: usize = 4;
const MACHO_CPU_TYPE_END: usize = 8;
const MACHO_CPU_SUBTYPE_START: usize = 8;
const MACHO_CPU_SUBTYPE_END: usize = 12;
const CPU_SUBTYPE_BASE_MASK: u32 = 0x00ff_ffff;
const MAX_ALIGNMENT_EXPONENT: u32 = 64;
const U32_FIELD_SIZE: usize = 4;
const U64_FIELD_SIZE: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FatSlice {
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub offset: u64,
    pub size: u64,
    pub alignment: u32,
}

impl FatSlice {
    pub(super) fn identity(self) -> String {
        format!(
            "{SLICE_ID_PREFIX}:{:08x}:{:08x}:{:x}:{:x}:{:x}",
            self.cpu_type, self.cpu_subtype, self.offset, self.size, self.alignment
        )
    }
}

pub(super) fn parse_slice_table(file: &mut File, file_size: u64) -> Result<Vec<FatSlice>> {
    let magic = read_at(file, FAT_MAGIC_OFFSET, MACHO_MAGIC_SIZE)?;
    let (little_endian, is_64) = fat_encoding(&magic)?;
    let count = u64::from(read_u32(file, FAT_ARCH_COUNT_OFFSET, little_endian)?);
    if count == 0 || count > u64::from(MAX_FAT_ARCHITECTURES) {
        bail!("Fat Mach-O architecture count is outside the supported range");
    }
    let entry_size = if is_64 {
        FAT64_ARCH_SIZE
    } else {
        FAT32_ARCH_SIZE
    };
    let table_end = FAT_HEADER_SIZE
        .checked_add(
            count
                .checked_mul(entry_size)
                .context("Fat Mach-O table overflows")?,
        )
        .context("Fat Mach-O table overflows")?;
    if table_end > file_size {
        bail!("Fat Mach-O architecture table exceeds the file");
    }
    let mut slices = Vec::with_capacity(count as usize);
    for index in 0..count {
        let slice = read_slice_entry(
            file,
            FAT_HEADER_SIZE + index * entry_size,
            little_endian,
            is_64,
        )?;
        validate_slice(file, file_size, table_end, slice)?;
        slices.push(slice);
    }
    reject_overlapping_slices(&mut slices)?;
    Ok(slices)
}

fn read_slice_entry(
    file: &mut File,
    entry_offset: u64,
    little_endian: bool,
    is_64: bool,
) -> Result<FatSlice> {
    let cpu_type = read_u32(file, entry_offset + CPU_TYPE_OFFSET, little_endian)?;
    let cpu_subtype = read_u32(file, entry_offset + CPU_SUBTYPE_OFFSET, little_endian)?;
    let (offset, size, alignment) = if is_64 {
        let offset = read_u64(file, entry_offset + FAT64_SLICE_OFFSET_FIELD, little_endian)?;
        let size = read_u64(file, entry_offset + FAT64_SLICE_SIZE_FIELD, little_endian)?;
        let alignment = read_u32(file, entry_offset + FAT64_ALIGNMENT_FIELD, little_endian)?;
        if read_u32(file, entry_offset + FAT64_RESERVED_FIELD, little_endian)? != 0 {
            bail!("Fat Mach-O 64-bit slice reserved field is nonzero");
        }
        (offset, size, alignment)
    } else {
        (
            u64::from(read_u32(
                file,
                entry_offset + FAT32_SLICE_OFFSET_FIELD,
                little_endian,
            )?),
            u64::from(read_u32(
                file,
                entry_offset + FAT32_SLICE_SIZE_FIELD,
                little_endian,
            )?),
            read_u32(file, entry_offset + FAT32_ALIGNMENT_FIELD, little_endian)?,
        )
    };
    Ok(FatSlice {
        cpu_type,
        cpu_subtype,
        offset,
        size,
        alignment,
    })
}

fn validate_slice(file: &mut File, file_size: u64, table_end: u64, slice: FatSlice) -> Result<()> {
    let end = slice
        .offset
        .checked_add(slice.size)
        .context("Fat Mach-O slice range overflows")?;
    if slice.size < MACHO_HEADER32_SIZE as u64 || slice.offset < table_end || end > file_size {
        bail!("Fat Mach-O slice range is invalid");
    }
    if slice.alignment >= MAX_ALIGNMENT_EXPONENT || slice.offset % (1_u64 << slice.alignment) != 0 {
        bail!("Fat Mach-O slice alignment is invalid");
    }
    let header_length = if slice.size >= MACHO_HEADER64_SIZE as u64 {
        MACHO_HEADER64_SIZE
    } else {
        MACHO_HEADER32_SIZE
    };
    let header = read_at(file, slice.offset, header_length)?;
    let (little_endian, is_64) = thin_encoding(&header)?;
    if is_64 && slice.size < MACHO_HEADER64_SIZE as u64 {
        bail!("Fat Mach-O 64-bit slice header is truncated");
    }
    let cpu_type = endian_u32(
        &header[MACHO_CPU_TYPE_START..MACHO_CPU_TYPE_END],
        little_endian,
    )?;
    let cpu_subtype = endian_u32(
        &header[MACHO_CPU_SUBTYPE_START..MACHO_CPU_SUBTYPE_END],
        little_endian,
    )?;
    if cpu_type != slice.cpu_type
        || cpu_subtype & CPU_SUBTYPE_BASE_MASK != slice.cpu_subtype & CPU_SUBTYPE_BASE_MASK
    {
        bail!("Fat Mach-O slice architecture does not match its table entry");
    }
    Ok(())
}

fn reject_overlapping_slices(slices: &mut [FatSlice]) -> Result<()> {
    slices.sort_by_key(|slice| slice.offset);
    for pair in slices.windows(2) {
        let previous_end = pair[0]
            .offset
            .checked_add(pair[0].size)
            .context("Fat Mach-O slice range overflows")?;
        if previous_end > pair[1].offset {
            bail!("Fat Mach-O slices overlap");
        }
    }
    Ok(())
}

fn fat_encoding(magic: &[u8]) -> Result<(bool, bool)> {
    match magic {
        [0xca, 0xfe, 0xba, 0xbe] => Ok((false, false)),
        [0xbe, 0xba, 0xfe, 0xca] => Ok((true, false)),
        [0xca, 0xfe, 0xba, 0xbf] => Ok((false, true)),
        [0xbf, 0xba, 0xfe, 0xca] => Ok((true, true)),
        _ => anyhow::bail!("sample is not a supported Fat Mach-O container"),
    }
}

fn thin_encoding(header: &[u8]) -> Result<(bool, bool)> {
    match header.get(..MACHO_MAGIC_SIZE) {
        Some([0xfe, 0xed, 0xfa, 0xcf]) => Ok((false, true)),
        Some([0xcf, 0xfa, 0xed, 0xfe]) => Ok((true, true)),
        Some([0xfe, 0xed, 0xfa, 0xce]) => Ok((false, false)),
        Some([0xce, 0xfa, 0xed, 0xfe]) => Ok((true, false)),
        _ => anyhow::bail!("Fat Mach-O slice does not contain a Mach-O image"),
    }
}

fn read_u32(file: &mut File, offset: u64, little_endian: bool) -> Result<u32> {
    endian_u32(&read_at(file, offset, U32_FIELD_SIZE)?, little_endian)
}

fn read_u64(file: &mut File, offset: u64, little_endian: bool) -> Result<u64> {
    let bytes: [u8; U64_FIELD_SIZE] = read_at(file, offset, U64_FIELD_SIZE)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid 64-bit Fat Mach-O field"))?;
    Ok(if little_endian {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn endian_u32(bytes: &[u8], little_endian: bool) -> Result<u32> {
    let value: [u8; U32_FIELD_SIZE] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid 32-bit Fat Mach-O field"))?;
    Ok(if little_endian {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    })
}

fn read_at(file: &mut File, offset: u64, length: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))
        .context("seek Fat Mach-O sample")?;
    let mut bytes = vec![0_u8; length];
    file.read_exact(&mut bytes)
        .context("read Fat Mach-O sample")?;
    Ok(bytes)
}
