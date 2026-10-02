use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

const HEX_PREFIX: &str = "0x";

/// A binary location with an explicit, non-interchangeable address space.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AddressSpace {
    FileOffset,
    Rva,
    Va,
    RuntimeVa,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BinaryAddress {
    pub sample_sha256: String,
    pub slice: Option<String>,
    pub address_space: AddressSpace,
    pub value: String,
    pub debug_session_id: Option<String>,
    pub module_identity: Option<String>,
    pub load_base: Option<String>,
    pub rva: Option<String>,
}

impl BinaryAddress {
    pub fn static_va(sample_sha256: String, slice: Option<String>, value: u64) -> Self {
        Self {
            sample_sha256,
            slice,
            address_space: AddressSpace::Va,
            value: format_hex_address(value),
            debug_session_id: None,
            module_identity: None,
            load_base: None,
            rva: None,
        }
    }

    pub fn validate_identity(
        &self,
        expected_sha256: &str,
        expected_slice: Option<&str>,
    ) -> Result<()> {
        if self.sample_sha256 != expected_sha256 {
            bail!("binary address sample digest does not match the authorized sample");
        }
        if self.slice.as_deref() != expected_slice {
            bail!("binary address slice does not match the analysis revision");
        }
        Ok(())
    }
}

pub fn parse_hex_address(value: &str) -> Result<u64> {
    let number = value.strip_prefix(HEX_PREFIX).ok_or_else(|| {
        anyhow::anyhow!("binary address must be a 0x-prefixed hexadecimal string")
    })?;
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("binary address must contain only hexadecimal digits");
    }
    u64::from_str_radix(number, 16).map_err(Into::into)
}

pub fn format_hex_address(value: u64) -> String {
    format!("{HEX_PREFIX}{value:x}")
}

#[cfg(test)]
mod tests {
    use super::parse_hex_address;

    #[test]
    fn parses_u64_hex_without_javascript_number_loss() {
        assert_eq!(parse_hex_address("0xffffffffffffffff").unwrap(), u64::MAX);
        assert!(parse_hex_address("18446744073709551615").is_err());
    }
}
