use crate::error::{GovmemError, Result};

pub const HEADER_SIZE: usize = 12;
pub const GROUP_SIZE: usize = 80;
pub const PAGE_SIZE: usize = 0x1000;

pub const VALID_MAGICS: [u32; 4] = [0xbed2bed0, 0xbad1bad1, 0xbed2bed2, 0xbed3bed3];

#[derive(Debug)]
pub struct VmsnHeader {
    pub magic: u32,
    pub reserved: u32,
    pub group_count: u32,
}

#[derive(Debug)]
pub struct VmsnGroup {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

impl VmsnHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(GovmemError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "VMSN header too short",
            )));
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if !VALID_MAGICS.contains(&magic) {
            return Err(GovmemError::InvalidMagic(magic));
        }
        let reserved = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let group_count = u32::from_le_bytes(data[8..12].try_into().unwrap());
        Ok(Self {
            magic,
            reserved,
            group_count,
        })
    }
}

impl VmsnGroup {
    pub fn parse(data: &[u8]) -> Self {
        let name_bytes = &data[..64];
        let name = name_bytes
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect::<Vec<u8>>();
        let name = String::from_utf8_lossy(&name).to_string();
        let offset = u64::from_le_bytes(data[64..72].try_into().unwrap());
        let size = u64::from_le_bytes(data[72..80].try_into().unwrap());
        Self { name, offset, size }
    }
}

/// Parse all groups from a VMSN file.
pub fn parse_vmsn(data: &[u8]) -> Result<(VmsnHeader, Vec<VmsnGroup>)> {
    let header = VmsnHeader::parse(data)?;
    let mut groups = Vec::with_capacity(header.group_count as usize);
    for i in 0..header.group_count as usize {
        let start = HEADER_SIZE + i * GROUP_SIZE;
        let end = start + GROUP_SIZE;
        if end > data.len() {
            break;
        }
        groups.push(VmsnGroup::parse(&data[start..end]));
    }
    Ok((header, groups))
}
