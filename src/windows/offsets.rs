use crate::error::{GovmemError, Result};

/// EPROCESS field offsets for Windows 10 x64.
#[derive(Debug, Clone, Copy)]
pub struct EprocessOffsets {
    pub directory_table_base: u64,
    pub unique_process_id: u64,
    pub active_process_links: u64,
    pub image_file_name: u64,
    pub peb: u64,
    pub section_base_address: u64,
}

/// PEB / LDR offsets for enumerating loaded DLLs.
#[derive(Debug, Clone, Copy)]
pub struct LdrOffsets {
    pub peb_ldr: u64,
    pub ldr_in_load_order: u64,
    pub ldr_in_memory_order: u64,
    pub ldr_entry_dll_base: u64,
    pub ldr_entry_size_of_image: u64,
    pub ldr_entry_full_dll_name: u64,
    pub ldr_entry_base_dll_name: u64,
}

/// Default EPROCESS offsets for Windows 10 x64 (builds 14393-19045).
/// These are stable across most Windows 10 versions.
pub const WIN10_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    directory_table_base: 0x28,
    unique_process_id: 0x440,
    active_process_links: 0x448,
    image_file_name: 0x5A8,
    peb: 0x550,
    section_base_address: 0x520,
};

/// Default LDR offsets for Windows 10 x64.
pub const WIN10_X64_LDR: LdrOffsets = LdrOffsets {
    peb_ldr: 0x18,
    ldr_in_load_order: 0x10,
    ldr_in_memory_order: 0x20,
    ldr_entry_dll_base: 0x30,
    ldr_entry_size_of_image: 0x40,
    ldr_entry_full_dll_name: 0x48,
    ldr_entry_base_dll_name: 0x58,
};

pub fn offsets_for_build(build: u32) -> Result<EprocessOffsets> {
    match build {
        14393..=22631 => Ok(WIN10_X64_EPROCESS),
        _ => Err(GovmemError::UnsupportedBuild(build)),
    }
}
