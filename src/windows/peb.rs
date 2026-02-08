use crate::error::Result;
use crate::memory::VirtualMemory;
use crate::windows::offsets::LdrOffsets;

/// A loaded DLL in a process's address space.
#[derive(Debug)]
pub struct LoadedModule {
    pub base: u64,
    pub size: u32,
    pub full_name: String,
    pub base_name: String,
}

/// Walk PEB -> PEB_LDR_DATA -> InLoadOrderModuleList to enumerate loaded DLLs.
pub fn enumerate_modules(
    vmem: &impl VirtualMemory,
    peb_addr: u64,
    ldr_offsets: &LdrOffsets,
) -> Result<Vec<LoadedModule>> {
    let mut modules = Vec::new();

    // PEB.Ldr
    let ldr = vmem.read_virt_u64(peb_addr + ldr_offsets.peb_ldr)?;
    if ldr == 0 {
        return Ok(modules);
    }

    // PEB_LDR_DATA.InLoadOrderModuleList (LIST_ENTRY: Flink, Blink)
    let list_head = ldr + ldr_offsets.ldr_in_load_order;
    let first_flink = vmem.read_virt_u64(list_head)?;
    if first_flink == 0 || first_flink == list_head {
        return Ok(modules);
    }

    let mut current = first_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_head || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        // LDR_DATA_TABLE_ENTRY starts at the LIST_ENTRY (InLoadOrderLinks is at offset 0)
        let entry_base = current;

        let dll_base = match vmem.read_virt_u64(entry_base + ldr_offsets.ldr_entry_dll_base) {
            Ok(b) => b,
            Err(_) => break,
        };

        if dll_base == 0 {
            // Skip sentinel entries
            let next = vmem.read_virt_u64(current)?;
            current = next;
            continue;
        }

        let size = vmem
            .read_virt_u32(entry_base + ldr_offsets.ldr_entry_size_of_image)
            .unwrap_or(0);

        let base_name = vmem
            .read_win_unicode_string(entry_base + ldr_offsets.ldr_entry_base_dll_name)
            .unwrap_or_default();

        let full_name = vmem
            .read_win_unicode_string(entry_base + ldr_offsets.ldr_entry_full_dll_name)
            .unwrap_or_default();

        modules.push(LoadedModule {
            base: dll_base,
            size,
            full_name,
            base_name,
        });

        // Follow Flink to next entry
        let next = match vmem.read_virt_u64(current) {
            Ok(n) => n,
            Err(_) => break,
        };
        current = next;
    }

    Ok(modules)
}
