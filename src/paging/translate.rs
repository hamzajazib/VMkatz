use crate::error::{GovmemError, Result};
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::entry::PageTableEntry;

/// 4-level x86-64 page table walker.
pub struct PageTableWalker<'a, P: PhysicalMemory> {
    phys: &'a P,
}

impl<'a, P: PhysicalMemory> PageTableWalker<'a, P> {
    pub fn new(phys: &'a P) -> Self {
        Self { phys }
    }

    /// Translate a virtual address to a physical address using the given CR3 (DTB).
    pub fn translate(&self, cr3: u64, vaddr: u64) -> Result<u64> {
        let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

        // PML4: bits [47:39]
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = PageTableEntry(self.phys.read_phys_u64(pml4_base + pml4_idx * 8)?);
        if !pml4e.is_present() {
            return Err(GovmemError::PageFault(vaddr, "PML4"));
        }

        // PDPT: bits [38:30]
        let pdpt_base = pml4e.frame_addr();
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = PageTableEntry(self.phys.read_phys_u64(pdpt_base + pdpt_idx * 8)?);
        if !pdpte.is_present() {
            return Err(GovmemError::PageFault(vaddr, "PDPT"));
        }
        if pdpte.is_large_page() {
            // 1GB huge page
            let phys = (pdpte.raw() & 0x000F_FFFF_C000_0000) | (vaddr & 0x3FFF_FFFF);
            return Ok(phys);
        }

        // PD: bits [29:21]
        let pd_base = pdpte.frame_addr();
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = PageTableEntry(self.phys.read_phys_u64(pd_base + pd_idx * 8)?);
        if !pde.is_present() {
            return Err(GovmemError::PageFault(vaddr, "PD"));
        }
        if pde.is_large_page() {
            // 2MB large page
            let phys = (pde.raw() & 0x000F_FFFF_FFE0_0000) | (vaddr & 0x1F_FFFF);
            return Ok(phys);
        }

        // PT: bits [20:12]
        let pt_base = pde.frame_addr();
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = PageTableEntry(self.phys.read_phys_u64(pt_base + pt_idx * 8)?);
        if !pte.is_present() {
            // Check for transition PTE (Windows-specific)
            if pte.is_transition() {
                return Ok(pte.frame_addr() | (vaddr & 0xFFF));
            }
            return Err(GovmemError::PageFault(vaddr, "PT"));
        }

        Ok(pte.frame_addr() | (vaddr & 0xFFF))
    }
}

/// A mapping from virtual address to physical address for a present page.
pub struct PageMapping {
    pub vaddr: u64,
    pub paddr: u64,
    pub size: u64, // 4KB, 2MB, or 1GB
}

impl<'a, P: PhysicalMemory> PageTableWalker<'a, P> {
    /// Enumerate all present user-mode pages for a given CR3.
    /// Calls the callback for each present page mapping.
    pub fn enumerate_present_pages<F>(&self, cr3: u64, mut callback: F)
    where
        F: FnMut(PageMapping),
    {
        let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

        // Only scan user-mode half (PML4 entries 0-255)
        for pml4_idx in 0..256u64 {
            let pml4e_addr = pml4_base + pml4_idx * 8;
            let pml4e = match self.phys.read_phys_u64(pml4e_addr) {
                Ok(v) => PageTableEntry(v),
                Err(_) => continue,
            };
            if !pml4e.is_present() {
                continue;
            }

            let pdpt_base = pml4e.frame_addr();
            for pdpt_idx in 0..512u64 {
                let pdpte = match self.phys.read_phys_u64(pdpt_base + pdpt_idx * 8) {
                    Ok(v) => PageTableEntry(v),
                    Err(_) => continue,
                };
                if !pdpte.is_present() {
                    continue;
                }
                if pdpte.is_large_page() {
                    let vaddr = (pml4_idx << 39) | (pdpt_idx << 30);
                    let paddr = pdpte.raw() & 0x000F_FFFF_C000_0000;
                    callback(PageMapping { vaddr, paddr, size: 0x4000_0000 });
                    continue;
                }

                let pd_base = pdpte.frame_addr();
                for pd_idx in 0..512u64 {
                    let pde = match self.phys.read_phys_u64(pd_base + pd_idx * 8) {
                        Ok(v) => PageTableEntry(v),
                        Err(_) => continue,
                    };
                    if !pde.is_present() {
                        continue;
                    }
                    if pde.is_large_page() {
                        let vaddr = (pml4_idx << 39) | (pdpt_idx << 30) | (pd_idx << 21);
                        let paddr = pde.raw() & 0x000F_FFFF_FFE0_0000;
                        callback(PageMapping { vaddr, paddr, size: 0x20_0000 });
                        continue;
                    }

                    let pt_base = pde.frame_addr();
                    for pt_idx in 0..512u64 {
                        let pte = match self.phys.read_phys_u64(pt_base + pt_idx * 8) {
                            Ok(v) => PageTableEntry(v),
                            Err(_) => continue,
                        };
                        if pte.is_present() || pte.is_transition() {
                            let vaddr = (pml4_idx << 39) | (pdpt_idx << 30) | (pd_idx << 21) | (pt_idx << 12);
                            let paddr = pte.frame_addr();
                            callback(PageMapping { vaddr, paddr, size: 0x1000 });
                        }
                    }
                }
            }
        }
    }
}

/// Process virtual memory: combines a DTB (CR3) with physical memory for address translation.
pub struct ProcessMemory<'a, P: PhysicalMemory> {
    phys: &'a P,
    walker: PageTableWalker<'a, P>,
    dtb: u64,
}

impl<'a, P: PhysicalMemory> ProcessMemory<'a, P> {
    pub fn new(phys: &'a P, dtb: u64) -> Self {
        Self {
            phys,
            walker: PageTableWalker::new(phys),
            dtb,
        }
    }

    pub fn dtb(&self) -> u64 {
        self.dtb
    }

    pub fn phys(&self) -> &'a P {
        self.phys
    }

    pub fn translate(&self, vaddr: u64) -> Result<u64> {
        self.walker.translate(self.dtb, vaddr)
    }
}

impl<'a, P: PhysicalMemory> VirtualMemory for ProcessMemory<'a, P> {
    fn read_virt(&self, vaddr: u64, buf: &mut [u8]) -> Result<()> {
        // Handle page-crossing reads, zero-fill pages that fault (demand-paged/swapped).
        let mut offset = 0;
        while offset < buf.len() {
            let current_vaddr = vaddr + offset as u64;
            let page_remaining = 0x1000 - (current_vaddr & 0xFFF) as usize;
            let chunk = std::cmp::min(page_remaining, buf.len() - offset);
            match self.walker.translate(self.dtb, current_vaddr) {
                Ok(phys_addr) => {
                    if self.phys.read_phys(phys_addr, &mut buf[offset..offset + chunk]).is_err() {
                        // Physical read failed, zero-fill
                        buf[offset..offset + chunk].fill(0);
                    }
                }
                Err(_) => {
                    // Page not present (paged out / demand paging), zero-fill
                    buf[offset..offset + chunk].fill(0);
                }
            }
            offset += chunk;
        }
        Ok(())
    }
}
