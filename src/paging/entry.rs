/// Wrapper for a 64-bit page table entry.
#[derive(Debug, Clone, Copy)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Present bit (bit 0).
    pub fn is_present(&self) -> bool {
        self.0 & 1 != 0
    }

    /// Page Size bit (bit 7) - indicates 2MB page (PDE) or 1GB page (PDPTE).
    pub fn is_large_page(&self) -> bool {
        self.0 & (1 << 7) != 0
    }

    /// Extract the physical frame address (bits 12-51, mask lower 12 bits).
    pub fn frame_addr(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }

    /// Windows transition PTE: bit 11 set (prototype) and bit 10 clear.
    /// Transition PTEs point to pages still in physical memory but marked not-present.
    pub fn is_transition(&self) -> bool {
        (self.0 & (1 << 11)) != 0 && (self.0 & (1 << 10)) == 0
    }

    pub fn raw(&self) -> u64 {
        self.0
    }
}
