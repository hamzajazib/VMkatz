use thiserror::Error;

#[derive(Error, Debug)]
pub enum GovmemError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid VMSN magic: 0x{0:08x}")]
    InvalidMagic(u32),

    #[error("Group '{0}' not found in VMSN")]
    GroupNotFound(String),

    #[error("Tag '{0}' not found")]
    TagNotFound(String),

    #[error("Physical address 0x{0:x} unmappable (outside all regions)")]
    UnmappablePhysical(u64),

    #[error("Page fault at 0x{0:x} (level: {1})")]
    PageFault(u64, &'static str),

    #[error("System process not found")]
    SystemProcessNotFound,

    #[error("Process '{0}' not found")]
    ProcessNotFound(String),

    #[error("PE parse error at 0x{0:x}: {1}")]
    PeError(u64, String),

    #[error("Pattern not found: {0}")]
    PatternNotFound(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Unsupported Windows build: {0}")]
    UnsupportedBuild(u32),
}

pub type Result<T> = std::result::Result<T, GovmemError>;
