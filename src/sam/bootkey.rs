//! Bootkey (System Key) extraction from the SYSTEM registry hive.
//!
//! The bootkey is derived from the class names of four LSA subkeys
//! (JD, Skew1, GBG, Data), concatenated and permuted.

use crate::error::{GovmemError, Result};
use super::hive::Hive;

/// Permutation table applied to the raw 16-byte key.
const PBOX: [usize; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];

/// Extract the 16-byte bootkey from SYSTEM hive data.
pub fn extract_bootkey(system_hive_data: &[u8]) -> Result<[u8; 16]> {
    let hive = Hive::new(system_hive_data)?;
    let root = hive.root_key()?;

    // Determine current ControlSet from Select\Current
    let select = root.subkey(&hive, "Select")?;
    let current_cs = select.value_dword(&hive, "Current")?;
    log::info!("Current ControlSet: {}", current_cs);

    let cs_name = format!("ControlSet{:03}", current_cs);
    let lsa = root
        .subkey(&hive, &cs_name)?
        .subkey(&hive, "Control")?
        .subkey(&hive, "Lsa")?;

    // Read class names of JD, Skew1, GBG, Data and decode hex → bytes
    let key_names = ["JD", "Skew1", "GBG", "Data"];
    let mut raw = Vec::with_capacity(16);

    for &kn in &key_names {
        let sub = lsa.subkey(&hive, kn)?;
        let class = sub.class_name(&hive)?;
        let bytes = hex::decode(&class).map_err(|e| {
            GovmemError::DecryptionError(format!(
                "Bad hex in {} class name '{}': {}",
                kn, class, e
            ))
        })?;
        raw.extend_from_slice(&bytes);
    }

    if raw.len() != 16 {
        return Err(GovmemError::DecryptionError(format!(
            "Bootkey raw length {} (expected 16)",
            raw.len()
        )));
    }

    // Apply permutation
    let mut bootkey = [0u8; 16];
    for (i, &p) in PBOX.iter().enumerate() {
        bootkey[i] = raw[p];
    }

    Ok(bootkey)
}
