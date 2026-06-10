use goblin::pe::{section_table, PE};

use crate::analysis::binary::SectionInfo;

pub fn architecture(pe: &PE<'_>) -> String {
    match pe.header.coff_header.machine {
        0x8664 => "x86_64".to_string(),
        0x014c => "x86".to_string(),
        0xaa64 => "aarch64".to_string(),
        machine => format!("pe-machine-{machine:#x}"),
    }
}

pub fn sections(pe: &PE<'_>) -> Vec<SectionInfo> {
    pe.sections
        .iter()
        .map(|section| {
            let name = section.name().unwrap_or("<invalid>").to_string();
            let characteristics = section.characteristics;
            SectionInfo {
                name,
                address: u64::from(section.virtual_address),
                size: u64::from(section.virtual_size),
                executable: characteristics & section_table::IMAGE_SCN_MEM_EXECUTE != 0,
                writable: characteristics & section_table::IMAGE_SCN_MEM_WRITE != 0,
            }
        })
        .collect()
}
