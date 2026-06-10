use goblin::elf::{header, section_header, Elf};

use crate::analysis::binary::SectionInfo;

pub fn architecture(elf: &Elf<'_>) -> String {
    match elf.header.e_machine {
        header::EM_X86_64 => "x86_64".to_string(),
        header::EM_386 => "x86".to_string(),
        header::EM_AARCH64 => "aarch64".to_string(),
        header::EM_ARM => "arm".to_string(),
        header::EM_RISCV => "riscv".to_string(),
        machine => format!("elf-machine-{machine}"),
    }
}

pub fn sections(elf: &Elf<'_>) -> Vec<SectionInfo> {
    elf.section_headers
        .iter()
        .filter_map(|section| {
            let name = elf.shdr_strtab.get_at(section.sh_name)?.to_string();
            Some(SectionInfo {
                name,
                address: section.sh_addr,
                size: section.sh_size,
                executable: section.sh_flags & u64::from(section_header::SHF_EXECINSTR) != 0,
                writable: section.sh_flags & u64::from(section_header::SHF_WRITE) != 0,
            })
        })
        .collect()
}
