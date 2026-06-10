use goblin::{
    elf::{program_header, Elf},
    pe::PE,
};
use serde::{Deserialize, Serialize};

use crate::analysis::binary::SectionInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProtections {
    pub nx: ProtectionState,
    pub pie: ProtectionState,
    pub relro: ProtectionState,
    pub canary: ProtectionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionState {
    Enabled,
    Disabled,
    Partial,
    Unknown,
}

impl SecurityProtections {
    pub fn unknown() -> Self {
        Self {
            nx: ProtectionState::Unknown,
            pie: ProtectionState::Unknown,
            relro: ProtectionState::Unknown,
            canary: ProtectionState::Unknown,
        }
    }
}

pub fn check_elf(
    elf: &Elf<'_>,
    sections: &[SectionInfo],
    symbols: &[String],
) -> SecurityProtections {
    let nx = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == program_header::PT_GNU_STACK)
        .map(|ph| {
            if ph.p_flags & program_header::PF_X == 0 {
                ProtectionState::Enabled
            } else {
                ProtectionState::Disabled
            }
        })
        .unwrap_or(ProtectionState::Unknown);

    let pie = if elf.is_lib {
        ProtectionState::Enabled
    } else {
        ProtectionState::Disabled
    };

    let has_gnu_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == program_header::PT_GNU_RELRO);
    let has_bind_now = elf.dynamic.as_ref().map_or(false, |dynamic| {
        dynamic.dyns.iter().any(|dyn_entry| {
            dyn_entry.d_tag == goblin::elf::dynamic::DT_BIND_NOW
                || (dyn_entry.d_tag == goblin::elf::dynamic::DT_FLAGS
                    && dyn_entry.d_val & u64::from(goblin::elf::dynamic::DF_BIND_NOW) != 0)
        })
    });
    let relro = match (has_gnu_relro, has_bind_now) {
        (true, true) => ProtectionState::Enabled,
        (true, false) => ProtectionState::Partial,
        (false, _) => ProtectionState::Disabled,
    };

    let canary = if symbols
        .iter()
        .any(|sym| sym.contains("__stack_chk_fail") || sym.contains("__stack_chk_guard"))
    {
        ProtectionState::Enabled
    } else {
        ProtectionState::Disabled
    };

    let nx = if nx == ProtectionState::Unknown
        && sections
            .iter()
            .any(|section| section.name == ".stack" && section.executable)
    {
        ProtectionState::Disabled
    } else {
        nx
    };

    SecurityProtections {
        nx,
        pie,
        relro,
        canary,
    }
}

pub fn check_pe(pe: &PE<'_>, sections: &[SectionInfo]) -> SecurityProtections {
    let nx = if pe
        .header
        .optional_header
        .as_ref()
        .map_or(false, |optional| {
            optional.windows_fields.dll_characteristics & 0x0100 != 0
        }) {
        ProtectionState::Enabled
    } else {
        ProtectionState::Disabled
    };

    let pie = if pe
        .header
        .optional_header
        .as_ref()
        .map_or(false, |optional| {
            optional.windows_fields.dll_characteristics & 0x0040 != 0
        }) {
        ProtectionState::Enabled
    } else {
        ProtectionState::Disabled
    };

    let writable_executable = sections
        .iter()
        .any(|section| section.writable && section.executable);
    let nx = if writable_executable {
        ProtectionState::Disabled
    } else {
        nx
    };

    SecurityProtections {
        nx,
        pie,
        relro: ProtectionState::Unknown,
        canary: ProtectionState::Unknown,
    }
}
