use goblin::{elf::Elf, pe::PE};

pub fn extract_elf_imports(elf: &Elf<'_>) -> Vec<String> {
    let mut imports = elf
        .dynsyms
        .iter()
        .filter(|sym| sym.st_shndx == 0)
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name).map(str::to_string))
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    imports.sort();
    imports.dedup();
    imports
}

pub fn extract_pe_imports(pe: &PE<'_>) -> Vec<String> {
    let mut imports = pe
        .imports
        .iter()
        .map(|import| import.name.to_string())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    imports.sort();
    imports.dedup();
    imports
}
