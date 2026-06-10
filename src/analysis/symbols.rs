use goblin::{elf::Elf, pe::PE};

pub fn extract_elf_symbols(elf: &Elf<'_>) -> Vec<String> {
    let mut symbols = elf
        .syms
        .iter()
        .filter_map(|sym| elf.strtab.get_at(sym.st_name).map(str::to_string))
        .chain(
            elf.dynsyms
                .iter()
                .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name).map(str::to_string)),
        )
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    symbols.sort();
    symbols.dedup();
    symbols
}

pub fn extract_elf_exports(elf: &Elf<'_>) -> Vec<String> {
    let mut exports = elf
        .dynsyms
        .iter()
        .filter(|sym| sym.st_shndx != 0)
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name).map(str::to_string))
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    exports.sort();
    exports.dedup();
    exports
}

pub fn extract_pe_exports(pe: &PE<'_>) -> Vec<String> {
    let mut exports = pe
        .exports
        .iter()
        .filter_map(|export| export.name.map(str::to_string))
        .collect::<Vec<_>>();
    exports.sort();
    exports.dedup();
    exports
}
