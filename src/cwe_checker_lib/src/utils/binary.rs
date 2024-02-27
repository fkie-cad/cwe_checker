//! Utility structs and functions which directly parse the binary file.

use crate::prelude::*;
use goblin::elf;
use goblin::pe;

/// Contains all information parsed out of the bare metal configuration JSON file.
///
/// The content is information that is necessary for handling bare metal binaries
/// and that the cwe_checker cannot automatically deduce from the binary itself.
///
/// When handling bare metal binaries
/// we assume that the corresponding MCU uses a very simple memory layout
/// consisting of exactly one region of non-volatile (flash) memory
/// and exactly one region of volatile memory (RAM).
/// Furthermore, we assume that the binary itself is just a dump of the non-volatile memory region.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct BareMetalConfig {
    /// The CPU type.
    ///
    /// The string has to match the `processor_id` that Ghidra uses for the specific CPU type,
    /// as it is forwarded to Ghidra to identify the CPU.
    pub processor_id: String,
    /// The base address of the non-volatile memory (usually flash memory) used by the chip.
    /// The string is parsed as a hexadecimal number.
    ///
    /// We assume that the size of the non-volatile memory equals the size of the input binary.
    /// In other words, we assume
    /// that the input binary is a complete dump of the contents of the non-volatile memory of the chip.
    pub flash_base_address: String,
    /// The base address of the volatile memory (RAM) used by the chip.
    /// The string is parsed as a hexadecimal number.
    pub ram_base_address: String,
    /// The size of the volatile memory (RAM) used by the chip.
    /// The string is parsed as a hexadecimal number.
    ///
    /// If the exact size is unknown, then one can try to use an upper approximation instead.
    pub ram_size: String,
}

impl BareMetalConfig {
    /// Return the base address of the binary as an integer.
    pub fn parse_binary_base_address(&self) -> u64 {
        parse_hex_string_to_u64(&self.flash_base_address)
            .expect("Parsing of the binary base address failed.")
    }
}

/// A helper function to parse a hex string to an integer.
pub fn parse_hex_string_to_u64(mut string: &str) -> Result<u64, Error> {
    if string.starts_with("0x") {
        string = &string[2..]
    }
    Ok(u64::from_str_radix(string, 16)?)
}

/// A continuous segment in the memory image.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct MemorySegment {
    /// The contents of the segment
    pub bytes: Vec<u8>,
    /// The base address, i.e. the address of the first byte of the segment
    pub base_address: u64,
    /// Is the segment readable
    pub read_flag: bool,
    /// Is the segment writeable
    pub write_flag: bool,
    /// Is the segment executable
    pub execute_flag: bool,
}

impl MemorySegment {
    /// Generate a segment from a section header of a relocatable ELF object
    /// file.
    pub fn from_elf_section(
        binary: &[u8],
        base_address: u64,
        section_header: &elf::SectionHeader,
    ) -> Self {
        let bytes: Vec<u8> = match section_header.file_range() {
            Some(range) => binary[range].to_vec(),
            // `SHT_NOBITS`
            None => core::iter::repeat(0)
                .take(section_header.sh_size as usize)
                .collect(),
        };
        let alignment = section_header.sh_addralign.next_power_of_two();
        Self {
            bytes,
            base_address: base_address.next_multiple_of(alignment),
            // ELF format specification does not allow for Declaration of
            // sections as non-readable.
            read_flag: true,
            write_flag: section_header.is_writable(),
            execute_flag: section_header.is_executable(),
        }
    }

    /// Generate a segment from a program header of an ELF file.
    pub fn from_elf_segment(binary: &[u8], program_header: &elf::ProgramHeader) -> MemorySegment {
        let mut bytes: Vec<u8> = binary[program_header.file_range()].to_vec();
        if program_header.vm_range().len() > program_header.file_range().len() {
            // The additional memory space must be filled with null bytes.
            bytes.resize(program_header.vm_range().len(), 0u8);
        }
        MemorySegment {
            bytes,
            base_address: program_header.p_vaddr,
            read_flag: program_header.is_read(),
            write_flag: program_header.is_write(),
            execute_flag: program_header.is_executable(),
        }
    }

    /// Generate a segment from a section table from a PE file.
    pub fn from_pe_section(
        binary: &[u8],
        section_header: &pe::section_table::SectionTable,
    ) -> MemorySegment {
        let mut bytes: Vec<u8> = binary[section_header.pointer_to_raw_data as usize
            ..(section_header.pointer_to_raw_data as usize
                + section_header.size_of_raw_data as usize)]
            .to_vec();
        if section_header.virtual_size > section_header.size_of_raw_data {
            // The additional memory space must be filled with null bytes.
            bytes.resize(section_header.virtual_size as usize, 0u8);
        }
        MemorySegment {
            bytes,
            base_address: section_header.virtual_address as u64,
            read_flag: (section_header.characteristics & 0x40000000) != 0,
            write_flag: (section_header.characteristics & 0x80000000) != 0,
            execute_flag: (section_header.characteristics & 0x20000000) != 0,
        }
    }

    /// Generate a segment with the given `base_address` and content given by `binary`.
    /// The segment is readable, writeable and executable, its size equals the size of `binary`.
    pub fn from_bare_metal_file(binary: &[u8], base_address: u64) -> MemorySegment {
        MemorySegment {
            bytes: binary.to_vec(),
            base_address,
            read_flag: true,
            write_flag: true,
            execute_flag: true,
        }
    }

    /// Generate a segment with the given base address and size.
    /// The segment is readable and writeable, but not executable.
    /// The content is set to a vector of zeroes.
    pub fn new_bare_metal_ram_segment(base_address: u64, size: u64) -> MemorySegment {
        MemorySegment {
            bytes: vec![0; size as usize],
            base_address,
            read_flag: true,
            write_flag: true,
            execute_flag: false,
        }
    }
}
