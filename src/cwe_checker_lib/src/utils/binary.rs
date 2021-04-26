//! Utility structs and functions which directly parse the binary file.

use crate::intermediate_representation::BinOpType;
use crate::intermediate_representation::BitvectorExtended;
use crate::prelude::*;
use goblin::elf;
use goblin::pe;
use goblin::Object;

/// A representation of the runtime image of a binary after being loaded into memory by the loader.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RuntimeMemoryImage {
    memory_segments: Vec<MemorySegment>,
    is_little_endian: bool,
}

/// A continuous segment in the memory image.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
struct MemorySegment {
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
}

impl RuntimeMemoryImage {
    /// Generate a runtime memory image for a given binary.
    ///
    /// The function can parse ELF and PE files as input.
    pub fn new(binary: &[u8]) -> Result<Self, Error> {
        let parsed_object = Object::parse(binary)?;

        match parsed_object {
            Object::Elf(elf_file) => {
                let mut memory_segments = Vec::new();
                for header in elf_file.program_headers.iter() {
                    if header.p_type == elf::program_header::PT_LOAD {
                        memory_segments.push(MemorySegment::from_elf_segment(binary, header));
                    }
                }
                if memory_segments.is_empty() {
                    return Err(anyhow!("No loadable segments found"));
                }
                Ok(RuntimeMemoryImage {
                    memory_segments,
                    is_little_endian: elf_file.header.endianness().unwrap().is_little(),
                })
            }
            Object::PE(pe_file) => {
                let mut memory_segments = Vec::new();
                for header in pe_file.sections.iter() {
                    if (header.characteristics & 0x02000000) == 0 {
                        // Only load segments which are not discardable
                        memory_segments.push(MemorySegment::from_pe_section(binary, header));
                    }
                }
                if memory_segments.is_empty() {
                    return Err(anyhow!("No loadable segments found"));
                }
                let mut memory_image = RuntimeMemoryImage {
                    memory_segments,
                    is_little_endian: true,
                };
                memory_image.add_global_memory_offset(pe_file.image_base as u64);
                Ok(memory_image)
            }
            _ => Err(anyhow!("Object type not supported.")),
        }
    }

    /// Return whether values in the memory image should be interpreted in little-endian
    /// or big-endian byte order.
    pub fn is_little_endian_byte_order(&self) -> bool {
        self.is_little_endian
    }

    /// Add a global offset to the base addresses of all memory segments.
    /// Useful to align the addresses with those reported by Ghidra
    /// if the Ghidra backend added such an offset to all addresses.
    pub fn add_global_memory_offset(&mut self, offset: u64) {
        for segment in self.memory_segments.iter_mut() {
            segment.base_address += offset;
        }
    }

    /// Read the contents of the memory image at the given address
    /// to emulate a read instruction to global data at runtime.
    ///
    /// The read method is endian-aware,
    /// i.e. values are interpreted with the endianness of the CPU architecture.
    /// If the address points to a writeable segment, the returned value is a `Ok(None)` value,
    /// since the data may change during program execution.
    ///
    /// Returns an error if the address is not contained in the global data address range.
    pub fn read(&self, address: &Bitvector, size: ByteSize) -> Result<Option<Bitvector>, Error> {
        let address = address.try_to_u64().unwrap();
        for segment in self.memory_segments.iter() {
            if address >= segment.base_address
                && u64::from(size) <= segment.base_address + segment.bytes.len() as u64
                && address <= segment.base_address + segment.bytes.len() as u64 - u64::from(size)
            {
                if segment.write_flag {
                    // The segment is writeable, thus we do not know the content at runtime.
                    return Ok(None);
                }
                let index = (address - segment.base_address) as usize;
                let mut bytes = segment.bytes[index..index + u64::from(size) as usize].to_vec();
                if self.is_little_endian {
                    bytes = bytes.into_iter().rev().collect();
                }
                let mut bytes = bytes.into_iter();
                let mut bitvector = Bitvector::from_u8(bytes.next().unwrap());
                for byte in bytes {
                    let new_byte = Bitvector::from_u8(byte);
                    bitvector = bitvector.bin_op(BinOpType::Piece, &new_byte)?;
                }
                return Ok(Some(bitvector));
            }
        }
        // No segment fully contains the read.
        Err(anyhow!("Address is not a valid global memory address."))
    }

    /// Read the contents of memory from a given address onwards until a null byte is reached and checks whether the
    /// content is a valid UTF8 string.
    pub fn read_string_until_null_terminator(&self, address: &Bitvector) -> Result<&str, Error> {
        let address = address.try_to_u64().unwrap();
        for segment in self.memory_segments.iter() {
            if address >= segment.base_address
                && address <= segment.base_address + segment.bytes.len() as u64
            {
                let start_index = (address - segment.base_address) as usize;
                if let Some(end_index) = segment.bytes[start_index..].iter().position(|&b| b == 0) {
                    let c_str = std::ffi::CStr::from_bytes_with_nul(
                        &segment.bytes[start_index..start_index + end_index + 1],
                    )?;
                    return Ok(c_str.to_str()?);
                } else {
                    return Err(anyhow!("Not a valid string in memory."));
                }
            }
        }

        Err(anyhow!("Address is not a valid global memory address."))
    }

    /// Checks whether the memory content at the input address is
    /// an address to another memory position and returns the address in memory.
    pub fn parse_address_if_recursive(
        &self,
        address: &Bitvector,
        arch_size: ByteSize,
    ) -> Result<Bitvector, Error> {
        match self.read(address, arch_size) {
            Ok(Some(recursive_address)) => {
                if let Ok(_) = self.read(&recursive_address, arch_size) {
                    return Ok(recursive_address);
                } else {
                    return Ok(address.clone());
                }
            }
            Ok(None) => Err(anyhow!(
                "Writeable address does not guarantee correct content."
            )),
            Err(e) => Err(e),
        }
    }

    /// Check whether all addresses in the given interval point to a readable segment in the runtime memory image.
    ///
    /// Returns an error if the address interval intersects more than one memory segment
    /// or if it does not point to global memory at all.
    pub fn is_interval_readable(
        &self,
        start_address: u64,
        end_address: u64,
    ) -> Result<bool, Error> {
        for segment in self.memory_segments.iter() {
            if start_address >= segment.base_address
                && start_address < segment.base_address + segment.bytes.len() as u64
            {
                if end_address <= segment.base_address + segment.bytes.len() as u64 {
                    return Ok(segment.read_flag);
                } else {
                    return Err(anyhow!("Interval spans more than one segment"));
                }
            }
        }
        Err(anyhow!("Address not contained in runtime memory image"))
    }

    /// For an address to global read-only memory, return the memory segment it points to
    /// and the index inside the segment, where the address points to.
    ///
    /// Returns an error if the target memory segment is marked as writeable
    /// or if the pointer does not point to global memory.
    pub fn get_ro_data_pointer_at_address(
        &self,
        address: &Bitvector,
    ) -> Result<(&[u8], usize), Error> {
        let address = address.try_to_u64().unwrap();
        for segment in self.memory_segments.iter() {
            if address >= segment.base_address
                && address < segment.base_address + segment.bytes.len() as u64
            {
                if segment.write_flag {
                    return Err(anyhow!("Target segment is writeable"));
                } else {
                    return Ok((&segment.bytes, (address - segment.base_address) as usize));
                }
            }
        }
        Err(anyhow!("Pointer target not in global memory."))
    }

    /// Check whether the given address points to a writeable segment in the runtime memory image.
    ///
    /// Returns an error if the address does not point to global memory.
    pub fn is_address_writeable(&self, address: &Bitvector) -> Result<bool, Error> {
        let address = address.try_to_u64().unwrap();
        for segment in self.memory_segments.iter() {
            if address >= segment.base_address
                && address < segment.base_address + segment.bytes.len() as u64
            {
                return Ok(segment.write_flag);
            }
        }
        Err(anyhow!("Address not contained in runtime memory image"))
    }

    /// Check whether all addresses in the given interval point to a writeable segment in the runtime memory image.
    ///
    /// Returns an error if the address interval intersects more than one memory segment
    /// or if it does not point to global memory at all.
    pub fn is_interval_writeable(
        &self,
        start_address: u64,
        end_address: u64,
    ) -> Result<bool, Error> {
        for segment in self.memory_segments.iter() {
            if start_address >= segment.base_address
                && start_address < segment.base_address + segment.bytes.len() as u64
            {
                if end_address <= segment.base_address + segment.bytes.len() as u64 {
                    return Ok(segment.write_flag);
                } else {
                    return Err(anyhow!("Interval spans more than one segment"));
                }
            }
        }
        Err(anyhow!("Address not contained in runtime memory image"))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    impl RuntimeMemoryImage {
        /// Create a mock runtime memory image for unit tests.
        pub fn mock() -> RuntimeMemoryImage {
            RuntimeMemoryImage {
                memory_segments: vec![
                    MemorySegment {
                        bytes: [0xb0u8, 0xb1, 0xb2, 0xb3, 0xb4].to_vec(),
                        base_address: 0x1000,
                        read_flag: true,
                        write_flag: false,
                        execute_flag: false,
                    },
                    MemorySegment {
                        bytes: [0u8; 8].to_vec(),
                        base_address: 0x2000,
                        read_flag: true,
                        write_flag: true,
                        execute_flag: false,
                    },
                    MemorySegment {
                        bytes: [
                            0x01, 0x02, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
                            0x64, 0x00,
                        ]
                        .to_vec(),
                        base_address: 0x3000,
                        read_flag: true,
                        write_flag: false,
                        execute_flag: false,
                    },
                ],
                is_little_endian: true,
            }
        }
    }

    #[test]
    fn read_endianness() {
        let mut mem_image = RuntimeMemoryImage::mock();
        let address = Bitvector::from_u32(0x1001);
        assert_eq!(
            mem_image.read(&address, ByteSize::new(4)).unwrap(),
            Bitvector::from_u32(0xb4b3b2b1).into()
        );
        mem_image.is_little_endian = false;
        assert_eq!(
            mem_image.read(&address, ByteSize::new(4)).unwrap(),
            Bitvector::from_u32(0xb1b2b3b4).into()
        );
    }

    #[test]
    fn ro_data_pointer() {
        let mem_image = RuntimeMemoryImage::mock();
        let address = Bitvector::from_u32(0x1002);
        let (slice, index) = mem_image.get_ro_data_pointer_at_address(&address).unwrap();
        assert_eq!(index, 2);
        assert_eq!(&slice[index..], &[0xb2u8, 0xb3, 0xb4]);
    }

    #[test]
    fn test_read_string_until_null_terminator() {
        let mem_image = RuntimeMemoryImage::mock();
        // the byte array contains "Hello World".
        let expected_string: &str =
            std::str::from_utf8(b"\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64").unwrap();
        let address = Bitvector::from_u32(0x3002);
        assert_eq!(
            expected_string,
            mem_image
                .read_string_until_null_terminator(&address)
                .unwrap(),
        );
    }
}
