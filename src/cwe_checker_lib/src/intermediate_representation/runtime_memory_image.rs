use super::*;
use crate::utils::binary::{parse_hex_string_to_u64, BareMetalConfig, MemorySegment};
use goblin::{elf, Object};

/// A representation of the runtime image of a binary after being loaded into memory by the loader.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RuntimeMemoryImage {
    /// Sequence of memory segments.
    pub memory_segments: Vec<MemorySegment>,
    /// Endianness
    pub is_little_endian: bool,
}

impl RuntimeMemoryImage {
    /// Generate a runtime memory image containing no memory segments.
    /// Primarily useful in situations where any access to global memory would be an error.
    pub fn empty(is_little_endian: bool) -> RuntimeMemoryImage {
        RuntimeMemoryImage {
            memory_segments: Vec::new(),
            is_little_endian,
        }
    }

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

    /// Generate a runtime memory image for a bare metal binary.
    ///
    /// The generated runtime memory image contains:
    /// * one memory region corresponding to non-volatile memory
    /// * one memory region corresponding to volatile memory (RAM)
    ///
    /// See [`BareMetalConfig`] for more information about the assumed memory layout for bare metal binaries.
    pub fn new_from_bare_metal(
        binary: &[u8],
        bare_metal_config: &BareMetalConfig,
    ) -> Result<Self, Error> {
        let processor_id_parts: Vec<&str> = bare_metal_config.processor_id.split(':').collect();
        if processor_id_parts.len() < 3 {
            return Err(anyhow!("Could not parse processor ID."));
        }
        let is_little_endian = match processor_id_parts[1] {
            "LE" => true,
            "BE" => false,
            _ => return Err(anyhow!("Could not parse endianness of the processor ID.")),
        };
        let flash_base_address = parse_hex_string_to_u64(&bare_metal_config.flash_base_address)?;
        let ram_base_address = parse_hex_string_to_u64(&bare_metal_config.ram_base_address)?;
        let ram_size = parse_hex_string_to_u64(&bare_metal_config.ram_size)?;
        // Check that the whole binary is contained in addressable space.
        let address_bit_length = processor_id_parts[2].parse::<u64>()?;
        match flash_base_address.checked_add(binary.len() as u64) {
            Some(max_address) => {
                if (max_address >> address_bit_length) != 0 {
                    return Err(anyhow!("Binary too large for given base address"));
                }
            }
            None => return Err(anyhow!("Binary too large for given base address")),
        }

        Ok(RuntimeMemoryImage {
            memory_segments: vec![
                MemorySegment::from_bare_metal_file(binary, flash_base_address),
                MemorySegment::new_bare_metal_ram_segment(ram_base_address, ram_size),
            ],
            is_little_endian,
        })
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

    /// Checks whether the constant is a global memory address.
    pub fn is_global_memory_address(&self, constant: &Bitvector) -> bool {
        if self.read(constant, constant.bytesize()).is_ok() {
            return true;
        }
        false
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
mod tests {
    use crate::{bitvec, intermediate_representation::*};

    #[test]
    fn read_endianness() {
        let mut mem_image = RuntimeMemoryImage::mock();
        let address = bitvec!("0x1001:4");
        assert_eq!(
            mem_image.read(&address, ByteSize::new(4)).unwrap(),
            bitvec!("0xb4b3b2b1:4").into()
        );
        mem_image.is_little_endian = false;
        assert_eq!(
            mem_image.read(&address, ByteSize::new(4)).unwrap(),
            bitvec!("0xb1b2b3b4:4").into()
        );
    }

    #[test]
    fn ro_data_pointer() {
        let mem_image = RuntimeMemoryImage::mock();
        let address = bitvec!("0x1002:4");
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
        let address = bitvec!("0x3002:4");
        assert_eq!(
            expected_string,
            mem_image
                .read_string_until_null_terminator(&address)
                .unwrap(),
        );
    }
}
