//! This module contains the implementations of various builder functions for
//! the higher intermediate representation [Project](crate::intermediate_representation::Expression),
//! [Program](crate::intermediate_representation::Expression)
//! and [RuntimeMemoryImage](crate::intermediate_representation::Expression).

#[cfg(test)]
use crate::utils::binary::MemorySegment;
#[cfg(test)]
use crate::{intermediate_representation::*, variable};
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
impl RuntimeMemoryImage {
    /// Creates a mock runtime memory image with: byte series, strings and format strings.
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
                // Contains the Hello World string at byte 3002.
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
                MemorySegment {
                    bytes: [0x02, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].to_vec(),
                    base_address: 0x4000,
                    read_flag: true,
                    write_flag: false,
                    execute_flag: false,
                },
                // Contains strings: '/dev/sd%c%d' and 'cat %s'
                MemorySegment {
                    bytes: [
                        0x2f, 0x64, 0x65, 0x76, 0x2f, 0x73, 0x64, 0x25, 0x63, 0x25, 0x64, 0x00,
                        0x63, 0x61, 0x74, 0x20, 0x25, 0x73, 0x00,
                    ]
                    .to_vec(),
                    base_address: 0x5000,
                    read_flag: true,
                    write_flag: false,
                    execute_flag: false,
                },
                // Contains string: 'cat %s %s %s %s' starting at the first byte.
                MemorySegment {
                    bytes: [
                        0x63, 0x61, 0x74, 0x20, 0x25, 0x73, 0x20, 0x25, 0x73, 0x20, 0x25, 0x73,
                        0x20, 0x25, 0x73, 0x00,
                    ]
                    .to_vec(),
                    base_address: 0x6000,
                    read_flag: true,
                    write_flag: false,
                    execute_flag: false,
                },
                // Contains string: 'str1 str2 str3 str4'
                MemorySegment {
                    bytes: [
                        0x73, 0x74, 0x72, 0x31, 0x20, 0x73, 0x74, 0x72, 0x32, 0x20, 0x73, 0x74,
                        0x72, 0x33, 0x20, 0x73, 0x74, 0x72, 0x34, 0x00,
                    ]
                    .to_vec(),
                    base_address: 0x7000,
                    read_flag: true,
                    write_flag: false,
                    execute_flag: false,
                },
            ],
            is_little_endian: true,
        }
    }
}

#[cfg(test)]
impl Program {
    fn add_extern_symbols_to_program(a: Vec<(Tid, ExternSymbol)>) -> Program {
        Program {
            subs: BTreeMap::new(),
            extern_symbols: BTreeMap::from_iter(a),
            entry_points: BTreeSet::new(),
            address_base_offset: 0x1000u64,
        }
    }

    /// Returns Program with malloc, free and other_function
    pub fn mock_x64() -> Program {
        let malloc = ExternSymbol::create_extern_symbol(
            "malloc",
            CallingConvention::mock_x64(),
            Some(Datatype::Integer),
            Some(Datatype::Pointer),
        );
        let free = ExternSymbol::create_extern_symbol(
            "free",
            CallingConvention::mock_x64(),
            Some(Datatype::Pointer),
            None,
        );
        let other_function = ExternSymbol::create_extern_symbol(
            "other_function",
            CallingConvention::mock_x64(),
            None,
            None,
        );

        Program::add_extern_symbols_to_program(vec![
            (malloc.tid.clone(), malloc),
            (free.tid.clone(), free),
            (other_function.tid.clone(), other_function),
        ])
    }

    /// Returns Program with malloc, free and other_function
    pub fn mock_arm32() -> Program {
        let malloc = ExternSymbol::create_extern_symbol(
            "malloc",
            CallingConvention::mock_arm32(),
            Some(Datatype::Integer),
            Some(Datatype::Pointer),
        );
        let free = ExternSymbol::create_extern_symbol(
            "free",
            CallingConvention::mock_arm32(),
            Some(Datatype::Pointer),
            None,
        );
        let other_function = ExternSymbol::create_extern_symbol(
            "other_function",
            CallingConvention::mock_arm32(),
            None,
            None,
        );

        Program::add_extern_symbols_to_program(vec![
            (malloc.tid.clone(), malloc),
            (free.tid.clone(), free),
            (other_function.tid.clone(), other_function),
        ])
    }
}

#[cfg(test)]
impl Project {
    /// Returns project with x64 calling convention and mocked program.
    pub fn mock_x64() -> Project {
        let mut none_cconv_register: Vec<Variable> = vec![
            "RAX", "RBX", "RSP", "RBP", "R10", "R11", "R12", "R13", "R14", "R15",
        ]
        .into_iter()
        .map(|name| variable!(format!("{name}:8")))
        .collect();
        let mut integer_register = CallingConvention::mock_x64().integer_parameter_register;
        integer_register.append(&mut none_cconv_register);

        let calling_conventions: BTreeMap<String, CallingConvention> =
            BTreeMap::from([("__stdcall".to_string(), CallingConvention::mock_x64())]);

        Project {
            program: Term {
                tid: Tid::new("program_tid"),
                term: Program::mock_x64(),
            },
            cpu_architecture: "x86_64".to_string(),
            stack_pointer_register: variable!("RSP:8"),
            calling_conventions,
            register_set: integer_register.iter().cloned().collect(),
            datatype_properties: DatatypeProperties::mock_x64(),
            runtime_memory_image: RuntimeMemoryImage::mock(),
        }
    }

    pub fn mock_arm32() -> Project {
        let none_cconv_4byte_register: Vec<Variable> = vec!["r12", "r14", "r15"]
            .into_iter()
            .map(|name| variable!(format!("{name}:4")))
            .collect();

        let none_cconv_16byte_register: Vec<Variable> = vec![
            "q0", "q1", "q2", "q3", "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15",
        ]
        .into_iter()
        .map(|name| variable!(format!("{name}:16")))
        .collect();

        let callee_saved_register = CallingConvention::mock_arm32().callee_saved_register;

        let integer_register = CallingConvention::mock_arm32()
            .integer_parameter_register
            .into_iter()
            .chain(none_cconv_4byte_register)
            .chain(none_cconv_16byte_register)
            .chain(callee_saved_register);

        Project {
            program: Term {
                tid: Tid::new("program_tid"),
                term: Program::mock_arm32(),
            },
            cpu_architecture: "arm32".to_string(),
            stack_pointer_register: variable!("sp:4"),
            calling_conventions: BTreeMap::from([(
                "__stdcall".to_string(),
                CallingConvention::mock_arm32(),
            )]),
            register_set: integer_register.collect(),
            datatype_properties: DatatypeProperties::mock_arm32(),
            runtime_memory_image: RuntimeMemoryImage::mock(),
        }
    }
}
