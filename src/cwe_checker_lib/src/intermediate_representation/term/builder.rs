//! This module contains the implementations of various builder functions
//! for different terms.
#[cfg(test)]
use crate::utils::binary::MemorySegment;
#[cfg(test)]
use crate::{expr, intermediate_representation::*, variable};
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
impl Expression {
    /// Shortcut for creating a cast expression
    #[cfg(test)]
    pub fn cast(self, op: CastOpType) -> Expression {
        Expression::Cast {
            op,
            size: ByteSize::new(8),
            arg: Box::new(self),
        }
    }

    /// Shortcut for creating a subpiece expression
    #[cfg(test)]
    pub fn subpiece(self, low_byte: ByteSize, size: ByteSize) -> Expression {
        Expression::Subpiece {
            low_byte,
            size,
            arg: Box::new(self),
        }
    }

    /// Shortcut for creating unary operation expressions.
    #[cfg(test)]
    pub fn un_op(self, op: UnOpType) -> Expression {
        Expression::UnOp {
            op,
            arg: Box::new(self),
        }
    }
}

/// ## Helper functions for building defs
#[cfg(test)]
impl Def {
    /// Shortcut for creating a assign def
    pub fn assign(tid: &str, var: Variable, value: Expression) -> Term<Def> {
        Term {
            tid: Tid::new(tid),
            term: Def::Assign { var, value },
        }
    }

    /// Shortcut for assign def of temp variable. Note: bytesize is 4.
    pub fn pointer_plus_offset_to_temp_var(
        tid: &str,
        tmp_name: &str,
        pointer: &str,
        offset: i64,
    ) -> Term<Def> {
        Def::assign(
            tid,
            Variable {
                name: String::from(tmp_name),
                size: ByteSize::new(4),
                is_temp: true,
            },
            expr!(format!("{}:4 + {}:4", pointer, offset)),
        )
    }

    /// Shortcut for store def from temp variable. Note: bytesize is 4.
    pub fn store_var_content_at_temp_var(tid: &str, tmp_name: &str, var: &str) -> Term<Def> {
        Term {
            tid: Tid::new(tid),
            term: Def::Store {
                address: Expression::Var(Variable {
                    name: String::from(tmp_name),
                    size: ByteSize::new(4),
                    is_temp: true,
                }),
                value: expr!(format!("{}:4", var)),
            },
        }
    }

    /// Shortcut fir load def from temp variable. Note, bytesize is 4
    pub fn load_var_content_from_temp_var(tid: &str, var: &str, tmp_name: &str) -> Term<Def> {
        Term {
            tid: Tid::new(tid),
            term: Def::Load {
                var: variable!(format!("{}:4", var)),
                address: Expression::Var(Variable {
                    name: String::from(tmp_name),
                    size: ByteSize::new(4),
                    is_temp: true,
                }),
            },
        }
    }
}

/// ## Helper functions for building jmps
#[cfg(test)]
impl Jmp {
    /// Shortcut for creating a call
    pub fn call(tid: &str, target_tid: &str, return_tid: Option<&str>) -> Term<Jmp> {
        let return_tid = return_tid.map(|tid_name| Tid::new(tid_name));
        Term {
            tid: Tid::new(tid),
            term: Jmp::Call {
                target: Tid::new(target_tid),
                return_: return_tid,
            },
        }
    }

    /// Shortcut for creating a branch
    pub fn branch(tid: &str, target_tid: &str) -> Term<Jmp> {
        Term {
            tid: Tid::new(tid),
            term: Jmp::Branch(Tid::new(target_tid)),
        }
    }
}

/// ## Helper functions for datatype properties
#[cfg(test)]
impl DatatypeProperties {
    pub fn mock() -> DatatypeProperties {
        DatatypeProperties {
            char_size: ByteSize::new(1),
            double_size: ByteSize::new(8),
            float_size: ByteSize::new(4),
            integer_size: ByteSize::new(4),
            long_double_size: ByteSize::new(8),
            long_long_size: ByteSize::new(8),
            long_size: ByteSize::new(4),
            pointer_size: ByteSize::new(8),
            short_size: ByteSize::new(2),
        }
    }

    /// Datatype sizes according to System V ABI
    pub fn mock_x64() -> DatatypeProperties {
        DatatypeProperties {
            char_size: ByteSize::new(1),
            double_size: ByteSize::new(8),
            float_size: ByteSize::new(4),
            integer_size: ByteSize::new(4),
            long_double_size: ByteSize::new(16),
            long_long_size: ByteSize::new(8),
            long_size: ByteSize::new(8),
            pointer_size: ByteSize::new(8),
            short_size: ByteSize::new(2),
        }
    }

    pub fn mock_arm32() -> DatatypeProperties {
        DatatypeProperties {
            char_size: ByteSize::new(1),
            double_size: ByteSize::new(8),
            float_size: ByteSize::new(4),
            integer_size: ByteSize::new(4),
            long_double_size: ByteSize::new(8),
            long_long_size: ByteSize::new(8),
            long_size: ByteSize::new(4),
            pointer_size: ByteSize::new(4),
            short_size: ByteSize::new(2),
        }
    }
}

#[cfg(test)]
impl Blk {
    /// Creates empty block with given tid.
    pub fn mock_with_tid(tid: &str) -> Term<Blk> {
        Term {
            tid: Tid::new(tid),
            term: Blk {
                defs: Vec::new(),
                jmps: Vec::new(),
                indirect_jmp_targets: Vec::new(),
            },
        }
    }

    /// Creates empty block with tid "block".
    pub fn mock() -> Term<Blk> {
        Self::mock_with_tid("block")
    }
}
#[cfg(test)]
impl Sub {
    pub fn mock(name: impl ToString) -> Term<Sub> {
        Term {
            tid: Tid::new(name.to_string()),
            term: Sub {
                name: name.to_string(),
                blocks: Vec::new(),
                calling_convention: None,
            },
        }
    }
}

/// Wrapper for subpiece to model float register for argument passing
#[cfg(test)]
fn create_float_register_subpiece(
    name: &str,
    reg_size: u64,
    low_byte: u64,
    size: u64,
) -> Expression {
    Expression::subpiece(
        expr!(format!("{name}:{reg_size}")),
        ByteSize::new(low_byte),
        ByteSize::new(size),
    )
}

#[cfg(test)]
impl CallingConvention {
    /// Creates System V Calling Convention with Advanced Vector Extensions 512
    pub fn mock_x64() -> CallingConvention {
        CallingConvention {
            name: "__stdcall".to_string(), // so that the mock is useable as standard calling convention in tests
            integer_parameter_register: vec![
                variable!("RDI:8"),
                variable!("RSI:8"),
                variable!("RDX:8"),
                variable!("RCX:8"),
                variable!("R8:8"),
                variable!("R9:8"),
            ],
            // ABI: first 8 Bytes of ZMM0-ZMM7 for float parameter
            // Ghidra: first 8 Bytes of YMM0-YMM7 for float parameter
            float_parameter_register: vec![
                create_float_register_subpiece("ZMM0", 64, 0, 8),
                create_float_register_subpiece("ZMM1", 64, 0, 8),
                create_float_register_subpiece("ZMM2", 64, 0, 8),
                create_float_register_subpiece("ZMM3", 64, 0, 8),
                create_float_register_subpiece("ZMM4", 64, 0, 8),
                create_float_register_subpiece("ZMM5", 64, 0, 8),
                create_float_register_subpiece("ZMM6", 64, 0, 8),
                create_float_register_subpiece("ZMM7", 64, 0, 8),
            ],
            integer_return_register: vec![variable!("RAX:8"), variable!("RDX:8")],
            // ABI: XMM0-XMM1 float return register
            // Ghidra: uses XMM0 only
            float_return_register: vec![create_float_register_subpiece("ZMM0", 64, 0, 8)],
            callee_saved_register: vec![
                variable!("RBP:8"),
                variable!("RBX:8"),
                variable!("RSP:8"),
                variable!("R12:8"),
                variable!("R13:8"),
                variable!("R14:8"),
                variable!("R15:8"),
            ],
        }
    }

    /// Following ARM32 ABI with MVE Extention
    pub fn mock_arm32() -> CallingConvention {
        CallingConvention {
            name: "__stdcall".to_string(), // so that the mock is useable as standard calling convention in tests
            integer_parameter_register: vec![
                variable!("r0:4"),
                variable!("r1:4"),
                variable!("r2:4"),
                variable!("r3:4"),
            ],
            // ABI: q0-q3 used for argument passing
            // Ghidra: uses q0-q1 only
            float_parameter_register: vec![
                create_float_register_subpiece("q0", 16, 0, 4),
                create_float_register_subpiece("q0", 16, 4, 4),
                create_float_register_subpiece("q0", 16, 8, 4),
                create_float_register_subpiece("q0", 16, 12, 4),
                create_float_register_subpiece("q1", 16, 0, 4),
                create_float_register_subpiece("q1", 16, 4, 4),
                create_float_register_subpiece("q1", 16, 8, 4),
                create_float_register_subpiece("q1", 16, 12, 4),
            ],
            // ABI: r0-r1 used as integer return register
            // Ghidra uses r0 only
            integer_return_register: vec![
                variable!("r0:4"),
                variable!("r1:4"),
                variable!("r2:4"),
                variable!("r3:4"),
            ],
            // ABI: whole q0 used as float return
            // Ghidra: uses first 8 Bytes of q0 only
            float_return_register: vec![create_float_register_subpiece("q0", 16, 0, 4)],
            callee_saved_register: vec![
                variable!("r4:4"),
                variable!("r5:4"),
                variable!("r6:4"),
                variable!("r7:4"),
                variable!("r8:4"),
                variable!("r9:4"),
                variable!("r10:4"),
                variable!("r11:4"),
                variable!("r13:4"),
                variable!("q4:16"),
                variable!("q5:16"),
                variable!("q6:16"),
                variable!("q7:16"),
            ],
        }
    }
}

#[cfg(test)]
impl Arg {
    pub fn mock_register(name: impl ToString, size_in_bytes: impl Into<ByteSize>) -> Arg {
        Arg::Register {
            expr: expr!(format!("{}:{}", name.to_string(), size_in_bytes.into())),
            data_type: None,
        }
    }

    pub fn mock_register_with_data_type(
        name: impl ToString,
        size_in_bytes: impl Into<ByteSize>,
        data_type: Option<Datatype>,
    ) -> Arg {
        Arg::Register {
            expr: expr!(format!("{}:{}", name.to_string(), size_in_bytes.into())),
            data_type,
        }
    }

    pub fn mock_pointer_register(name: impl ToString, size_in_bytes: impl Into<ByteSize>) -> Arg {
        Arg::Register {
            expr: expr!(format!("{}:{}", name.to_string(), size_in_bytes.into())),
            data_type: Some(Datatype::Pointer),
        }
    }
}

#[cfg(test)]
impl ExternSymbol {
    pub fn mock_x64(name: impl ToString) -> ExternSymbol {
        ExternSymbol {
            tid: Tid::new(name.to_string()),
            addresses: vec!["UNKNOWN".to_string()],
            name: name.to_string(),
            calling_convention: Some("__stdcall".to_string()),
            parameters: vec![Arg::mock_register("RDI", 8)],
            return_values: vec![Arg::mock_register("RAX", 8)],
            no_return: false,
            has_var_args: false,
        }
    }

    pub fn mock_arm32(name: impl ToString) -> ExternSymbol {
        ExternSymbol {
            tid: Tid::new(name.to_string()),
            addresses: vec!["UNKNOWN".to_string()],
            name: name.to_string(),
            calling_convention: Some("__stdcall".to_string()),
            parameters: vec![Arg::mock_register("r0", 4)],
            return_values: vec![Arg::mock_register("r0", 4)],
            no_return: false,
            has_var_args: false,
        }
    }

    pub fn mock_sprintf_x64() -> Self {
        ExternSymbol {
            tid: Tid::new("sprintf"),
            addresses: vec!["UNKNOWN".to_string()],
            name: "sprintf".to_string(),
            calling_convention: Some("__stdcall".to_string()),
            parameters: vec![Arg::mock_register("RDI", 8), Arg::mock_register("RSI", 8)],
            return_values: vec![Arg::mock_register("RAX", 8)],
            no_return: false,
            has_var_args: true,
        }
    }

    /// Returns extern symbol with argument/return register according to calling convention
    pub fn create_extern_symbol(
        name: &str,
        cconv: CallingConvention,
        arg_type: Option<Datatype>,
        return_type: Option<Datatype>,
    ) -> ExternSymbol {
        ExternSymbol {
            tid: Tid::new(name),
            addresses: vec![],
            name: name.to_string(),
            calling_convention: Some(cconv.name),
            parameters: match arg_type {
                Some(data_type) => {
                    vec![Arg::from_var(
                        cconv.integer_parameter_register[0].clone(),
                        Some(data_type),
                    )]
                }
                None => vec![],
            },
            return_values: match return_type {
                Some(data_type) => {
                    vec![Arg::from_var(
                        cconv.integer_return_register[0].clone(),
                        Some(data_type),
                    )]
                }
                None => vec![],
            },
            no_return: false,
            has_var_args: false,
        }
    }
}

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
