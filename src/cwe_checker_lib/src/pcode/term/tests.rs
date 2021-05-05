use super::*;
use crate::intermediate_representation::{BinOpType, CastOpType, Variable as IrVariable};

struct Setup {
    project: Project,
    sub_t: Term<Sub>,
    blk_t: Term<Blk>,
    def_0_t: Term<Def>,
    def_1_t: Term<Def>,
    def_2_t: Term<Def>,
    def_3_t: Term<Def>,
    def_4_t: Term<Def>,
    def_5_t: Term<Def>,
    jmp_t: Term<Jmp>,
}

impl Setup {
    fn new() -> Self {
        Self {
            project: serde_json::from_str(
                r#"
                {
                    "program": {
                      "tid": {
                        "id": "prog_08048000",
                        "address": "08048000"
                      },
                      "term": {
                        "subs": [],
                        "extern_symbols": [],
                        "entry_points":[],
                        "image_base": "10000"
                      }
                    },
                    "stack_pointer_register": {
                        "name": "RSP",
                        "size": 8,
                        "is_virtual": false
                    },
                    "cpu_architecture": "x86_64",
                    "register_properties": [
                        {
                            "register": "AH",
                            "base_register": "RAX",
                            "lsb": 1,
                            "size": 1
                        },
                        {
                            "register": "AL",
                            "base_register": "RAX",
                            "lsb": 0,
                            "size": 1
                        },
                        {
                            "register": "AX",
                            "base_register": "RAX",
                            "lsb": 0,
                            "size": 2
                        },
                        {
                            "register": "EAX",
                            "base_register": "RAX",
                            "lsb": 0,
                            "size": 4
                        },
                        {
                            "register": "RAX",
                            "base_register": "RAX",
                            "lsb": 0,
                            "size": 8
                        },
                        {
                            "register": "EDI",
                            "base_register": "RDI",
                            "lsb": 0,
                            "size": 4
                        },
                        {
                            "register": "RDI",
                            "base_register": "RDI",
                            "lsb": 0,
                            "size": 8
                        }
                    ],
                    "register_calling_convention": [
                        {
                            "calling_convention": "default",
                            "integer_parameter_register": [],
                            "float_parameter_register": [],
                            "return_register": [],
                            "unaffected_register": [],
                            "killed_by_call_register": []
                        }
                    ],
                    "datatype_properties": {
                        "char_size": 1,
                        "double_size": 8,
                        "float_size": 4,
                        "integer_size": 4,
                        "long_double_size": 8,
                        "long_long_size": 8,
                        "long_size": 4,
                        "pointer_size": 4,
                        "short_size": 2
                    }
                }
                "#,
            )
            .unwrap(),
            sub_t: serde_json::from_str(
                r#"
                    {
                    "tid": {
                        "id": "sub_00101000",
                        "address": "00101000"
                    },
                    "term": {
                        "name": "sub_name",
                        "blocks": []
                    }
                    }
                    "#,
            )
            .unwrap(),
            blk_t: serde_json::from_str(
                r#"
                    {
                    "tid": {
                        "id": "blk_00101000",
                        "address": "00101000"
                    },
                    "term": {
                        "defs": [],
                        "jmps": []
                    }
                    }
                    "#,
            )
            .unwrap(),
            def_0_t: serde_json::from_str(
                r#"
            {
                "tid": {
                  "id": "instr_001053f8_0",
                  "address": "001053f8"
                },
                "term": {
                  "lhs": {
                    "name": "EDI",
                    "value": null,
                    "address": null,
                    "size": 4,
                    "is_virtual": false
                  },
                  "rhs": {
                    "mnemonic": "LOAD",
                    "input0": null,
                    "input1": {
                      "name": "EDI",
                      "value": null,
                      "address": null,
                      "size": 4,
                      "is_virtual": false
                    },
                    "input2": null
                  }
                }
              }
            "#,
            )
            .unwrap(),
            def_1_t: serde_json::from_str(
                r#"
            {
                "tid": {
                  "id": "instr_001053f8_1",
                  "address": "001053f8"
                },
                "term": {
                  "lhs": {
                    "name": "AH",
                    "value": null,
                    "address": null,
                    "size": 1,
                    "is_virtual": false
                  },
                  "rhs": {
                    "mnemonic": "INT_XOR",
                    "input0": {
                      "name": "AH",
                      "value": null,
                      "address": null,
                      "size": 1,
                      "is_virtual": false
                    },
                    "input1": {
                        "name": "AH",
                        "value": null,
                        "address": null,
                        "size": 1,
                        "is_virtual": false
                      },
                    "input2": null
                  }
                }
              }
            "#,
            )
            .unwrap(),
            def_2_t: serde_json::from_str(
                r#"
            {
                "tid": {
                  "id": "instr_001053f8_2",
                  "address": "001053f8"
                },
                "term": {
                  "lhs": {
                    "name": "EAX",
                    "value": null,
                    "address": null,
                    "size": 4,
                    "is_virtual": false
                  },
                  "rhs": {
                    "mnemonic": "COPY",
                    "input0": {
                      "name": "EDI",
                      "value": null,
                      "address": null,
                      "size": 4,
                      "is_virtual": false
                    },
                    "input1": null,
                    "input2": null
                  }
                }
              }
            "#,
            )
            .unwrap(),
            def_3_t: serde_json::from_str(
                r#"
            {
                "tid": {
                  "id": "instr_001053f8_3",
                  "address": "001053f8"
                },
                "term": {
                  "lhs": {
                    "name": "RAX",
                    "value": null,
                    "address": null,
                    "size": 8,
                    "is_virtual": false
                  },
                  "rhs": {
                    "mnemonic": "INT_ZEXT",
                    "input0": {
                      "name": "EAX",
                      "value": null,
                      "address": null,
                      "size": 4,
                      "is_virtual": false
                    },
                    "input1": null,
                    "input2": null
                  }
                }
              }
            "#,
            )
            .unwrap(),
            def_4_t: serde_json::from_str(
                r#"
            {
                "tid": {
                  "id": "instr_001053f8_4",
                  "address": "001053f8"
                },
                "term": {
                  "lhs": {
                    "name": "EAX",
                    "value": null,
                    "address": null,
                    "size": 4,
                    "is_virtual": false
                  },
                  "rhs": {
                    "mnemonic": "PIECE",
                    "input0": {
                      "name": null,
                      "value": "00000000",
                      "address": null,
                      "size": 2,
                      "is_virtual": false
                    },
                    "input1": {
                      "name": "AX",
                      "value": null,
                      "address": null,
                      "size": 2,
                      "is_virtual": false
                    },
                    "input2": null
                  }
                }
              }
            "#,
            )
            .unwrap(),
            def_5_t: serde_json::from_str(
                r#"
            {
                "tid": {
                  "id": "instr_001053f8_5",
                  "address": "001053f8"
                },
                "term": {
                  "lhs": {
                    "name": "AX",
                    "value": null,
                    "address": null,
                    "size": 2,
                    "is_virtual": false
                  },
                  "rhs": {
                    "mnemonic": "SUBPIECE",
                    "input0": {
                      "name": "EDI",
                      "value": null,
                      "address": null,
                      "size": 4,
                      "is_virtual": false
                    },
                    "input1": {
                      "name": null,
                      "value": "00000001",
                      "address": null,
                      "size": 4,
                      "is_virtual": false
                    },
                    "input2": null
                  }
                }
              }
            "#,
            )
            .unwrap(),
            jmp_t: serde_json::from_str(
                r#"
                    {
                        "tid": {
                        "id": "instr_00102014_2",
                        "address": "00102014"
                        },
                        "term": {
                        "type_": "CALL",
                        "mnemonic": "CALLIND",
                        "call": {
                            "target": {
                            "Indirect": {
                                "name": "EAX",
                                "size": 4,
                                "is_virtual": false
                            }
                            },
                            "return": {
                            "Direct": {
                                "id": "blk_00102016",
                                "address": "00102016"
                            }
                            }
                        }
                        }
                    }
                    "#,
            )
            .unwrap(),
        }
    }
}

#[test]
fn def_deserialization() {
    let def: Def = serde_json::from_str(
        r#"
      {
        "lhs": {
          "name": "CF",
          "size": 1,
          "is_virtual": false
        },
        "rhs": {
          "mnemonic": "INT_CARRY",
          "input0": {
            "name": "RDX",
            "size": 8,
            "is_virtual": false
          },
          "input1": {
            "name": "RDI",
            "size": 8,
            "is_virtual": false
          }
        }
      }
      "#,
    )
    .unwrap();
    let _: IrDef = def.into_ir_def(ByteSize::new(8));
    let def: Def = serde_json::from_str(
        r#"
            {
                "lhs": {
                    "address": "004053e8",
                    "size": 4,
                    "is_virtual": false
                },
                "rhs": {
                    "mnemonic": "INT_XOR",
                    "input0": {
                        "name": "$load_temp0",
                        "size": 4,
                        "is_virtual": true
                    },
                    "input1": {
                        "name": "$U4780",
                        "size": 4,
                        "is_virtual": true
                    }
                }
            }
            "#,
    )
    .unwrap();
    let _: IrDef = def.into_ir_def(ByteSize::new(8));
}

#[test]
fn label_deserialization() {
    let _: Label = serde_json::from_str(
        r#"
        {
            "Direct": {
              "id": "blk_00103901",
              "address": "00103901"
            }
        }
        "#,
    )
    .unwrap();
    let _: Label = serde_json::from_str(
        r#"
        {
            "Indirect": {
                "name": "00109ef0",
                "size": 8,
                "is_virtual": false
            }
        }
        "#,
    )
    .unwrap();
}

#[test]
fn jmp_deserialization() {
    let setup = Setup::new();
    let jmp_term: Term<Jmp> = setup.jmp_t.clone();
    let _: IrJmp = jmp_term.term.into();
}

#[test]
fn blk_deserialization() {
    let setup = Setup::new();
    let block_term: Term<Blk> = setup.blk_t.clone();
    let _: IrBlk = block_term.term.into_ir_blk(ByteSize::new(8));
}

#[test]
fn arg_deserialization() {
    let _: Arg = serde_json::from_str(
        r#"
            {
            "var": {
                "name": "RDI",
                "size": 8,
                "is_virtual": false
            },
            "intent": "INPUT"
            }
            "#,
    )
    .unwrap();
    let _: Arg = serde_json::from_str(
        r#"
            {
                "location": {
                "mnemonic": "LOAD",
                "input0": {
                    "address": "0x4",
                    "size": 4,
                    "is_virtual": false
                }
                },
                "intent": "INPUT"
            }
        "#,
    )
    .unwrap();
}

#[test]
fn sub_deserialization() {
    let setup = Setup::new();
    let sub_term: Term<Sub> = setup.sub_t.clone();
    let _: Term<IrSub> = sub_term.into_ir_sub_term(ByteSize::new(8));
    let sub_term: Term<Sub> = serde_json::from_str(
        r#"
          {
          "tid": {
              "id": "sub_00101000",
              "address": "00101000"
          },
          "term": {
              "name": "sub_name",
              "blocks": [
                {
                  "tid": {
                      "id": "blk_0010030",
                      "address": "00100030"
                  },
                  "term": {
                      "defs": [],
                      "jmps": []
                  }
                },
                {
                  "tid": {
                      "id": "blk_00101000",
                      "address": "00101000"
                  },
                  "term": {
                      "defs": [],
                      "jmps": []
                  }
                }
              ]
          }
          }
          "#,
    )
    .unwrap();
    // Example has special case where the starting block has to be corrected
    assert!(sub_term.tid.address != sub_term.term.blocks[0].tid.address);
    let ir_sub: Term<IrSub> = sub_term.into_ir_sub_term(ByteSize::new(8));
    assert_eq!(ir_sub.tid.address, ir_sub.term.blocks[0].tid.address);
}

#[test]
fn extern_symbol_deserialization() {
    let symbol: ExternSymbol = serde_json::from_str(
        r#"
            {
                "tid": {
                  "id": "sub_08048410",
                  "address": "08048410"
                },
                "addresses": [
                    "08048410"
                ],
                "name": "atoi",
                "calling_convention": "__cdecl",
                "arguments": [
                  {
                    "location": {
                      "mnemonic": "LOAD",
                      "input0": {
                        "address": "0x4",
                        "size": 4,
                        "is_virtual": false
                      }
                    },
                    "intent": "INPUT"
                  },
                  {
                    "var": {
                      "name": "EAX",
                      "size": 4,
                      "is_virtual": false
                    },
                    "intent": "OUTPUT"
                  }
                ],
                "no_return": false,
                "has_var_args": false
            }
            "#,
    )
    .unwrap();
    let _: IrExternSymbol = symbol.into();
}

#[test]
fn program_deserialization() {
    let program_term: Term<Program> = serde_json::from_str(
        r#"
            {
            "tid": {
                "id": "prog_00101000",
                "address": "00101000"
            },
            "term": {
                "subs": [],
                "extern_symbols": [],
                "entry_points":[],
                "image_base": "10000"
            }
            }
            "#,
    )
    .unwrap();
    let _: IrProgram = program_term.term.into_ir_program(10000, ByteSize::new(8));
}

#[test]
fn project_deserialization() {
    let setup = Setup::new();
    let project: Project = setup.project.clone();
    let _: IrProject = project.into_ir_project(10000);
}

#[test]
fn add_load_defs_for_implicit_ram_access() {
    let mut blk: Blk = Blk {
        defs: Vec::new(),
        jmps: Vec::new(),
    };
    blk.defs.push(
        serde_json::from_str(
            r#"
    {
        "tid": {
          "id": "instr_001053f8_0",
          "address": "001053f8"
        },
        "term": {
          "lhs": {
            "name": "RDI",
            "value": null,
            "address": null,
            "size": 8,
            "is_virtual": false
          },
          "rhs": {
            "mnemonic": "COPY",
            "input0": {
              "name": null,
              "value": null,
              "address": "0010a018",
              "size": 8,
              "is_virtual": false
            },
            "input1": null,
            "input2": null
          }
        }
      }
    "#,
        )
        .unwrap(),
    );
    blk.add_load_defs_for_implicit_ram_access(ByteSize::new(8));
    assert_eq!(
        blk.defs[0]
            .term
            .lhs
            .as_ref()
            .unwrap()
            .name
            .as_ref()
            .unwrap(),
        "$load_temp0"
    );
    assert_eq!(
        blk.defs[1]
            .term
            .rhs
            .input0
            .as_ref()
            .unwrap()
            .name
            .as_ref()
            .unwrap(),
        "$load_temp0"
    );
    assert_eq!(blk.defs.len(), 2);
}

#[test]
fn from_project_to_ir_project() {
    let setup = Setup::new();
    let mut mock_project: Project = setup.project.clone();
    let mut blk = setup.blk_t;
    blk.term.defs.push(setup.def_0_t);
    blk.term.defs.push(setup.def_1_t);
    blk.term.defs.push(setup.def_2_t);
    blk.term.defs.push(setup.def_3_t);
    blk.term.defs.push(setup.def_4_t);
    blk.term.defs.push(setup.def_5_t);
    blk.term.jmps.push(setup.jmp_t);

    let mut sub = setup.sub_t;
    sub.term.blocks.push(blk);
    mock_project.program.term.subs.push(sub.clone());

    let ir_program = mock_project.into_ir_project(10000).program.term;
    let ir_rdi_var = IrVariable {
        name: String::from("RDI"),
        size: ByteSize::new(8),
        is_temp: false,
    };
    let ir_rax_var = IrVariable {
        name: String::from("RAX"),
        size: ByteSize::new(8),
        is_temp: false,
    };

    // From: EDI = LOAD EDI
    // To: RDI = PIECE(SUBPIECE(RDI, 4, 4), (LOAD SUBPIECE(RDI, 0, 4)))
    let expected_def_0 = IrDef::Load {
        var: ir_rdi_var.clone(),
        address: IrExpression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(IrExpression::Subpiece {
                low_byte: ByteSize::new(4),
                size: ByteSize::new(4),
                arg: Box::new(IrExpression::Var(ir_rdi_var.clone())),
            }),
            rhs: Box::new(IrExpression::Subpiece {
                low_byte: ByteSize::new(0),
                size: ByteSize::new(4),
                arg: Box::new(IrExpression::Var(ir_rdi_var.clone())),
            }),
        },
    };
    // From: AH = AH INT_XOR AH
    // To: RAX = PIECE(PIECE(SUBPIECE(RAX, 2, 6), (SUBPIECE(RAX, 1, 1) INT_XOR SUBPIECE(RAX, 1, 1))), SUBPIECE(RAX, 0, 1))
    let expected_def_1 = IrDef::Assign {
        var: ir_rax_var.clone(),
        value: IrExpression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(IrExpression::BinOp {
                op: BinOpType::Piece,
                lhs: Box::new(IrExpression::Subpiece {
                    low_byte: ByteSize::new(2),
                    size: ByteSize::new(6),
                    arg: Box::new(IrExpression::Var(ir_rax_var.clone())),
                }),
                rhs: Box::new(IrExpression::BinOp {
                    op: BinOpType::IntXOr,
                    lhs: Box::new(IrExpression::Subpiece {
                        low_byte: ByteSize::new(1),
                        size: ByteSize::new(1),
                        arg: Box::new(IrExpression::Var(ir_rax_var.clone())),
                    }),
                    rhs: Box::new(IrExpression::Subpiece {
                        low_byte: ByteSize::new(1),
                        size: ByteSize::new(1),
                        arg: Box::new(IrExpression::Var(ir_rax_var.clone())),
                    }),
                }),
            }),
            rhs: Box::new(IrExpression::Subpiece {
                low_byte: ByteSize::new(0),
                size: ByteSize::new(1),
                arg: Box::new(IrExpression::Var(ir_rax_var.clone())),
            }),
        },
    };

    // From: EAX = COPY EDI && RAX = INT_ZEXT EAX
    // To: RAX = INT_ZEXT SUBPIECE(RDI, 0, 4)
    let expected_def_3 = IrDef::Assign {
        var: ir_rax_var.clone(),
        value: IrExpression::Cast {
            op: CastOpType::IntZExt,
            size: ByteSize::new(8),
            arg: Box::new(IrExpression::Subpiece {
                low_byte: ByteSize::new(0),
                size: ByteSize::new(4),
                arg: Box::new(IrExpression::Var(ir_rdi_var.clone())),
            }),
        },
    };

    // From: EAX = PIECE(0:2, AX)
    // To: RAX = PIECE(SUBPIECE(RAX, 4, 4), PIECE(0:2, SUBPIECE(RAX, 0, 2)))
    let expected_def_4 = IrDef::Assign {
        var: ir_rax_var.clone(),
        value: IrExpression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(IrExpression::Subpiece {
                low_byte: ByteSize::new(4),
                size: ByteSize::new(4),
                arg: Box::new(IrExpression::Var(ir_rax_var.clone())),
            }),
            rhs: Box::new(IrExpression::BinOp {
                op: BinOpType::Piece,
                lhs: Box::new(IrExpression::Const(Bitvector::zero(
                    ByteSize::new(2).into(),
                ))),
                rhs: Box::new(IrExpression::Subpiece {
                    low_byte: ByteSize::new(0),
                    size: ByteSize::new(2),
                    arg: Box::new(IrExpression::Var(ir_rax_var.clone())),
                }),
            }),
        },
    };

    // From: AX = SUBPIECE(EDI, 1, 2)
    // To: RAX = PIECE(SUBPIECE(RAX, 2, 6), SUBPIECE(RDI, 1, 2))
    let expected_def_5 = IrDef::Assign {
        var: ir_rax_var.clone(),
        value: IrExpression::BinOp {
            op: BinOpType::Piece,
            lhs: Box::new(IrExpression::Subpiece {
                low_byte: ByteSize::new(2),
                size: ByteSize::new(6),
                arg: Box::new(IrExpression::Var(ir_rax_var.clone())),
            }),
            rhs: Box::new(IrExpression::Subpiece {
                low_byte: ByteSize::new(1),
                size: ByteSize::new(2),
                arg: Box::new(IrExpression::Var(ir_rdi_var.clone())),
            }),
        },
    };

    let mut target_tid = Tid::new("blk_00102016");
    target_tid.address = String::from("00102016");

    // From: CALLIND EAX
    // To: CALLIND SUBPIECE(RAX, 0, 4)
    let expected_jmp = IrJmp::CallInd {
        target: IrExpression::Subpiece {
            low_byte: ByteSize::new(0),
            size: ByteSize::new(4),
            arg: Box::new(IrExpression::Var(ir_rax_var.clone())),
        },
        return_: Some(target_tid.clone()),
    };

    // Checks whether the zero extension was correctly removed; leaving only 5 definitions behind.
    assert_eq!(ir_program.subs[0].term.blocks[0].term.defs.len(), 5);

    // Checks if the other definitions and the jump were correctly casted.
    assert_eq!(
        ir_program.subs[0].term.blocks[0].term.defs[0].term,
        expected_def_0
    );
    assert_eq!(
        ir_program.subs[0].term.blocks[0].term.defs[1].term,
        expected_def_1
    );
    assert_eq!(
        ir_program.subs[0].term.blocks[0].term.defs[2].term,
        expected_def_3
    );
    assert_eq!(
        ir_program.subs[0].term.blocks[0].term.defs[3].term,
        expected_def_4
    );
    assert_eq!(
        ir_program.subs[0].term.blocks[0].term.defs[4].term,
        expected_def_5
    );
    assert_eq!(
        ir_program.subs[0].term.blocks[0].term.jmps[0].term,
        expected_jmp
    );
}
