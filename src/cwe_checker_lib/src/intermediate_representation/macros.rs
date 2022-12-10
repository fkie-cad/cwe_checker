//! This module implements macros for an intuitive and condensed construction of intermediate representation elements.
//! [variable!] creates a Variable, [bitvec!] creates a Bitvector, [expr!] creates an Expression, [def!] and [defs!]
//! create `Term<Def>` and Vec<Term<Def>>.

/// Creates a `Variable` specified by the string slice of form `name:size`.
///
/// `size` determines the size in bytes. `is_temp` field is set to `false`.
///
///
/// ## Example
/// ```rust
///     use cwe_checker_lib::intermediate_representation::*;
///     use cwe_checker_lib::variable;
///
///     assert_eq!(variable!("RAX:8"), Variable{ name: "RAX".into(), size: ByteSize::new(8), is_temp: false });
/// ```
#[macro_export]
macro_rules! variable {
    (  $x:expr  ) => {
        parsing::parse_variable($x)
    };
}

/// Creates a `Bitvector` specified by the string slice of form `0xvalue:size` or value:size.
///
/// `value` is either in hexadecimal representation with leading `0x` or in
/// decimal representation. `size` is in bytes.
/// If `value` does not fit in `size`, `value` is truncated.
/// ## Panics
///- string must contain `:`
///- `size` must be one of `1`, `2`, `4` or `8`
///
/// ## Example
/// ```rust
///     use cwe_checker_lib::intermediate_representation::*;
///     use cwe_checker_lib::bitvec;
///
///     assert_eq!(bitvec!("0xFF:4"), Bitvector::from_u32(0xFF));
///     assert_eq!(bitvec!("0x-A:8"), Bitvector::from_i64(-10));
///     assert_eq!(bitvec!("-5:1"), Bitvector::from_i8(-5));
/// ```
#[macro_export]
macro_rules! bitvec {
    (  $x:expr  ) => {
        parsing::parse_bitvec($x)
    };
}

/// Creates an `Expression` specified by the string slice.
///
/// Currently supported are: `Var` and `Const` as well as `IntAdd` of `BinOp`.
/// Does not support `(`, `)` nor chaining of `+`.
/// ## Panics
///- utilizes `variable!` and `bitvec!` macros and their constrains.
///
///
/// ## Example
/// ```rust
///     use cwe_checker_lib::intermediate_representation::*;
///     use cwe_checker_lib::expr;
///
///     assert_eq!(expr!("0xFF:32"), Expression::Const(Bitvector::from_u32(0xFF)));
///     assert_eq!(
///     expr!("RAX:8"),
///     Expression::Var(Variable {name: "RAX".into(), size: ByteSize::new(8),is_temp: false})
///     );
///
///     assert_eq!(
///     expr!("RAX:8 + 0x42:8"),
///     Expression::BinOp { op: BinOpType::IntAdd,
///         lhs: Box::new(Expression::Var(Variable { name: "RAX".into(), size: ByteSize::new(8), is_temp: false })),
///         rhs: Box::new(Expression::Const(Bitvector::from_u8(0x42)))}
///     );
/// ```
#[macro_export]
macro_rules! expr {
    (  $x:expr  ) => {
        parsing::parse_expr($x)
    };
}

/// Creates a `Vec<Term<Def>>` specified by the string slices. Utilizes `variable!`, `bitvec!` and `expr!` macros and their constrains.
///
/// Tid IDs are optionally prefixed by `tid_name: `. If not, `tid_x` is set as Tid ID with incrementing `x` starting by `0`.
/// ## Syntax
/// Load: `var := Load from expr`, with a Variable `var` according to `variable!` macro and and expression `expr` according to `expr!` macro.
///
/// Store: `Store at expr_a := expr_b` with Expressions `expr_a` and `expr_b` according to `expr!` macro.
///
/// Assign: `var = expr` with a Variable `var` according to `var!` macro and an Expression `expr` according to `expr!` macro.
/// ## Example
/// ```rust
///     use cwe_checker_lib::intermediate_representation::*;
///     use cwe_checker_lib::def;
///
///     defs!["tid_x: Store at RSP:8 + 0x8:8 := RAX:8", "RSP:8 = RSP:8 + 0x8:8", "tid_z: RDI:8 := Load from RSP:8"];
/// ```
#[macro_export]
macro_rules! defs {
    [$($x:expr),*] => {{
        let mut vec = vec![];
        let mut _tid_suffix: u8 = 0;
        $(
            vec.push(parsing::parse_def($x, _tid_suffix));
            _tid_suffix += 1;
        )*
        vec}

    };
}

/// Creates a `Term<Def>` specified by the string slices. Utilizes `variable!`, `bitvec!` and `expr!` macros and their constrains.
///
/// Tid ID is optionally prefixed by `tid_name: `. If not, Tid ID `tid_0` is set.
/// ## Syntax
/// Load: `var := Load from expr`, with a Variable `var` according to `variable!` macro and and expression `expr` according to `expr!` macro.
///
/// Store: `Store at expr_a := expr_b` with Expressions `expr_a` and `expr_b` according to `expr!` macro.
///
/// Assign: `var = expr` with a Variable `var` according to `var!` macro and an Expression `expr` according to `expr!` macro.
/// ## Example
/// ```rust
///     use cwe_checker_lib::intermediate_representation::*;
///     use cwe_checker_lib::def;
///
///     def!["tid_x: Store at RSP:8 + 0x8:8 := RAX:8"];
///     def!["RSP:8 = RSP:8 + 0x8:8"];
/// ```
#[macro_export]
macro_rules! def {
    ($x:expr) => {
        parsing::parse_def($x, 0)
    };
}

pub mod parsing {
    //! Provides parsing functions for the macros defined in `macros.rs`.
    //! This module hides the parsing functions and allows exposure of the macros only.
    use crate::intermediate_representation::{
        BinOpType, Bitvector, ByteSize, Def, Expression, Term, Tid, Variable,
    };
    use regex::RegexSet;

    /// Parses a Variable defining string slice and returns its corresponding Variable.
    ///
    /// This is used for the `var!` macro, consider the macro documentation for more details.
    #[allow(dead_code)]
    pub fn parse_variable(str: &str) -> Variable {
        let args: Vec<&str> = str.split(':').collect();
        if args.len() != 2 {
            panic!("Could not uniquely parse variable: {}", str)
        }

        let (name, size) = (args[0], args[1]);
        Variable {
            name: name.to_string(),
            size: ByteSize(size.parse().unwrap()),
            is_temp: false,
        }
    }

    /// Parses a Bitvector defining string slice and returns its corresponding Bitvector.
    ///
    /// This is used for the `bitvec!` macro, consider the macro documentation for more details.
    #[allow(dead_code)]
    pub fn parse_bitvec(str: &str) -> Bitvector {
        let args: Vec<&str> = str.split(&['x', ':'][..]).collect();
        let value: i64;
        if args.len() == 3 {
            // hex representation
            value = i64::from_str_radix(args[1], 16).unwrap();
        } else if args.len() == 2 {
            // dec representation
            value = args[0].parse().unwrap();
        } else {
            panic!("Could not uniquely parse bitvector: {}", str)
        }
        Bitvector::from_i64(value)
            .into_sign_resize(args[args.len() - 1].parse::<usize>().unwrap() * 8)
    }

    /// Parses a Expression defining string slice and returns its corresponding Expression.
    ///
    /// This is used for the `expr!` macro, consider the macro documentation for more details.
    #[allow(dead_code)]
    pub fn parse_expr(str: &str) -> Expression {
        let set = RegexSet::new([
            r"^[[:alnum:]&&[^0]]{1}[[:alnum:]&&[^x]]?[[:alnum:]]*:[0-9]{1,2}$", // Variable
            r"^^((0x[[:alnum:]]+)|^([0-9])+)+:[0-9]+$",                         // Constant
            r"^[^\+]*\+{1}[^\+]*$",                                             // BinOp (IntAdd)
            r"^[^\-]*\-{1}[^\-]*$",                                             // BinOp (IntSub)
        ])
        .unwrap();
        let result: Vec<usize> = set.matches(str).into_iter().collect();
        if result.len() != 1 {
            panic!("Expression: {} matched Regex: {:#?}", str, result)
        }

        match result[0] {
            0 => Expression::Var(parse_variable(str)),
            1 => Expression::Const(parse_bitvec(str)),
            2 => {
                let args: Vec<&str> = str.split('+').collect();
                Expression::BinOp {
                    op: BinOpType::IntAdd,
                    lhs: Box::new(parse_expr(args[0].trim())),
                    rhs: Box::new(parse_expr(args[1].trim())),
                }
            }
            3 => {
                let args: Vec<&str> = str.split('-').collect();
                Expression::BinOp {
                    op: BinOpType::IntSub,
                    lhs: Box::new(parse_expr(args[0].trim())),
                    rhs: Box::new(parse_expr(args[1].trim())),
                }
            }
            _ => panic!(),
        }
    }

    /// Parses a `Term<Def>` defining string slice and returns its corresponding `Term<Def>`.
    ///
    /// This is used for the `def!` and `defs!` macro, consider the macro documentation for more details.
    #[allow(dead_code)]
    pub fn parse_def<S: AsRef<str>>(str: S, tid_suffix: u8) -> Term<Def> {
        let set = RegexSet::new([
            r"^[[:ascii:]]+: [[:alnum:]:]* = ", // Assign with tid
            r"^[[:alnum:]:]* = ",               // Assign without tid
            r"^[[:ascii:]]+: [[:alnum:]:]* := Load from [[:ascii:]:]*$", // Load with tid
            r"^[[:alnum:]:]* := Load from [[:ascii:]:]*$", // Load without tid
            r"^[[:ascii:]]+: Store at [[:ascii:]:]* := ", // Store with tid
            r"^Store at [[:ascii:]:]* := ",     // Store without tid
        ])
        .unwrap();
        let result: Vec<usize> = set.matches(str.as_ref()).into_iter().collect();
        if result.len() != 1 {
            panic!("Def: {} matched Regex: {:#?}", str.as_ref(), result)
        }
        let (tid, def): (String, &str) = match result[0] {
            0 | 2 | 4 => {
                // tid is specified
                let (tid, def) = str.as_ref().split_once(": ").unwrap();
                (tid.into(), def)
            }
            _ => (format!("tid_{}", tid_suffix), str.as_ref()), // unspecified tid
        };

        match result[0] {
            0 | 1 => {
                // Assign
                let args: Vec<&str> = def.split('=').collect();
                Term {
                    tid: Tid::new(tid),
                    term: Def::Assign {
                        var: parse_variable(args[0].trim()),
                        value: parse_expr(args[1].trim()),
                    },
                }
            }
            2 | 3 => {
                // Load
                let args: Vec<&str> = def.split(":= Load from").collect();
                Term {
                    tid: Tid::new(tid),
                    term: Def::Load {
                        var: parse_variable(args[0].trim()),
                        address: parse_expr(args[1].trim()),
                    },
                }
            }
            4 | 5 => {
                // Store
                let args: Vec<&str> = def.split(":=").collect();
                Term {
                    tid: Tid::new(tid),
                    term: Def::Store {
                        address: parse_expr(args[0].trim_start_matches("Store at ")),
                        value: parse_expr(args[1].trim()),
                    },
                }
            }

            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::intermediate_representation::*;

    #[test]
    fn test_var() {
        assert_eq!(
            variable!("RAX:8"),
            Variable {
                name: "RAX".to_string(),
                size: ByteSize(8),
                is_temp: false
            }
        );
    }
    #[test]
    #[should_panic]
    fn var_empty_panics() {
        variable!("");
    }
    #[test]
    #[should_panic]
    fn var_no_colon_panics() {
        variable!("RAX8");
    }

    #[test]
    #[should_panic]
    fn var_no_size_panics() {
        variable!("RAX:");
    }

    #[test]
    fn test_bitvec() {
        assert_eq!(bitvec!("0x42:1"), Bitvector::from_u8(0x42));
        assert_eq!(bitvec!("0xFF:2"), Bitvector::from_u16(0xFF));
        assert_eq!(bitvec!("0xAAFF:1"), Bitvector::from_u8(0xFF));
        assert_eq!(bitvec!("0x-01:1"), Bitvector::from_i8(-1));
        assert_eq!(bitvec!("123:4"), Bitvector::from_u32(123));
        assert_eq!(bitvec!("-42:8"), Bitvector::from_i64(-42));
    }

    #[test]
    fn test_expr_var() {
        assert_eq!(
            expr!("RAX:8"),
            Expression::Var(Variable {
                name: "RAX".into(),
                size: ByteSize(8),
                is_temp: false
            })
        );
    }
    #[test]
    fn test_expr_const() {
        assert_eq!(
            expr!("0x42:8"),
            Expression::Const(Bitvector::from_u64(0x42))
        );
        assert_eq!(
            expr!("0xFFFF:1"),
            Expression::Const(Bitvector::from_u8(255))
        );
    }
    #[test]
    fn test_expr_plus() {
        assert_eq!(
            expr!("RAX:8 + 0x42:8"),
            Expression::BinOp {
                op: BinOpType::IntAdd,
                lhs: Box::new(Expression::Var(Variable {
                    name: "RAX".into(),
                    size: ByteSize(8),
                    is_temp: false
                })),
                rhs: Box::new(Expression::Const(Bitvector::from_u64(0x42)))
            }
        );
    }
    #[test]
    fn test_expr_minus() {
        assert_eq!(
            expr!("RAX:8 - 0x42:8"),
            Expression::BinOp {
                op: BinOpType::IntSub,
                lhs: Box::new(Expression::Var(Variable {
                    name: "RAX".into(),
                    size: ByteSize(8),
                    is_temp: false
                })),
                rhs: Box::new(Expression::Const(Bitvector::from_u64(0x42)))
            }
        );
    }
    #[test]
    fn test_def_tid() {
        let defs = defs![
            "RDI:8 = RAX:8 + RBP:8",
            "A: RAX:8 = 0x42:1",
            "RDX:8 = RAX:8 + RBP:8"
        ];
        assert_eq!(
            defs.into_iter()
                .map(|x| x.tid.to_string())
                .collect::<Vec<String>>(),
            ["tid_0", "A", "tid_2"]
        )
    }
    #[test]
    fn test_defs_assign() {
        assert_eq!(
            defs!["tid_0: RAX:8 = 0x42:1", "tid_1: RDI:8 = RAX:8 + RBP:8"],
            vec![
                Term {
                    tid: Tid::new("tid_0"),
                    term: Def::Assign {
                        var: Variable {
                            name: "RAX".into(),
                            size: ByteSize(8),
                            is_temp: false
                        },
                        value: Expression::Const(Bitvector::from_i8(0x42))
                    }
                },
                Term {
                    tid: Tid::new("tid_1"),
                    term: Def::Assign {
                        var: Variable {
                            name: "RDI".into(),
                            size: ByteSize(8),
                            is_temp: false
                        },
                        value: Expression::BinOp {
                            op: BinOpType::IntAdd,
                            lhs: Box::new(Expression::Var(Variable {
                                name: "RAX".into(),
                                size: ByteSize(8),
                                is_temp: false
                            })),
                            rhs: Box::new(Expression::Var(Variable {
                                name: "RBP".into(),
                                size: ByteSize(8),
                                is_temp: false
                            }))
                        }
                    }
                }
            ]
        );
    }

    #[test]
    fn test_defs_store() {
        assert_eq!(
            defs!["tid: Store at RSP:8 - 0x8:1 := 0x42:1"],
            vec![Term {
                tid: Tid::new("tid"),
                term: Def::Store {
                    address: Expression::BinOp {
                        op: BinOpType::IntSub,
                        lhs: Box::new(Expression::Var(Variable {
                            name: "RSP".into(),
                            size: ByteSize(8),
                            is_temp: false
                        })),
                        rhs: Box::new(Expression::Const(Bitvector::from_u8(0x8)))
                    },
                    value: Expression::Const(Bitvector::from_u8(0x42))
                }
            }]
        )
    }

    #[test]
    fn test_defs_load() {
        assert_eq!(
            defs!["tid_a: RAX:8 := Load from 0xFF00:4 + 0x08:4"],
            vec![Term {
                tid: Tid::new("tid_a"),
                term: Def::Load {
                    var: Variable {
                        name: "RAX".into(),
                        size: ByteSize(8),
                        is_temp: false
                    },
                    address: Expression::BinOp {
                        op: BinOpType::IntAdd,
                        lhs: Box::new(Expression::Const(Bitvector::from_u32(0xFF00))),
                        rhs: Box::new(Expression::Const(Bitvector::from_u32(0x08)))
                    }
                }
            }]
        )
    }

    #[test]
    fn test_defs_composition() {
        assert_eq!(
            defs![
                "tid_a: Store at RSP:8 + 0x8:1 := RAX:8",
                "tid_b: RSP:8 = RSP:8 + 0x8:1",
                "tid_c: RDI:8 := Load from RSP:8"
            ],
            vec![
                Term {
                    tid: Tid::new("tid_a"),
                    term: Def::Store {
                        address: Expression::BinOp {
                            op: BinOpType::IntAdd,
                            lhs: Box::new(Expression::Var(Variable {
                                name: "RSP".into(),
                                size: ByteSize(8),
                                is_temp: false
                            })),
                            rhs: Box::new(Expression::Const(Bitvector::from_u8(0x08)))
                        },
                        value: Expression::Var(Variable {
                            name: "RAX".into(),
                            size: ByteSize(8),
                            is_temp: false
                        })
                    }
                },
                Term {
                    tid: Tid::new("tid_b"),
                    term: Def::Assign {
                        var: Variable {
                            name: "RSP".into(),
                            size: ByteSize(8),
                            is_temp: false
                        },
                        value: Expression::BinOp {
                            op: BinOpType::IntAdd,
                            lhs: Box::new(Expression::Var(Variable {
                                name: "RSP".into(),
                                size: ByteSize(8),
                                is_temp: false
                            })),
                            rhs: Box::new(Expression::Const(Bitvector::from_u8(0x08)))
                        }
                    }
                },
                Term {
                    tid: Tid::new("tid_c"),
                    term: Def::Load {
                        var: Variable {
                            name: "RDI".into(),
                            size: ByteSize(8),
                            is_temp: false
                        },
                        address: Expression::Var(Variable {
                            name: "RSP".into(),
                            size: ByteSize(8),
                            is_temp: false
                        })
                    }
                }
            ]
        )
    }
}
