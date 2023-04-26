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
/// Currently supported are: `Var` and `Const` as well as `IntAdd` and `IntSub` of `BinOp`.
/// Supported unary operations are `IntNegate` and `BoolNegate`.
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
///     assert_eq!(expr!("¬(0xFF)"), Expression::UnOp { op: UnOpType::BoolNegate, arg: Box::new(Expression::Const(Bitvector::from_u32(0xFF)))});
///     assert_eq!(expr!("-(0xFF)"), Expression::UnOp { op: UnOpType::IntNegate, arg: Box::new(Expression::Const(Bitvector::from_u32(0xFF)))})
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
        BinOpType, Bitvector, ByteSize, Def, Expression, Term, Tid, UnOpType, Variable,
    };
    use regex::RegexSet;

    /// Parses a Variable defining string slice and returns its corresponding Variable.
    ///
    /// This is used for the `var!` macro, consider the macro documentation for more details.
    #[allow(dead_code)]
    pub fn parse_variable<S: AsRef<str>>(str: S) -> Variable {
        let args: Vec<&str> = str.as_ref().split(':').collect();
        if args.len() != 2 {
            panic!("Could not uniquely parse variable: {}", str.as_ref())
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
    pub fn parse_bitvec<S: AsRef<str>>(str: S) -> Bitvector {
        let args: Vec<&str> = str.as_ref().split(&['x', ':'][..]).collect();
        let value: i128;
        if args.len() == 3 {
            // hex representation
            value = i128::from_str_radix(args[1], 16).unwrap();
        } else if args.len() == 2 {
            // dec representation
            value = args[0].parse().unwrap();
        } else {
            panic!("Could not uniquely parse bitvector: {}", str.as_ref())
        }
        Bitvector::from_i128(value)
            .into_sign_resize(args[args.len() - 1].parse::<usize>().unwrap() * 8)
    }

    /// Parses a Expression defining string slice and returns its corresponding Expression.
    ///
    /// This is used for the `expr!` macro, consider the macro documentation for more details.
    /// Variable names must not start with a number.
    #[allow(dead_code)]
    pub fn parse_expr<S: AsRef<str>>(str: S) -> Expression {
        let set = RegexSet::new([
            r"^[[:alnum:]&&[^0-9]]{1}[[:alnum:]&&[^x]]?[[:alnum:]_]*:[0-9]{1,2}$", // Variable
            r"^((0x(-)?[[:alnum:]]+)|^(-)?([0-9])+)+:[0-9]+$",                     // Constant
            r"^[^\+]*\+{1}[^\+]*$",                                                // BinOp (IntAdd)
            r"^[[:ascii:]]+ \-{1} [[:ascii:]]+$",                                  // BinOp (IntSub)
            r"^-\([[:ascii:]]*\)$", // UnOp (IntNegate)
            r"^¬\([[:ascii:]]*\)$", // UnOp (BoolNegate)
        ])
        .unwrap();
        let result: Vec<usize> = set.matches(str.as_ref()).into_iter().collect();
        if result.len() != 1 {
            panic!("Expression: {} matched Regex: {:#?}", str.as_ref(), result)
        }

        match result[0] {
            0 => Expression::Var(parse_variable(str)),
            1 => Expression::Const(parse_bitvec(str)),
            2 => {
                let args: Vec<&str> = str.as_ref().split('+').collect();
                Expression::BinOp {
                    op: BinOpType::IntAdd,
                    lhs: Box::new(parse_expr(args[0].trim())),
                    rhs: Box::new(parse_expr(args[1].trim())),
                }
            }
            3 => {
                let args: Vec<&str> = str.as_ref().split('-').collect();
                Expression::BinOp {
                    op: BinOpType::IntSub,
                    lhs: Box::new(parse_expr(args[0].trim())),
                    rhs: Box::new(parse_expr(args[1].trim())),
                }
            }
            4 => {
                let arg: &str = str.as_ref().trim_matches(&['-', '(', ')'][..]);
                Expression::UnOp {
                    op: UnOpType::IntNegate,
                    arg: Box::new(parse_expr(arg.trim())),
                }
            }
            5 => {
                let arg: &str = str.as_ref().trim_matches(&['¬', '(', ')'][..]);
                Expression::UnOp {
                    op: UnOpType::BoolNegate,
                    arg: Box::new(parse_expr(arg.trim())),
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
                        address: parse_expr(args[0].trim_start_matches("Store at ").trim()),
                        value: parse_expr(args[1].trim()),
                    },
                }
            }

            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests;
