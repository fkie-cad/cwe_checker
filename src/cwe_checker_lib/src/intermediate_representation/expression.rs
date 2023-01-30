use std::fmt::{self, Debug};

use super::ByteSize;
use super::Variable;
use crate::prelude::*;

mod builder;
mod trivial_operation_substitution;

/// An expression is a calculation rule
/// on how to compute a certain value given some variables (register values) as input.
///
/// The basic building blocks of expressions are the same as for Ghidra P-Code.
/// However, expressions can be nested, unlike original P-Code.
///
/// Computing the value of an expression is a side-effect-free operation.
///
/// Expressions are typed in the sense that each expression has a `ByteSize`
/// indicating the size of the result when evaluating the expression.
/// Some expressions impose restrictions on the sizes of their inputs
/// for the expression to be well-typed.
///
/// All operations are defined the same as the corresponding P-Code operation.
/// Further information about specific operations can be obtained by looking up the P-Code mnemonics in the
/// [P-Code Reference Manual](https://ghidra.re/courses/languages/html/pcoderef.html).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Expression {
    /// A variable representing a register or temporary value of known size.
    Var(Variable),
    /// A constant value represented by a bitvector.
    Const(Bitvector),
    /// A binary operation.
    /// Note that most (but not all) operations require the left hand side (`lhs`)
    /// and right hand side (`rhs`) to be of equal size.
    BinOp {
        /// The opcode/type of the operation
        op: BinOpType,
        /// The left hand side expression
        lhs: Box<Expression>,
        /// The right hand side expression
        rhs: Box<Expression>,
    },
    /// A unary operation
    UnOp {
        /// The opcode/type of the operation
        op: UnOpType,
        /// The argument expression
        arg: Box<Expression>,
    },
    /// A cast operation for type cast between integer and floating point types of different byte lengths.
    Cast {
        /// The opcode/type of the cast operation
        op: CastOpType,
        /// The byte size of the result value of the expresion
        size: ByteSize,
        /// The argument of the expression
        arg: Box<Expression>,
    },
    /// An unknown value but with known size.
    /// This may be generated for e.g. unsupported assembly instructions.
    /// Note that computation of an unknown value is still required to be side-effect-free!
    Unknown {
        /// A description of the operation
        description: String,
        /// The byte size of the result of the unknown expression
        size: ByteSize,
    },
    /// Extracting a sub-bitvector from the argument expression.
    Subpiece {
        /// The lowest byte (i.e. least significant byte if interpreted as integer) of the sub-bitvector to extract.
        low_byte: ByteSize,
        /// The size of the resulting sub-bitvector
        size: ByteSize,
        /// The argument from which to extract the bitvector from.
        arg: Box<Expression>,
    },
}

/// The type/mnemonic of a binary operation.
/// See the Ghidra P-Code documentation for more information.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum BinOpType {
    Piece,
    IntEqual,
    IntNotEqual,
    IntLess,
    IntSLess,
    IntLessEqual,
    IntSLessEqual,
    IntAdd,
    IntSub,
    IntCarry,
    IntSCarry,
    IntSBorrow,
    IntXOr,
    IntAnd,
    IntOr,
    IntLeft,
    IntRight,
    IntSRight,
    IntMult,
    IntDiv,
    IntRem,
    IntSDiv,
    IntSRem,
    BoolXOr,
    BoolAnd,
    BoolOr,
    FloatEqual,
    FloatNotEqual,
    FloatLess,
    FloatLessEqual,
    FloatAdd,
    FloatSub,
    FloatMult,
    FloatDiv,
}

/// The type/mnemonic of a typecast
/// See the Ghidra P-Code documentation for more information.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CastOpType {
    IntZExt,
    IntSExt,
    Int2Float,
    Float2Float,
    Trunc,
    PopCount,
}

/// The type/mnemonic of an unary operation
/// See the Ghidra P-Code documentation for more information.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum UnOpType {
    IntNegate,
    Int2Comp,
    BoolNegate,
    FloatNegate,
    FloatAbs,
    FloatSqrt,
    FloatCeil,
    FloatFloor,
    FloatRound,
    FloatNaN,
}

impl Expression {
    /// Return the size (in bytes) of the result value of the expression.
    pub fn bytesize(&self) -> ByteSize {
        use BinOpType::*;
        use Expression::*;
        match self {
            Var(var) => var.size,
            Const(bitvec) => bitvec.width().into(),
            BinOp { op, lhs, rhs } => match op {
                Piece => lhs.bytesize() + rhs.bytesize(),
                IntEqual | IntNotEqual | IntLess | IntSLess | IntLessEqual | IntSLessEqual
                | IntCarry | IntSCarry | IntSBorrow | BoolXOr | BoolOr | BoolAnd | FloatEqual
                | FloatNotEqual | FloatLess | FloatLessEqual => ByteSize::new(1),
                IntAdd | IntSub | IntAnd | IntOr | IntXOr | IntLeft | IntRight | IntSRight
                | IntMult | IntDiv | IntRem | IntSDiv | IntSRem | FloatAdd | FloatSub
                | FloatMult | FloatDiv => lhs.bytesize(),
            },
            UnOp { op, arg } => match op {
                UnOpType::FloatNaN => ByteSize::new(1),
                _ => arg.bytesize(),
            },
            Cast { size, .. } | Unknown { size, .. } | Subpiece { size, .. } => *size,
        }
    }

    /// Return an array of all input variables of the given expression.
    /// The array may contain duplicates.
    pub fn input_vars(&self) -> Vec<&Variable> {
        use Expression::*;
        match self {
            Var(var) => vec![var],
            Const(_) | Unknown { .. } => Vec::new(),
            BinOp { op: _, lhs, rhs } => {
                let mut vars = lhs.input_vars();
                vars.append(&mut rhs.input_vars());
                vars
            }
            UnOp { arg, .. } | Cast { arg, .. } | Subpiece { arg, .. } => arg.input_vars(),
        }
    }

    /// Substitute every occurrence of `input_var` in `self` with the given `replace_with_expression`.
    pub fn substitute_input_var(
        &mut self,
        input_var: &Variable,
        replace_with_expression: &Expression,
    ) {
        use Expression::*;
        match self {
            Const(_) | Unknown { .. } => (),
            Var(var) if var == input_var => *self = replace_with_expression.clone(),
            Var(_) => (),
            Subpiece { arg, .. } | Cast { arg, .. } | UnOp { arg, .. } => {
                arg.substitute_input_var(input_var, replace_with_expression);
            }
            BinOp { lhs, rhs, .. } => {
                lhs.substitute_input_var(input_var, replace_with_expression);
                rhs.substitute_input_var(input_var, replace_with_expression);
            }
        }
    }
}

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expression::Var(var) => write!(f, "{var}"),
            Expression::Const(c) => {
                write!(f, "0x{:016x}:{}", c, c.bytesize())
            }
            Expression::BinOp { op, lhs, rhs } => match op {
                BinOpType::IntMult
                | BinOpType::IntDiv
                | BinOpType::IntRem
                | BinOpType::FloatMult
                | BinOpType::FloatDiv => write!(f, "{lhs} {op} {rhs}"),
                _ => write!(f, "({lhs} {op} {rhs})"),
            },
            Expression::UnOp { op, arg } => write!(f, "{op}({arg})"),
            Expression::Cast { op, size: _, arg } => write!(f, "{op}({arg})"),
            Expression::Unknown {
                description,
                size: _,
            } => write!(f, "{description}"),
            Expression::Subpiece {
                low_byte,
                size,
                arg,
            } => {
                write!(f, "({})[{}-{}]", arg, low_byte.0, low_byte.0 + size.0 - 1)
            }
        }
    }
}

impl fmt::Display for BinOpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinOpType::IntEqual => write!(f, "=="),
            BinOpType::IntNotEqual => write!(f, "!="),
            BinOpType::IntLess => write!(f, "<"),
            BinOpType::IntSLess => write!(f, "<"),
            BinOpType::IntLessEqual => write!(f, "<="),
            BinOpType::IntSLessEqual => write!(f, "<="),
            BinOpType::IntAdd => write!(f, "+"),
            BinOpType::IntSub => write!(f, "-"),
            BinOpType::IntXOr => write!(f, "^"),
            BinOpType::IntAnd => write!(f, "&"),
            BinOpType::IntOr => write!(f, "|"),
            BinOpType::IntLeft => write!(f, "<<"),
            BinOpType::IntRight => write!(f, ">>"),
            BinOpType::IntMult => write!(f, "*"),
            BinOpType::IntDiv => write!(f, "/"),
            BinOpType::IntRem => write!(f, "%"),
            BinOpType::BoolAnd => write!(f, "&&"),
            BinOpType::BoolOr => write!(f, "||"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl fmt::Display for UnOpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnOpType::BoolNegate => write!(f, "¬"),
            UnOpType::IntNegate => write!(f, "-"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl fmt::Display for CastOpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
#[cfg(test)]
mod tests;
