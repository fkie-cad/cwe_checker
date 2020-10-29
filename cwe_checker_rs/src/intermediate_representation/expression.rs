use super::ByteSize;
use super::Variable;
use crate::prelude::*;

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
        op: BinOpType,
        lhs: Box<Expression>,
        rhs: Box<Expression>,
    },
    /// A unary operation
    UnOp { op: UnOpType, arg: Box<Expression> },
    /// A cast operation for type cast between integer and floating point types of different byte lengths.
    Cast {
        op: CastOpType,
        size: ByteSize,
        arg: Box<Expression>,
    },
    /// An unknown value but with known size.
    /// This may be generated for e.g. unsupported assembly instructions.
    /// Note that computation of an unknown value is still required to be side-effect-free!
    Unknown { description: String, size: ByteSize },
    /// Extracting a sub-bitvector from the argument expression.
    Subpiece {
        low_byte: ByteSize,
        size: ByteSize,
        arg: Box<Expression>,
    },
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

    /// Substitute some trivial expressions with their result.
    /// E.g. substitute `a XOR a` with zero or substitute `a OR a` with `a`.
    pub fn substitute_trivial_operations(&mut self) {
        use Expression::*;
        match self {
            Var(_) | Const(_) | Unknown { .. } => (),
            Subpiece {
                low_byte,
                size,
                arg,
            } => {
                arg.substitute_trivial_operations();
                if *low_byte == ByteSize::new(0) && *size == arg.bytesize() {
                    *self = (**arg).clone();
                }
            }
            Cast { op, size, arg } => {
                arg.substitute_trivial_operations();
                if (*op == CastOpType::IntSExt || *op == CastOpType::IntZExt)
                    && *size == arg.bytesize()
                {
                    *self = (**arg).clone();
                }
            }
            UnOp { op: _, arg } => arg.substitute_trivial_operations(),
            BinOp { op, lhs, rhs } => {
                lhs.substitute_trivial_operations();
                rhs.substitute_trivial_operations();
                if lhs == rhs {
                    match op {
                        BinOpType::BoolAnd
                        | BinOpType::BoolOr
                        | BinOpType::IntAnd
                        | BinOpType::IntOr => {
                            // This is an identity operation
                            *self = (**lhs).clone();
                        }
                        BinOpType::BoolXOr | BinOpType::IntXOr => {
                            // `a xor a` always equals zero.
                            *self = Expression::Const(Bitvector::zero(lhs.bytesize().into()));
                        }
                        BinOpType::IntEqual
                        | BinOpType::IntLessEqual
                        | BinOpType::IntSLessEqual => {
                            *self = Expression::Const(Bitvector::one(ByteSize::new(1).into()));
                        }
                        BinOpType::IntNotEqual | BinOpType::IntLess | BinOpType::IntSLess => {
                            *self = Expression::Const(Bitvector::zero(ByteSize::new(1).into()));
                        }
                        _ => (),
                    }
                }
            }
        }
    }
}

/// The type/mnemonic of a binary operation
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
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CastOpType {
    IntZExt,
    IntSExt,
    Int2Float,
    Float2Float,
    Trunc,
}

/// The type/mnemonic of an unary operation
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trivial_expression_substitution() {
        let mut expr = Expression::BinOp {
            op: BinOpType::IntXOr,
            lhs: Box::new(Expression::Var(Variable {
                name: "RAX".into(),
                size: ByteSize::new(8),
                is_temp: false,
            })),
            rhs: Box::new(Expression::Var(Variable {
                name: "RAX".into(),
                size: ByteSize::new(8),
                is_temp: false,
            })),
        };
        expr.substitute_trivial_operations();
        assert_eq!(
            expr,
            Expression::Const(Bitvector::zero(ByteSize::new(8).into()))
        );
    }
}
