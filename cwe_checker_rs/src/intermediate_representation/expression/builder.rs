use apint::ApInt;

use super::{BinOpType, CastOpType, Expression, Variable};
use crate::prelude::*;

/// ## Helper functions for building expressions
impl Expression {
    // Shortcut for creating a constant expression from an i64 value
    pub fn const_from_i64(value: i64) -> Expression {
        Expression::Const(Bitvector::from_i64(value))
    }

    // Shortcut for creating a constant expression from an apint value (e.g. copy of global address)
    pub fn const_from_apint(value: ApInt) -> Expression {
        Expression::Const(value)
    }

    // Shortcut for creating a variable expression
    pub fn var(name: &str) -> Expression {
        Expression::Var(Variable {
            name: name.into(),
            size: ByteSize::new(8),
            is_temp: false,
        })
    }

    // Shortcut for creating a cast expression
    pub fn cast(self, op: CastOpType) -> Expression {
        Expression::Cast {
            op,
            size: ByteSize::new(8),
            arg: Box::new(self),
        }
    }

    // Shortcut for creating a subpiece expression
    pub fn subpiece(self, low_byte: ByteSize, size: ByteSize) -> Expression {
        Expression::Subpiece {
            low_byte,
            size,
            arg: Box::new(self),
        }
    }

    /// Shortcut for creating an `IntAdd`-expression
    pub fn plus(self, rhs: Expression) -> Expression {
        Expression::BinOp {
            lhs: Box::new(self),
            op: BinOpType::IntAdd,
            rhs: Box::new(rhs),
        }
    }

    /// Construct an expression that adds a constant value to the given expression.
    ///
    /// The bytesize of the value is automatically adjusted to the bytesize of the given expression.
    pub fn plus_const(self, value: i64) -> Expression {
        let bytesize = self.bytesize();
        let mut value = Bitvector::from_i64(value);
        match u64::from(bytesize) {
            size if size > 8 => value.sign_extend(bytesize).unwrap(),
            size if size < 8 => value.truncate(bytesize).unwrap(),
            _ => (),
        }
        self.plus(Expression::Const(value))
    }
}
