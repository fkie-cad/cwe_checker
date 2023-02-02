#[cfg(test)]
use super::CastOpType;
use super::*;

/// ## Helper functions for building expressions
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
        if value == 0 {
            return self;
        }
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
