use super::*;

/// ## Helper functions for building expressions
impl Expression {
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
