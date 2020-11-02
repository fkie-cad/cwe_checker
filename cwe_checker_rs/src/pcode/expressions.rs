use super::Def;
use crate::intermediate_representation::BinOpType as IrBinOpType;
use crate::intermediate_representation::ByteSize;
use crate::intermediate_representation::CastOpType as IrCastOpType;
use crate::intermediate_representation::Expression as IrExpression;
use crate::intermediate_representation::UnOpType as IrUnOpType;
use crate::intermediate_representation::Variable as IrVariable;
use crate::prelude::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Variable {
    pub name: Option<String>,
    pub value: Option<String>,
    pub address: Option<String>,
    pub size: ByteSize,
    pub is_virtual: bool,
}

impl From<Variable> for IrVariable {
    /// Translate a P-Code variable into a register variable of the internally used IR.
    /// Panic if the variable does not represent a register.
    fn from(pcode_var: Variable) -> IrVariable {
        IrVariable {
            name: pcode_var.name.unwrap(),
            size: pcode_var.size,
            is_temp: pcode_var.is_virtual, // TODO: rename `pcode_var.is_virtual` to `is_temp`
        }
    }
}

impl From<Variable> for IrExpression {
    /// Translate a P-Code variable into a `Var`or `Const` expression of the internally used IR.
    /// Panics if the translation fails.
    fn from(pcode_var: Variable) -> IrExpression {
        match (&pcode_var.name, &pcode_var.value) {
            (Some(_name), None) => IrExpression::Var(pcode_var.into()),
            (None, Some(_hex_value)) => IrExpression::Const(pcode_var.parse_to_bitvector()),
            _ => panic!("Conversion failed:\n{:?}", pcode_var),
        }
    }
}

impl Variable {
    /// Parses a variable representing a concrete value or a concrete address to a bitvector containing the value or address.
    pub fn parse_to_bitvector(&self) -> Bitvector {
        match (&self.value, &self.address) {
            (Some(hex_value), None) | (None, Some(hex_value)) => {
                // TODO: Implement parsing for large hex values.
                if u64::from(self.size) > 8 {
                    panic!(
                        "Parsing of immediates greater than 8 bytes not yet implemented: {}",
                        hex_value
                    );
                }
                let val: u64 = u64::from_str_radix(&hex_value, 16).unwrap();
                let mut bitvector: Bitvector = Bitvector::from_u64(val);
                bitvector.truncate(self.size).unwrap();
                bitvector
            }
            _ => panic!(),
        }
    }

    /// Generate a virtual variable with the given name and size.
    pub fn new_virtual(name: impl Into<String>, size: ByteSize) -> Variable {
        Variable {
            name: Some(name.into()),
            value: None,
            address: None,
            size,
            is_virtual: true,
        }
    }

    /// Generate a variable representing a constant
    pub fn new_const(value_string: impl Into<String>, size: ByteSize) -> Variable {
        Variable {
            name: None,
            value: Some(value_string.into()),
            address: None,
            size,
            is_virtual: false,
        }
    }

    /// Create a LOAD instruction out of a variable representing a load from a constant address into a virtual register.
    ///
    /// Note that the address pointer size gets set to zero, since the function does not know the correct size for pointers.
    pub fn to_load_def(&self, target_register_name: impl Into<String>) -> Def {
        Def {
            lhs: Some(Variable::new_virtual(target_register_name, self.size)),
            rhs: Expression {
                mnemonic: ExpressionType::LOAD,
                input0: None,
                input1: Some(Variable::new_const(
                    self.address.as_ref().unwrap(),
                    ByteSize::from(0 as u64), // We do not know the correct pointer size here.
                )),
                input2: None,
            },
        }
    }

    /// Translates a variable into the byte size that it represents. Panics on error.
    pub fn parse_to_bytesize(self) -> ByteSize {
        match (&self.name, &self.value) {
            (None, Some(hex_value)) => {
                assert!(u64::from(self.size) <= 8);
                let val: u64 = u64::from_str_radix(&hex_value, 16).unwrap();
                val.into()
            }
            _ => panic!(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Expression {
    pub mnemonic: ExpressionType,
    pub input0: Option<Variable>,
    pub input1: Option<Variable>,
    pub input2: Option<Variable>,
}

impl From<Expression> for IrExpression {
    /// Translates a P-Code expression into an expression of the internally used IR if possible.
    /// Panics if translation is not possible.
    ///
    /// Cases where translation is not possible:
    /// - `LOAD` and `STORE`, since these are not expressions (they have side effects).
    /// - Expressions which store the size of their output in the output variable (to which we do not have access here).
    /// These include `SUBPIECE`, `INT_ZEXT`, `INT_SEXT`, `INT2FLOAT`, `FLOAT2FLOAT` and `TRUNC`.
    /// Translation of these expressions is handled explicitly during translation of `Def`.
    fn from(expr: Expression) -> IrExpression {
        use ExpressionType::*;
        match expr.mnemonic {
            COPY => expr.input0.unwrap().into(),
            LOAD | STORE | SUBPIECE => panic!(),
            PIECE | INT_EQUAL | INT_NOTEQUAL | INT_LESS | INT_SLESS | INT_LESSEQUAL
            | INT_SLESSEQUAL | INT_ADD | INT_SUB | INT_CARRY | INT_SCARRY | INT_SBORROW
            | INT_XOR | INT_AND | INT_OR | INT_LEFT | INT_RIGHT | INT_SRIGHT | INT_MULT
            | INT_DIV | INT_REM | INT_SDIV | INT_SREM | BOOL_XOR | BOOL_AND | BOOL_OR
            | FLOAT_EQUAL | FLOAT_NOTEQUAL | FLOAT_LESS | FLOAT_LESSEQUAL | FLOAT_ADD
            | FLOAT_SUB | FLOAT_MULT | FLOAT_DIV => IrExpression::BinOp {
                op: expr.mnemonic.into(),
                lhs: Box::new(expr.input0.unwrap().into()),
                rhs: Box::new(expr.input1.unwrap().into()),
            },
            INT_NEGATE | INT_2COMP | BOOL_NEGATE | FLOAT_NEG | FLOAT_ABS | FLOAT_SQRT
            | FLOAT_CEIL | FLOAT_FLOOR | FLOAT_ROUND | FLOAT_NAN => IrExpression::UnOp {
                op: expr.mnemonic.into(),
                arg: Box::new(expr.input0.unwrap().into()),
            },
            INT_ZEXT | INT_SEXT | INT2FLOAT | FLOAT2FLOAT | TRUNC => panic!(),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ExpressionType {
    COPY,
    LOAD,
    STORE,
    PIECE,
    SUBPIECE,

    INT_EQUAL,
    INT_NOTEQUAL,
    INT_LESS,
    INT_SLESS,
    INT_LESSEQUAL,
    INT_SLESSEQUAL,

    INT_ADD,
    INT_SUB,
    INT_CARRY,
    INT_SCARRY,
    INT_SBORROW,

    INT_XOR,
    INT_AND,
    INT_OR,

    INT_LEFT,
    INT_RIGHT,
    INT_SRIGHT,

    INT_MULT,
    INT_DIV,
    INT_REM,
    INT_SDIV,
    INT_SREM,

    BOOL_XOR,
    BOOL_AND,
    BOOL_OR,

    FLOAT_EQUAL,
    FLOAT_NOTEQUAL,
    FLOAT_LESS,
    FLOAT_LESSEQUAL,

    FLOAT_ADD,
    FLOAT_SUB,
    FLOAT_MULT,
    FLOAT_DIV,

    INT_NEGATE,
    INT_2COMP,
    BOOL_NEGATE,

    FLOAT_NEG,
    FLOAT_ABS,
    FLOAT_SQRT,
    FLOAT_CEIL,
    FLOAT_FLOOR,
    FLOAT_ROUND,
    FLOAT_NAN,

    INT_ZEXT,
    INT_SEXT,
    INT2FLOAT,
    FLOAT2FLOAT,
    TRUNC,
}

impl From<ExpressionType> for IrBinOpType {
    /// Translates expression types.
    /// Panics when given a type not representable by the target type.
    fn from(expr_type: ExpressionType) -> IrBinOpType {
        use ExpressionType::*;
        use IrBinOpType::*;
        match expr_type {
            PIECE => IrBinOpType::Piece,
            INT_EQUAL => IrBinOpType::IntEqual,
            INT_NOTEQUAL => IrBinOpType::IntNotEqual,
            INT_LESS => IrBinOpType::IntLess,
            INT_SLESS => IrBinOpType::IntSLess,
            INT_LESSEQUAL => IntLessEqual,
            INT_SLESSEQUAL => IntSLessEqual,

            INT_ADD => IrBinOpType::IntAdd,
            INT_SUB => IrBinOpType::IntSub,

            INT_CARRY => IrBinOpType::IntCarry,
            INT_SCARRY => IrBinOpType::IntSCarry,
            INT_SBORROW => IrBinOpType::IntSBorrow,
            INT_XOR => IrBinOpType::IntXOr,
            INT_AND => IrBinOpType::IntAnd,
            INT_OR => IrBinOpType::IntOr,

            INT_LEFT => IrBinOpType::IntLeft,
            INT_RIGHT => IrBinOpType::IntRight,
            INT_SRIGHT => IrBinOpType::IntSRight,
            INT_MULT => IrBinOpType::IntMult,
            INT_DIV => IrBinOpType::IntDiv,

            INT_REM => IrBinOpType::IntRem,
            INT_SDIV => IrBinOpType::IntSDiv,
            INT_SREM => IrBinOpType::IntSRem,
            BOOL_XOR => IrBinOpType::BoolXOr,
            BOOL_AND => IrBinOpType::BoolAnd,

            BOOL_OR => IrBinOpType::BoolOr,
            FLOAT_EQUAL => IrBinOpType::FloatEqual,
            FLOAT_NOTEQUAL => IrBinOpType::FloatNotEqual,
            FLOAT_LESS => IrBinOpType::FloatLess,
            FLOAT_LESSEQUAL => IrBinOpType::FloatLessEqual,

            FLOAT_ADD => IrBinOpType::FloatAdd,
            FLOAT_SUB => IrBinOpType::FloatSub,
            FLOAT_MULT => IrBinOpType::FloatMult,
            FLOAT_DIV => IrBinOpType::FloatDiv,

            _ => panic!(),
        }
    }
}

impl From<ExpressionType> for IrUnOpType {
    /// Translates expression types.
    /// Panics when given a type not representable by the target type.
    fn from(expr_type: ExpressionType) -> IrUnOpType {
        use ExpressionType::*;
        match expr_type {
            INT_NEGATE => IrUnOpType::IntNegate,
            INT_2COMP => IrUnOpType::Int2Comp,
            BOOL_NEGATE => IrUnOpType::BoolNegate,
            FLOAT_NEG => IrUnOpType::FloatNegate,
            FLOAT_ABS => IrUnOpType::FloatAbs,
            FLOAT_SQRT => IrUnOpType::FloatSqrt,
            FLOAT_CEIL => IrUnOpType::FloatCeil,
            FLOAT_FLOOR => IrUnOpType::FloatFloor,
            FLOAT_ROUND => IrUnOpType::FloatRound,
            FLOAT_NAN => IrUnOpType::FloatNaN,
            _ => panic!(),
        }
    }
}

impl From<ExpressionType> for IrCastOpType {
    /// Translates expression types.
    /// Panics when given a type not representable by the target type.
    fn from(expr_type: ExpressionType) -> IrCastOpType {
        use ExpressionType::*;
        match expr_type {
            INT_ZEXT => IrCastOpType::IntZExt,
            INT_SEXT => IrCastOpType::IntSExt,
            INT2FLOAT => IrCastOpType::Int2Float,
            FLOAT2FLOAT => IrCastOpType::Float2Float,
            TRUNC => IrCastOpType::Trunc,
            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_deserialization() {
        let _: Variable = serde_json::from_str(
            r#"
        {
            "name": "RSP",
            "size": 8,
            "is_virtual": false
        }
        "#,
        )
        .unwrap();
    }

    #[test]
    fn expression_deserialization() {
        let _: Expression = serde_json::from_str(
            r#"
            {
                "mnemonic": "INT_SLESS",
                "input0": {
                "name": "EAX",
                "size": 4,
                "is_virtual": false
                },
                "input1": {
                "value": "00000000",
                "size": 4,
                "is_virtual": false
                }
            }
            "#,
        )
        .unwrap();
    }
}
