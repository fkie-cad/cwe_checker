use super::Def;
use crate::intermediate_representation::BinOpType as IrBinOpType;
use crate::intermediate_representation::ByteSize;
use crate::intermediate_representation::CastOpType as IrCastOpType;
use crate::intermediate_representation::Expression as IrExpression;
use crate::intermediate_representation::UnOpType as IrUnOpType;
use crate::intermediate_representation::Variable as IrVariable;
use crate::prelude::*;

/// A variable representing a varnode in Ghidra P-Code
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Variable {
    /// The name of the register if the varnode represents a register
    pub name: Option<String>,
    /// The value of the varnode if it represents a constant
    pub value: Option<String>,
    /// If the varnode represents an implicit `LOAD` from memory,
    /// the (necessarily constant) address of the `LOAD`.
    pub address: Option<String>,
    /// The size (in bytes) of the varnode
    pub size: ByteSize,
    /// A flag set to `true` for virtual/temporary registers.
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
            (None, Some(_hex_value)) => IrExpression::Const(pcode_var.parse_const_to_bitvector()),
            _ => panic!("Conversion failed:\n{pcode_var:?}"),
        }
    }
}

impl Variable {
    /// Parses a variable representing a concrete value to a bitvector containing the value.
    pub fn parse_const_to_bitvector(&self) -> Bitvector {
        match &self.value {
            Some(hex_value) => {
                let mut bitvector = Bitvector::from_str_radix(16, hex_value).unwrap();
                match bitvector.width().cmp(&self.size.into()) {
                    std::cmp::Ordering::Greater => bitvector.truncate(self.size).unwrap(),
                    std::cmp::Ordering::Less => bitvector.zero_extend(self.size).unwrap(),
                    std::cmp::Ordering::Equal => (),
                }
                bitvector
            }
            _ => panic!(),
        }
    }

    /// Parses a variable representing an address to a pointer-sized bitvector containing the address.
    pub fn parse_address_to_bitvector(&self, generic_pointer_size: ByteSize) -> Bitvector {
        match &self.address {
            Some(hex_value) => {
                let mut bitvector = Bitvector::from_str_radix(16, hex_value).unwrap();
                match bitvector.width().cmp(&generic_pointer_size.into()) {
                    std::cmp::Ordering::Greater => {
                        bitvector.truncate(generic_pointer_size).unwrap()
                    }
                    std::cmp::Ordering::Less => {
                        bitvector.zero_extend(generic_pointer_size).unwrap()
                    }
                    std::cmp::Ordering::Equal => (),
                }
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
    pub fn to_load_def(
        &self,
        target_register_name: impl Into<String>,
        generic_pointer_size: ByteSize,
    ) -> Def {
        Def {
            lhs: Some(Variable::new_virtual(target_register_name, self.size)),
            rhs: Expression {
                mnemonic: ExpressionType::LOAD,
                input0: None,
                input1: Some(Variable::new_const(
                    self.address.as_ref().unwrap(),
                    generic_pointer_size,
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
                let val: u64 = u64::from_str_radix(hex_value, 16).unwrap();
                val.into()
            }
            _ => panic!(),
        }
    }
}

/// A P-Code expression.
///
/// P-Code itself does not divide instructions into expressions, definitions and jumps,
/// like in the internally used IR.
/// This type roughly corresponds to P-Code instructions without side effects
/// (except for assigning to the output register).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Expression {
    /// The instruction mnemonic
    pub mnemonic: ExpressionType,
    /// The first input varnode (if it exists).
    pub input0: Option<Variable>,
    /// The second input varnode (if it exists).
    pub input1: Option<Variable>,
    /// The third input varnode (if it exists).
    pub input2: Option<Variable>,
}

impl From<Expression> for IrExpression {
    /// Translates a P-Code expression into an expression of the internally used IR if possible.
    /// Panics if translation is not possible.
    ///
    /// Cases where translation is not possible:
    /// - `LOAD` and `STORE`, since these are not expressions (they have side effects).
    /// - Expressions which store the size of their output in the output variable (to which we do not have access here).
    /// These include `SUBPIECE`, `INT_ZEXT`, `INT_SEXT`, `INT2FLOAT`, `FLOAT2FLOAT`, `TRUNC` and `POPCOUNT`.
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
            INT_ZEXT | INT_SEXT | INT2FLOAT | FLOAT2FLOAT | TRUNC | POPCOUNT => panic!(),
        }
    }
}

/// Expression Opcodes as parsed from Ghidra
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ExpressionType {
    COPY,
    LOAD,
    STORE,
    PIECE,
    SUBPIECE,
    POPCOUNT,

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
    #[serde(alias = "CEIL")]
    FLOAT_CEIL,
    #[serde(alias = "FLOOR")]
    FLOAT_FLOOR,
    #[serde(alias = "ROUND")]
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
            POPCOUNT => IrCastOpType::PopCount,
            _ => panic!(),
        }
    }
}

/// Properties of a register with respect to its base register.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RegisterProperties {
    /// The register name.
    pub register: String,
    /// The name of the base register.
    pub base_register: String,
    /// The least significant byte of the register when viewed as a sub-register of the base register.
    pub lsb: ByteSize,
    /// The size (in bytes) of the register
    pub size: ByteSize,
}

impl From<&RegisterProperties> for IrVariable {
    /// Create a variable representing the same register as the given `register_prop`.
    fn from(register_prop: &RegisterProperties) -> IrVariable {
        IrVariable {
            name: register_prop.register.clone(),
            size: register_prop.size,
            is_temp: false,
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

    #[test]
    fn register_properties_deserialization() {
        let _: RegisterProperties = serde_json::from_str(
            r#"
            {
                "register": "AH",
                "base_register": "EAX",
                "lsb": 2,
                "size": 1
            }
            "#,
        )
        .unwrap();
    }

    #[test]
    fn parse_to_bitvector() {
        let mut var = Variable {
            name: None,
            value: Some("0".to_string()),
            address: None,
            size: ByteSize::new(8),
            is_virtual: false,
        };
        assert_eq!(var.parse_const_to_bitvector(), Bitvector::from_u64(0));
        var.value = Some("0010f".to_string());
        assert_eq!(var.parse_const_to_bitvector(), Bitvector::from_u64(271));
        var.value = Some("1ff".to_string());
        var.size = ByteSize::new(1);
        assert_eq!(var.parse_const_to_bitvector(), Bitvector::from_u8(255));
        var.size = ByteSize::new(16);
        assert_eq!(var.parse_const_to_bitvector(), Bitvector::from_u128(511));

        var.value = Some("00_ffffffffffffffff_ffffffffffffffff".to_string());
        var.size = ByteSize::new(16);
        assert_eq!(var.parse_const_to_bitvector(), Bitvector::from_i128(-1));
        var.size = ByteSize::new(10);
        assert_eq!(
            var.parse_const_to_bitvector(),
            Bitvector::from_i128(-1)
                .into_truncate(ByteSize::new(10))
                .unwrap()
        );

        let var = Variable {
            name: None,
            value: None,
            address: Some("000010f".to_string()),
            size: ByteSize::new(1), // Note that this size is not the size of a pointer!
            is_virtual: false,
        };
        assert_eq!(
            var.parse_address_to_bitvector(ByteSize::new(8)),
            Bitvector::from_u64(271)
        );
    }
}
