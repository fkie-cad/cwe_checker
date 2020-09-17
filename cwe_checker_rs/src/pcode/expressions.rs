use crate::prelude::*;
use crate::term::{Term, Tid};
use crate::intermediate_representation::ByteSize;
use crate::intermediate_representation::Variable as IrVariable;
use crate::intermediate_representation::Expression as IrExpression;
use crate::intermediate_representation::BinOpType as IrBinOpType;
use crate::intermediate_representation::UnOpType as IrUnOpType;
use crate::intermediate_representation::CastOpType as IrCastOpType;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Variable {
  pub name: Option<String>,
  pub value: Option<String>,
  pub size: ByteSize,
  pub is_virtual: bool,
}

impl From<Variable> for IrVariable {
  fn from(pcode_var: Variable) -> IrVariable {
    IrVariable {
      name: pcode_var.name.unwrap(),
      size: pcode_var.size,
      is_temp: pcode_var.is_virtual, // TODO: rename `pcode_var.is_virtual` to `is_temp`
    }
  }
}

impl From<Variable> for IrExpression {
  fn from(pcode_var: Variable) -> IrExpression {
    match (&pcode_var.name, &pcode_var.value) {
      (Some(_name), None) => IrExpression::Var(pcode_var.into()),
      (None, Some(hex_value)) => {
        // TODO: Implement parsing for large hex values.
        if pcode_var.size > 8.into() {
          panic!("Parsing of immediates greater than 8 bytes not yet implemented: {}", hex_value);
        }
        let val: u64 = u64::from_str_radix(&hex_value, 16).unwrap();
        let mut bitvector: Bitvector = Bitvector::from_u64(val);
        bitvector.truncate(pcode_var.size).unwrap();
        IrExpression::Const(bitvector)
      },
      _ => panic!(),
    }
    
  }
}

impl From<Variable> for ByteSize {
  fn from(pcode_var: Variable) -> ByteSize {
    match (&pcode_var.name, &pcode_var.value) {
      (None, Some(hex_value)) => {
        // TODO: Implement parsing for large hex values.
        if pcode_var.size > 8.into() {
          panic!("Parsing of immediates greater than 8 bytes not yet implemented: {}", hex_value);
        }
        let val: u64 = u64::from_str_radix(&hex_value, 16).unwrap();
        val.into()
      },
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
  fn from(expr: Expression) -> IrExpression {
    match expr.mnemonic {
      _ => todo!(),
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
  FLOAT_NEGATE,
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
  fn from(expr_type: ExpressionType) -> IrBinOpType {
    use ExpressionType::*;
    match expr_type {
      PIECE => IrBinOpType::Piece,
      INT_EQUAL => IrBinOpType::IntEqual,
      INT_NOTEQUAL => IrBinOpType::IntNotEqual,
      INT_LESS => IrBinOpType::IntLess,
      INT_SLESS => IrBinOpType::IntSLess,
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
  fn from(expr_type: ExpressionType) -> IrUnOpType {
    use ExpressionType::*;
    match expr_type {
      INT_NEGATE => IrUnOpType::IntNegate,
      INT_2COMP => IrUnOpType::Int2Comp,
      BOOL_NEGATE => IrUnOpType::BoolNegate,
      FLOAT_NEGATE => IrUnOpType::FloatNegate,
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
            "mnemonic": "INT_SUB",
            "input0": {
              "name": "RSP",
              "size": 8,
              "is_virtual": false
            },
            "input1": {
              "name": "00000008",
              "size": 8,
              "is_virtual": false
            }
        }
        "#,
    )
    .unwrap();
  }
}