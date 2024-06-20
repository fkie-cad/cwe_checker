//! This module models ghidra pcode operations and implements their mapping to
//! [UnOpType](crate::intermediate_representation::UnOpType),
//! [BinOpType](crate::intermediate_representation::BinOpType) and
//! [CastOpType](crate::intermediate_representation::CastOpType).

use crate::{
    intermediate_representation::{BinOpType, CastOpType, Expression, Jmp, Tid, UnOpType},
    pcode::{ExpressionType, JmpType},
};

use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

/// P-Code operation wrapper type
///
/// Wrapps expression and jump types for direct deserializations.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
#[serde(untagged)]
pub enum PcodeOperation {
    ExpressionType(ExpressionType),
    JmpType(JmpType),
}

impl Display for PcodeOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PcodeOperation::JmpType(j) => write!(f, "JMP({})", j),
            PcodeOperation::ExpressionType(e) => write!(f, "EXPR({})", e),
        }
    }
}

impl ExpressionType {
    /// Returns the IR `UnOpType`, otherwise `None`.
    pub fn into_ir_unop(&self) -> Option<UnOpType> {
        use ExpressionType::*;
        match self {
            INT_NEGATE => Some(UnOpType::IntNegate),
            INT_2COMP => Some(UnOpType::Int2Comp),
            BOOL_NEGATE => Some(UnOpType::BoolNegate),
            FLOAT_NEG => Some(UnOpType::FloatNegate),
            FLOAT_ABS => Some(UnOpType::FloatAbs),
            FLOAT_SQRT => Some(UnOpType::FloatSqrt),
            FLOAT_CEIL => Some(UnOpType::FloatCeil),
            FLOAT_FLOOR => Some(UnOpType::FloatFloor),
            FLOAT_ROUND => Some(UnOpType::FloatRound),
            FLOAT_NAN => Some(UnOpType::FloatNaN),
            _ => None,
        }
    }

    /// Returns the IR `BinOpType`, otherwise `None`.
    pub fn into_ir_biop(&self) -> Option<BinOpType> {
        use ExpressionType::*;
        match self {
            PIECE => Some(BinOpType::Piece),
            INT_EQUAL => Some(BinOpType::IntEqual),
            INT_NOTEQUAL => Some(BinOpType::IntNotEqual),
            INT_LESS => Some(BinOpType::IntLess),
            INT_SLESS => Some(BinOpType::IntSLess),
            INT_LESSEQUAL => Some(BinOpType::IntLessEqual),
            INT_SLESSEQUAL => Some(BinOpType::IntSLessEqual),
            INT_ADD => Some(BinOpType::IntAdd),
            INT_SUB => Some(BinOpType::IntSub),
            INT_CARRY => Some(BinOpType::IntCarry),
            INT_SCARRY => Some(BinOpType::IntSCarry),
            INT_SBORROW => Some(BinOpType::IntSBorrow),
            INT_XOR => Some(BinOpType::IntXOr),
            INT_AND => Some(BinOpType::IntAnd),
            INT_OR => Some(BinOpType::IntOr),
            INT_LEFT => Some(BinOpType::IntLeft),
            INT_RIGHT => Some(BinOpType::IntRight),
            INT_SRIGHT => Some(BinOpType::IntSRight),
            INT_MULT => Some(BinOpType::IntMult),
            INT_DIV => Some(BinOpType::IntDiv),
            INT_REM => Some(BinOpType::IntRem),
            INT_SDIV => Some(BinOpType::IntSDiv),
            INT_SREM => Some(BinOpType::IntSRem),
            BOOL_XOR => Some(BinOpType::BoolXOr),
            BOOL_AND => Some(BinOpType::BoolAnd),
            BOOL_OR => Some(BinOpType::BoolOr),
            FLOAT_EQUAL => Some(BinOpType::FloatEqual),
            FLOAT_NOTEQUAL => Some(BinOpType::FloatNotEqual),
            FLOAT_LESS => Some(BinOpType::FloatLess),
            FLOAT_LESSEQUAL => Some(BinOpType::FloatLessEqual),
            FLOAT_ADD => Some(BinOpType::FloatAdd),
            FLOAT_SUB => Some(BinOpType::FloatSub),
            FLOAT_MULT => Some(BinOpType::FloatMult),
            FLOAT_DIV => Some(BinOpType::FloatDiv),
            _ => None,
        }
    }

    /// Returns the IR `CastOpType`, otherwise `None`.
    pub fn into_ir_cast(&self) -> Option<CastOpType> {
        use ExpressionType::*;
        match self {
            INT_ZEXT => Some(CastOpType::IntZExt),
            INT_SEXT => Some(CastOpType::IntSExt),
            INT2FLOAT => Some(CastOpType::Int2Float),
            FLOAT2FLOAT => Some(CastOpType::Float2Float),
            TRUNC => Some(CastOpType::Trunc),
            POPCOUNT => Some(CastOpType::PopCount),
            _ => None,
        }
    }
}

impl JmpType {
    pub fn into_ir_branch(&self, target: Tid) -> Jmp {
        if matches!(self, JmpType::BRANCH) {
            Jmp::Branch(target)
        } else {
            panic!("Not a branch operation")
        }
    }

    pub fn into_ir_cbranch(&self, target: Tid, condition: Expression) -> Jmp {
        if matches!(self, JmpType::CBRANCH) {
            Jmp::CBranch { target, condition }
        } else {
            panic!("Not a conditional branch operation")
        }
    }

    pub fn into_ir_return(&self, expression: Expression) -> Jmp {
        if matches!(self, JmpType::RETURN) {
            Jmp::Return(expression)
        } else {
            panic!("Not a return operation")
        }
    }

    pub fn into_ir_branch_indirect(&self, target: Expression, return_: Option<Tid>) -> Jmp {
        if matches!(self, JmpType::CALLIND) {
            Jmp::CallInd { target, return_ }
        } else {
            panic!("Not a call indirect operation")
        }
    }

    pub fn into_ir_call(&self, target: Tid, return_: Option<Tid>) -> Jmp {
        if matches!(self, JmpType::CALL) {
            Jmp::Call { target, return_ }
        } else {
            panic!("Not a call operation")
        }
    }

    pub fn into_ir_call_other(&self, description: String, return_: Option<Tid>) -> Jmp {
        if matches!(self, JmpType::CALLOTHER) {
            Jmp::CallOther {
                description,
                return_,
            }
        } else {
            panic!("Not a call operation")
        }
    }
}
