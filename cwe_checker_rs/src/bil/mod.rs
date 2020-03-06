use serde::{Deserialize, Serialize};

pub mod variable;
pub use variable::*;

pub type Bitvector = apint::ApInt;

pub type BitSize = u16;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Expression {
    Var(Variable),
    Const(Bitvector),
    Load {
        memory: Box<Expression>,
        address: Box<Expression>,
        endian: Endianness,
        size: BitSize,
    },
    Store {
        memory: Box<Expression>,
        address: Box<Expression>,
        value: Box<Expression>,
        endian: Endianness,
        size: BitSize,
    },
    BinOp {
        op: BinOpType,
        lhs: Box<Expression>,
        rhs: Box<Expression>,
    },
    UnOp {
        op: UnOpType,
        arg: Box<Expression>,
    },
    Cast {
        kind: CastType,
        width: BitSize,
        arg: Box<Expression>,
    },
    Let {
        var: Variable,
        bound_exp: Box<Expression>,
        body_exp: Box<Expression>,
    },
    Unknown {
        description: String,
        type_: Type,
    },
    IfThenElse {
        condition: Box<Expression>,
        true_exp: Box<Expression>,
        false_exp: Box<Expression>,
    },
    Extract {
        low_bit: BitSize,
        high_bit: BitSize,
        arg: Box<Expression>,
    },
    Concat {
        left: Box<Expression>,
        right: Box<Expression>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CastType {
    UNSIGNED,
    SIGNED,
    HIGH,
    LOW,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum BinOpType {
    PLUS,
    MINUS,
    TIMES,
    DIVIDE,
    SDIVIDE,
    MOD,
    SMOD,
    LSHIFT,
    RSHIFT,
    ARSHIFT,
    AND,
    OR,
    XOR,
    EQ,
    NEQ,
    LT,
    LE,
    SLT,
    SLE,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum UnOpType {
    NEG,
    NOT,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Endianness {
    LittleEndian,
    BigEndian,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_deserialization() {
        let string = "\"UNSIGNED\"";
        assert_eq!(CastType::UNSIGNED, serde_json::from_str(string).unwrap());
        let string = "\"NEG\"";
        assert_eq!(UnOpType::NEG, serde_json::from_str(string).unwrap());
    }

    #[test]
    fn bitvector_deserialization() {
        let bitv = Bitvector::from_u64(234);
        let string = serde_json::to_string(&bitv).unwrap();
        println!("{}", string);
        println!("{:?}", bitv);
        let string = "{\"digits\":[234],\"width\":[64]}";
        assert_eq!(bitv, serde_json::from_str(string).unwrap());
    }

    #[test]
    fn expression_deserialization() {
        let string = "{\"BinOp\":{\"lhs\":{\"Const\":{\"digits\":[234],\"width\":[8]}},\"op\":\"PLUS\",\"rhs\":{\"Const\":{\"digits\":[234],\"width\":[8]}}}}";
        let bitv = Bitvector::from_u8(234);
        let exp = Expression::BinOp{
            op: BinOpType::PLUS,
            lhs: Box::new(Expression::Const(bitv.clone())),
            rhs: Box::new(Expression::Const(bitv)),
        };
        println!("{}", serde_json::to_string(&exp).unwrap());
        assert_eq!(exp, serde_json::from_str(string).unwrap())
    }
}
