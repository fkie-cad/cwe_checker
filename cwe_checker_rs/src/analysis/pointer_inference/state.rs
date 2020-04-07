use crate::prelude::*;
use std::collections::BTreeMap;
use super::data::Data;
use super::object::AbstractObjectList;
use crate::bil::*;
use crate::analysis::abstract_domain::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    pub register: BTreeMap<String, Data>,
    pub memory: AbstractObjectList,
}

impl State {
    /// evaluate the value of an expression in the current state
    pub fn eval(&self, expression: &Expression) -> Result<Data, Error> {
        use Expression::*;
        match expression {
            Var(variable) => {
                if let Some(data) = self.register.get(&variable.name) {
                    Ok(data.clone())
                } else {
                    Ok(Data::new_top(variable.bitsize()?))
                }
            },
            Const(bitvector) => {
                Ok(Data::bitvector(bitvector.clone()))
            },
            // TODO: implement handling of endianness for loads and writes!
            Load{memory: _, address, endian: _, size} => Ok(self.memory.get_value(&self.eval(address)?, *size)?),
            Store{..} => {
                // This does not return an error, but panics outright.
                // If this would return an error, it would hide a side effect, which is not allowed to happen.
                panic!("Store expression cannot be evaluated!")
            },
            BinOp{op, lhs, rhs} => {
                if *op == crate::bil::BinOpType::XOR && lhs == rhs {
                    // TODO: implement bitsize() for expressions to remove the state.eval(lhs) hack
                    return Ok(Data::Value(BitvectorDomain::Value(Bitvector::zero(apint::BitWidth::new(self.eval(lhs)?.bitsize() as usize)?))));
                }
                let (left, right) = (self.eval(lhs)?, self.eval(rhs)?);
                Ok(left.bin_op(*op, &right))
            },
            UnOp{op, arg} => Ok(self.eval(arg)?.un_op(*op)),
            Cast{kind, width, arg} => Ok(self.eval(arg)?.cast(*kind, *width)),
            Let{var: _, bound_exp: _, body_exp: _} => Err(anyhow!("Let binding expression handling not implemented")),
            Unknown{description, type_} => {
                if let crate::bil::variable::Type::Immediate(bitsize) = type_ {
                    Ok(Data::new_top(*bitsize))
                } else {
                    Err(anyhow!("Unknown Memory operation: {}", description))
                }
            },
            IfThenElse{condition: _, true_exp, false_exp} => Ok(self.eval(true_exp)?.merge(&self.eval(false_exp)?)),
            Extract{low_bit, high_bit, arg} => Ok(self.eval(arg)?.extract(*low_bit, *high_bit)),
            Concat{left, right} => Ok(self.eval(left)?.concat(&self.eval(right)?)),
        }
    }

    pub fn merge(&self, other: &Self) -> Self {
        let mut merged_register = self.register.clone();
        for (reg_name, other_value) in other.register.iter() {
            merged_register.entry(reg_name.to_string()).and_modify(|value| {*value = value.merge(other_value); }).or_insert(other_value.clone());
        };
        let merged_memory_objects = self.memory.merge(&other.memory);
        State {
            register: merged_register,
            memory: merged_memory_objects
        }
    }
}
