use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use super::data::*;
use super::object::AbstractObjectList;
use super::identifier::{AbstractIdentifier, AbstractLocation};
use crate::bil::*;
use crate::analysis::abstract_domain::*;

/// This struct contains all information known about the state at a specific point of time.
///
/// Notes:
/// - The *stack_id* is the identifier of the current stack frame.
/// Only reads and writes with offset less than 0 are permitted for it
/// - The *caller_ids* contain all known identifier of caller stack frames.
/// If a read to an offset >= 0 corresponding to the current stack frame happens, it is considered
/// a merge read to all caller stack frames.
/// A write to an offset >= 0 corresponding to the current stack frame writes to all caller stack frames.
/// - The caller_ids are given by the stack pointer at time of the call.
/// This way we can distinguish caller stack frames even if one function calls another several times.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    pub register: BTreeMap<String, Data>,
    pub memory: AbstractObjectList,
    pub stack_id: AbstractIdentifier,
    pub caller_ids: BTreeSet<AbstractIdentifier>,
}

impl State {
    /// Create a new state that contains only one memory object corresponding to the stack.
    /// The stack offset will be set to zero.
    pub fn new(stack_register: &Variable, function_tid: Tid) -> State {
        let stack_id = AbstractIdentifier::new(function_tid, AbstractLocation::from_var(stack_register).unwrap());
        let mut register: BTreeMap<String, Data> = BTreeMap::new();
        register.insert(stack_register.name.clone(), PointerDomain::new(stack_id.clone(), Bitvector::zero((stack_register.bitsize().unwrap() as usize).into()).into()).into());
        State {
            register,
            memory: AbstractObjectList::from_stack_id(stack_id.clone(), stack_register.bitsize().unwrap()),
            stack_id,
            caller_ids: BTreeSet::new(),
        }
    }

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
            Load{memory: _, address, endian: _, size} => Ok(self.memory.get_value(&self.adjust_pointer_for_read(&self.eval(address)?), *size)?),
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

    pub fn store_value(&mut self, address: &Data, value: &Data) -> Result<(), Error> {
        if let Data::Pointer(pointer) = self.adjust_pointer_for_read(address) {
            // TODO: This is a very inexact shortcut, as this write will unnecessarily merge caller memory regions.
            // A more precise solution would write to every caller memory region separately,
            // but would also need to check first whether the target memory region is unique or not.
            self.memory.set_value(pointer, value.clone())?;
            return Ok(());
        } else {
            // TODO: Implement recognition of stores to global memory.
            // Needs implementation of reads from global data first.
            return Err(anyhow!("Memory write to non-pointer data"));
        }
    }

    /// merge two states
    pub fn merge(&self, other: &Self) -> Self {
        assert_eq!(self.stack_id, other.stack_id);
        let mut merged_register = self.register.clone();
        for (reg_name, other_value) in other.register.iter() {
            merged_register.entry(reg_name.to_string()).and_modify(|value| {*value = value.merge(other_value); }).or_insert(other_value.clone());
        };
        let merged_memory_objects = self.memory.merge(&other.memory);
        State {
            register: merged_register,
            memory: merged_memory_objects,
            stack_id: self.stack_id.clone(),
            caller_ids: self.caller_ids.union(&other.caller_ids).cloned().collect()
        }
    }

    /// If the pointer contains a reference to the stack with offset >= 0, replace it with a pointer
    /// pointing to all possible caller ids.
    fn adjust_pointer_for_read(&self, address: &Data) -> Data {
        if let Data::Pointer(pointer) = address {
            let mut new_targets: BTreeMap<AbstractIdentifier, BitvectorDomain> = BTreeMap::new();
            for (id, offset) in pointer.iter_targets() {
                if *id == self.stack_id {
                    match offset {
                        BitvectorDomain::Value(offset_val) => {
                            if offset_val.try_to_i64().unwrap() >= 0 {
                                for caller_id in self.caller_ids.iter() {
                                    new_targets.insert(caller_id.clone(), offset.clone());
                                }
                                // Note that the id of the current stack frame was *not* added.
                            }
                        },
                        BitvectorDomain::Top(bitsize) => {
                            for caller_id in self.caller_ids.iter() {
                                new_targets.insert(caller_id.clone(), offset.clone());
                            }
                            // Note that we also add the id of the current stack frame
                            new_targets.insert(id.clone(), offset.clone());
                        },
                    }
                } else {
                    new_targets.insert(id.clone(), offset.clone());
                }
            }
            return Data::Pointer(PointerDomain::with_targets(new_targets));
        } else {
            return address.clone();
        }
    }

    /// For pointer values replace an abstract identifier with another one and add the offset_adjustment to the pointer offset.
    /// This is needed to adjust stack pointer on call and return instructions.
    pub fn replace_abstract_id(&mut self, old_id: &AbstractIdentifier, new_id: &AbstractIdentifier, offset_adjustment: &BitvectorDomain) {
        for register_data in self.register.values_mut() {
            register_data.replace_abstract_id(old_id, new_id, offset_adjustment);
        }
        self.memory.replace_abstract_id(old_id, new_id, offset_adjustment);
        if &self.stack_id == old_id {
            self.stack_id = new_id.clone();
        }
        if self.caller_ids.get(old_id).is_some() {
            self.caller_ids.remove(old_id);
            self.caller_ids.insert(new_id.clone());
        }
    }

    pub fn remove_unreferenced_objects(&mut self) {
        // get all referenced ids
        let mut referenced_ids = BTreeSet::new();
        for (_reg_name, data) in self.register.iter() {
            referenced_ids.append(&mut data.referenced_ids());
        }
        referenced_ids.insert(self.stack_id.clone());
        referenced_ids.append(&mut self.caller_ids.clone());
        self.add_recursively_referenced_ids_to_id_set(&mut referenced_ids);
        // remove unreferenced ids
        self.memory.remove_unused_ids(&referenced_ids);
    }

    pub fn add_recursively_referenced_ids_to_id_set(&self, ids: &mut BTreeSet<AbstractIdentifier>) {
        let mut unsearched_ids = ids.clone();
        while let Some(id) = unsearched_ids.iter().next() {
            let id = id.clone();
            unsearched_ids.remove(&id);
            let memory_ids = self.memory.get_referenced_ids(&id);
            for mem_id in memory_ids {
                if ids.get(&mem_id).is_none() {
                    ids.insert(mem_id.clone());
                    unsearched_ids.insert(mem_id);
                }
            }
        }
    }

    /// Mark a memory object as already freed (i.e. pointers to it are dangling).
    /// If the object cannot be identified uniquely, all possible targets are marked as having an unknown status.
    pub fn mark_mem_object_as_freed(&mut self, object_pointer: &PointerDomain) {
        self.memory.mark_mem_object_as_freed(object_pointer)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        unimplemented!()
    }
}
