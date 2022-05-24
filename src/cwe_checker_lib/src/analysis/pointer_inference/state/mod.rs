use super::object_list::AbstractObjectList;
use super::Data;
use crate::abstract_domain::*;
use crate::analysis::function_signature::FunctionSignature;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::binary::RuntimeMemoryImage;
use std::collections::{BTreeMap, BTreeSet};

mod access_handling;
mod id_manipulation;
mod value_specialization;

/// Contains all information known about the state of a program at a specific point of time.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    /// Maps a register variable to the data known about its content.
    /// A variable not contained in the map has value `Data::Top(..)`, i.e. nothing is known about its content.
    register: DomainMap<Variable, Data, MergeTopStrategy>,
    /// The list of all known memory objects.
    pub memory: AbstractObjectList,
    /// The abstract identifier of the current stack frame.
    /// It points to the base of the stack frame, i.e. only negative offsets point into the current stack frame.
    pub stack_id: AbstractIdentifier,
}

impl State {
    /// Create a new state that contains only one memory object corresponding to the stack.
    /// The stack offset will be set to zero.
    pub fn new(stack_register: &Variable, function_tid: Tid) -> State {
        let stack_id = AbstractIdentifier::new(
            function_tid,
            AbstractLocation::from_var(stack_register).unwrap(),
        );
        let mut register = DomainMap::from(BTreeMap::new());
        register.insert(
            stack_register.clone(),
            Data::from_target(
                stack_id.clone(),
                Bitvector::zero(apint::BitWidth::from(stack_register.size)).into(),
            ),
        );
        State {
            register,
            memory: AbstractObjectList::from_stack_id(stack_id.clone(), stack_register.size),
            stack_id,
        }
    }

    /// Create a new state from a function signature.
    ///
    /// The created state contains one memory object for the stack frame of the function
    /// and one memory object for each parameter that is dereferenced by the function
    /// (according to the function signature).
    pub fn from_fn_sig(
        fn_sig: &FunctionSignature,
        stack_register: &Variable,
        function_tid: Tid,
    ) -> State {
        let mock_global_memory = RuntimeMemoryImage::empty(true);
        let mut state = State::new(stack_register, function_tid.clone());
        // Adjust the upper bound of the stack frame to include all stack parameters
        // (and the return address at stack offset 0 for x86).
        let stack_upper_bound: i64 = match stack_register.name.as_str() {
            "ESP" => 4,
            "RSP" => 8,
            _ => 0,
        };
        let stack_upper_bound =
            std::cmp::max(stack_upper_bound, fn_sig.get_stack_params_total_size());
        let stack_obj = state.memory.get_object_mut(&state.stack_id).unwrap();
        stack_obj.add_to_upper_index_bound(stack_upper_bound);
        // Set parameter values and create parameter memory objects.
        for (arg, access_pattern) in &fn_sig.parameters {
            let param_id = AbstractIdentifier::from_arg(&function_tid, arg);
            match arg {
                Arg::Register {
                    expr: Expression::Var(var),
                    ..
                } => state.set_register(
                    var,
                    Data::from_target(param_id.clone(), Bitvector::zero(var.size.into()).into()),
                ),
                Arg::Register { .. } => continue, // Parameters in floating point registers are currently ignored.
                Arg::Stack { address, size, .. } => {
                    let param_data =
                        Data::from_target(param_id.clone(), Bitvector::zero((*size).into()).into());
                    state
                        .write_to_address(address, &param_data, &mock_global_memory)
                        .unwrap();
                }
            }
            if access_pattern.is_dereferenced() {
                state
                    .memory
                    .add_abstract_object(param_id, stack_register.size, None);
            }
        }
        state
    }

    /// Set the MIPS link register `t9` to the address of the callee TID.
    ///
    /// According to the System V ABI for MIPS the caller has to save the callee address in register `t9`
    /// on a function call to position-independent code.
    /// This function manually sets `t9` to the correct value
    /// to mitigate cases where `t9` could not be correctly computed due to previous analysis errors.
    ///
    /// Returns an error if the callee address could not be parsed (e.g. for `UNKNOWN` addresses).
    pub fn set_mips_link_register(
        &mut self,
        callee_tid: &Tid,
        generic_pointer_size: ByteSize,
    ) -> Result<(), Error> {
        let link_register = Variable {
            name: "t9".into(),
            size: generic_pointer_size,
            is_temp: false,
        };
        let address = Bitvector::from_u64(u64::from_str_radix(&callee_tid.address, 16)?)
            .into_resize_unsigned(generic_pointer_size);
        // FIXME: A better way would be to test whether the link register contains the correct value
        // and only fix and log cases where it doesn't contain the correct value.
        // Right now this is unfortunately the common case,
        // so logging every case would generate too many log messages.
        self.set_register(&link_register, address.into());
        Ok(())
    }

    /// Clear all non-callee-saved registers from the state.
    /// This automatically also removes all virtual registers.
    /// The parameter is a list of callee-saved register names.
    pub fn clear_non_callee_saved_register(&mut self, callee_saved_register: &[Variable]) {
        let register = callee_saved_register
            .iter()
            .filter_map(|var| {
                let value = self.get_register(var);
                if value.is_top() {
                    None
                } else {
                    Some((var.clone(), value))
                }
            })
            .collect();
        self.register = register;
    }

    /// Mark those parameter values of an extern function call, that are passed on the stack,
    /// as unknown data (since the function may modify them).
    pub fn clear_stack_parameter(
        &mut self,
        extern_call: &ExternSymbol,
        global_memory: &RuntimeMemoryImage,
    ) -> Result<(), Error> {
        let mut result_log = Ok(());
        for arg in &extern_call.parameters {
            match arg {
                Arg::Register { .. } => (),
                Arg::Stack { address, size, .. } => {
                    let data_top = Data::new_top(*size);
                    if let Err(err) = self.write_to_address(address, &data_top, global_memory) {
                        result_log = Err(err);
                    }
                }
            }
        }
        // We only return the last error encountered.
        result_log
    }

    /// Remove all objects that cannot longer be reached by any known pointer.
    /// This does not remove objects, where some caller may still know a pointer to the object.
    ///
    /// The function uses an underapproximation of all possible pointer targets contained in a memory object.
    /// This keeps the number of tracked objects reasonably small.
    pub fn remove_unreferenced_objects(&mut self) {
        // get all referenced IDs from registers
        let mut referenced_ids = BTreeSet::new();
        for (_reg_name, data) in self.register.iter() {
            referenced_ids.extend(data.referenced_ids().cloned());
        }
        // get all IDs of parameter objects and the current stack frame
        for id in self.memory.get_all_object_ids() {
            if id.get_tid() == self.stack_id.get_tid() && id.get_path_hints().is_empty() {
                referenced_ids.insert(id);
            }
        }
        referenced_ids = self.add_directly_reachable_ids_to_id_set(referenced_ids);
        // remove unreferenced objects
        self.memory.remove_unused_objects(&referenced_ids);
    }

    /// Remove all knowledge about the contents of non-callee-saved registers from the state.
    pub fn remove_non_callee_saved_register(&mut self, cconv: &CallingConvention) {
        let mut callee_saved_register = BTreeMap::new();
        for var in &cconv.callee_saved_register {
            if let Some(value) = self.register.get(var) {
                callee_saved_register.insert(var.clone(), value.clone());
            }
        }
        self.register = callee_saved_register.into();
    }

    /// Get the Tid of the function that this state belongs to.
    pub fn get_fn_tid(&self) -> &Tid {
        self.stack_id.get_tid()
    }
}

impl AbstractDomain for State {
    /// Merge two states
    fn merge(&self, other: &Self) -> Self {
        assert_eq!(self.stack_id, other.stack_id);
        let merged_memory_objects = self.memory.merge(&other.memory);
        State {
            register: self.register.merge(&other.register),
            memory: merged_memory_objects,
            stack_id: self.stack_id.clone(),
        }
    }

    /// A state has no *Top* element
    fn is_top(&self) -> bool {
        false
    }
}

impl State {
    /// Get a more compact json-representation of the state.
    /// Intended for pretty printing, not useable for serialization/deserialization.
    pub fn to_json_compact(&self) -> serde_json::Value {
        use serde_json::*;
        let mut state_map = Map::new();
        let register = self
            .register
            .iter()
            .map(|(var, data)| (var.name.clone(), data.to_json_compact()))
            .collect();
        let register = Value::Object(register);
        state_map.insert("register".into(), register);
        state_map.insert("memory".into(), self.memory.to_json_compact());
        state_map.insert(
            "stack_id".into(),
            Value::String(format!("{}", self.stack_id)),
        );

        Value::Object(state_map)
    }
}

#[cfg(test)]
mod tests;
