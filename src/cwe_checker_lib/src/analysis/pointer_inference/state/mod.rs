use super::object_list::AbstractObjectList;
use super::Data;
use crate::abstract_domain::*;
use crate::analysis::function_signature::AccessPattern;
use crate::analysis::function_signature::FunctionSignature;
use crate::intermediate_representation::*;
use crate::prelude::*;
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
    /// A list of constants that are assumed to be addresses of global variables accessed by this function.
    /// Used to replace constants by relative values pointing to the global memory object.
    known_global_addresses: Arc<BTreeSet<u64>>,
}

impl State {
    /// Create a new state that contains one memory object corresponding to the stack
    /// and one memory object corresponding to global memory.
    ///
    /// The stack offset will be set to zero.
    pub fn new(
        stack_register: &Variable,
        function_tid: Tid,
        global_addresses: BTreeSet<u64>,
    ) -> State {
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
            known_global_addresses: Arc::new(global_addresses),
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
        let global_addresses = fn_sig
            .global_parameters
            .keys()
            .map(|location| match location {
                AbstractLocation::GlobalAddress { address, .. }
                | AbstractLocation::GlobalPointer(address, _) => *address,
                _ => panic!("Unexpected non-global parameter"),
            })
            .collect();
        let mock_global_memory = RuntimeMemoryImage::empty(true);
        let mut state = State::new(stack_register, function_tid.clone(), global_addresses);
        // Set parameter values and create parameter memory objects.
        for params in sort_params_by_recursion_depth(&fn_sig.parameters).values() {
            for (param_location, access_pattern) in *params {
                state.add_param(param_location, access_pattern, &mock_global_memory);
            }
        }
        for (recursion_depth, params) in sort_params_by_recursion_depth(&fn_sig.global_parameters) {
            if recursion_depth > 0 {
                for (param_location, access_pattern) in params {
                    state.add_param(param_location, access_pattern, &mock_global_memory);
                }
            }
        }
        state
    }

    /// Add the given parameter to the function start state represented by `self`:
    /// For the given parameter location, add a parameter object if it was dereferenced (according to the access pattern)
    /// and write the pointer to the parameter object to the corresponding existing memory object of `self`.
    ///
    /// This function assumes that the parent memory object of `param` already exists if `param` is a nested parameter.
    fn add_param(
        &mut self,
        param: &AbstractLocation,
        access_pattern: &AccessPattern,
        global_memory: &RuntimeMemoryImage,
    ) {
        let param_id = AbstractIdentifier::new(self.stack_id.get_tid().clone(), param.clone());
        if !matches!(param, AbstractLocation::GlobalAddress { .. }) {
            if access_pattern.is_dereferenced() {
                self.memory
                    .add_abstract_object(param_id.clone(), self.stack_id.bytesize(), None);
            }
        }
        match param {
            AbstractLocation::Register(var) => {
                self.set_register(
                    var,
                    Data::from_target(param_id, Bitvector::zero(param.bytesize().into()).into()),
                );
            }
            AbstractLocation::Pointer(var, mem_location) => {
                let (parent_location, offset) =
                    param.get_parent_location(self.stack_id.bytesize()).unwrap();
                let parent_id =
                    AbstractIdentifier::new(self.stack_id.get_tid().clone(), parent_location);
                self.store_value(
                    &Data::from_target(parent_id, Bitvector::from_i64(offset).into()),
                    &Data::from_target(
                        param_id,
                        Bitvector::zero(param_id.bytesize().into()).into(),
                    ),
                    global_memory,
                );
            }
            AbstractLocation::GlobalAddress { address, size } => (),
            AbstractLocation::GlobalPointer(address, mem_location) => {
                let (parent_location, offset) =
                    param.get_parent_location(self.stack_id.bytesize()).unwrap();
                if let AbstractLocation::GlobalAddress { address, size } = parent_location {
                    let parent_id = self.get_global_mem_id();
                    self.store_value(
                        &Data::from_target(
                            parent_id,
                            Bitvector::from_u64(address + offset as u64)
                                .into_sign_resize(self.stack_id.bytesize())
                                .into(),
                        ),
                        &Data::from_target(
                            param_id,
                            Bitvector::zero(param_id.bytesize().into()).into(),
                        ),
                        global_memory,
                    );
                } else {
                    let parent_id =
                        AbstractIdentifier::new(self.stack_id.get_tid().clone(), parent_location);
                    self.store_value(
                        &Data::from_target(
                            parent_id,
                            Bitvector::from_i64(offset)
                                .into_sign_resize(self.stack_id.bytesize())
                                .into(),
                        ),
                        &Data::from_target(
                            param_id,
                            Bitvector::zero(param_id.bytesize().into()).into(),
                        ),
                        global_memory,
                    );
                }
            }
        }
    }

    /// Set the MIPS link register `t9` to the address of the callee TID.
    ///
    /// According to the System V ABI for MIPS the caller has to save the callee address in register `t9`
    /// on a function call to position-independent code.
    /// In MIPS this value is used to compute the addresses of some global variables,
    /// since MIPS does not use program-counter-relative access instructions like other instruction set architectures do.
    ///
    /// This function sets `t9` to the correct value.
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
        self.set_register(&link_register, address.into());
        Ok(())
    }

    /// Remove all objects and registers from the state whose contents will not be used after returning to a caller.
    /// 
    /// All remaining memory objects after the minimization are reachable in the caller
    /// either via a parameter object that may have been mutated in the call
    /// or via a return register.
    pub fn minimize_before_return_instruction(
        &mut self,
        fn_sig: &FunctionSignature,
        cconv: &CallingConvention,
    ) {
        self.clear_non_return_register(cconv);
        self.remove_immutable_parameter_objects(fn_sig);
        self.memory.remove(&self.stack_id);
        self.remove_unreferenced_objects();
    }

    /// Remove all parameter objects (including global parameter objects) that are not marked as mutably accessed.
    /// Used to minimize state before a return instruction.
    fn remove_immutable_parameter_objects(&mut self, fn_sig: &FunctionSignature) {
        self.memory.retain(|object_id, _object| {
            if object_id.get_tid() == self.get_fn_tid() {
                if let Some(access_pattern) = fn_sig.parameters.get(object_id.get_location()) {
                    if !access_pattern.is_mutably_dereferenced() {
                        return false;
                    }
                }
                if let Some(access_pattern) = fn_sig.global_parameters.get(object_id.get_location()) {
                    if !access_pattern.is_mutably_dereferenced() {
                        return false;
                    }
                }
            }
            true
        });
    }

    /// Clear all non-return registers from the state, including all virtual registers.
    /// This function is used to minimize the state before a return instruction.
    fn clear_non_return_register(&mut self, cconv: &CallingConvention) {
        let return_register: HashSet<Variable> = cconv
            .get_all_return_register()
            .into_iter()
            .cloned()
            .collect();
        self.register
            .retain(|var, _value| return_register.contains(var));
    }

    pub fn merge_mem_objects_with_unique_abstract_location(&mut self) {
        // TODO: Write doc-string for this function!
        todo!(); // Generate a map from all abstract locations to the corresponding pointer value.
        todo!(); // Throw out non-unique locations: A location is non-unique
                 // if it shares at least one mem-object with another location.
                 // Only callee-originating mem-objects count here.
        todo!(); // Merge mem-objects corresponding to unique abstract locations.
        todo!(); // Replace callee-originating IDs with an ID generated from the abstract location
                 // if the location is unique.
                 // Implementation probably differs between locations based on param objects and based on return registers.
        todo!(); // Decide whether the propagation of other non-unique callee-originating mem-objects should be limited.
                 // For example, one could limit the path length of corresponding IDs.

        todo!()
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
        // get the global memory ID, as it is always reachable
        referenced_ids.insert(self.get_global_mem_id());
        // Add IDs that are recursively reachable through the known IDs.
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

    /// Get the abstract ID of the global memory object corresponding to this function.
    pub fn get_global_mem_id(&self) -> AbstractIdentifier {
        AbstractIdentifier::new(
            self.stack_id.get_tid().clone(),
            AbstractLocation::GlobalAddress {
                address: 0,
                size: self.stack_id.bytesize(),
            },
        )
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
            known_global_addresses: self.known_global_addresses.clone(),
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

/// Sort parameters by recursion depth.
/// Helper function when one has to iterate over parameters in order of their recursion depth.
fn sort_params_by_recursion_depth(
    params: &BTreeMap<AbstractLocation, AccessPattern>,
) -> BTreeMap<u64, BTreeMap<&AbstractLocation, &AccessPattern>> {
    let mut sorted_params = BTreeMap::new();
    for (param, access_pattern) in params {
        let recursion_depth = param.recursion_depth();
        let bucket = sorted_params
            .entry(recursion_depth)
            .or_insert(BTreeMap::new());
        bucket.insert(param, access_pattern);
    }
    sorted_params
}

#[cfg(test)]
mod tests;
