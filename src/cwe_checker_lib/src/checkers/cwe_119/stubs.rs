use super::{Context, State};
use crate::abstract_domain::{RegisterDomain, TryToInterval};
use crate::analysis::pointer_inference::Data;
use crate::utils::log::CweWarning;
use crate::{analysis::vsa_results::VsaResult, intermediate_representation::*};

/// A struct containing all relevant information for handling an extern call.
pub struct ExternCallHandler<'a, 'b> {
    context: &'a Context<'b>,
    state: &'a mut State,
    fn_symbol: &'a ExternSymbol,
    jump: &'a Term<Jmp>,
}

impl<'a, 'b> ExternCallHandler<'a, 'b> {
    /// Create a new extern call handler for a specific call to a specific extern function.
    pub fn new(
        context: &'a Context<'b>,
        state: &'a mut State,
        fn_symbol: &'a ExternSymbol,
        jump: &'a Term<Jmp>,
    ) -> ExternCallHandler<'a, 'b> {
        ExternCallHandler {
            context,
            state,
            fn_symbol,
            jump,
        }
    }

    /// Handle a call to an extern function by either calling a specific symbol handler
    /// or by using the default extern call handler.
    ///
    /// The specific symbol handlers, where defined,
    /// check whether an input buffer is at least as large as a corresponding size parameter
    /// and generate warnings if that may not be the case.
    pub fn handle_call(&mut self) {
        let mut warnings = Vec::new();
        match self.fn_symbol.name.as_str() {
            "fgets" | "gets_s" | "snprintf" | "snprintf_s" | "sprintf_s" | "strnlen_s"
            | "vsnprintf" | "vsnprintf_s" | "vsprintf_s" => {
                warnings.append(&mut self.check_buffer_size(0, 1))
            }
            "memchr" | "memset" => warnings.append(&mut self.check_buffer_size(0, 2)),
            "getenv_s" | "read" | "recv" | "recvfrom" | "sendto" | "write" => {
                warnings.append(&mut self.check_buffer_size(1, 2))
            }
            "memcmp" | "memcpy" | "memmove" | "strncasecmp" | "strncat" | "strncmp" | "strncpy" => {
                warnings.append(&mut self.check_buffer_size(0, 2));
                warnings.append(&mut self.check_buffer_size(1, 2));
            }
            "fread" | "fwrite" => warnings.append(&mut self.check_buffer_size_and_count(0, 1, 2)),
            "qsort" | "qsort_s" => warnings.append(&mut self.check_buffer_size_and_count(0, 2, 1)),
            _ => self.handle_generic_call(),
        }

        if !warnings.is_empty() {
            let description = format!(
                "(Buffer Overflow) Call to {} at {} may access out-of-bounds memory.",
                self.fn_symbol.name, self.jump.tid.address
            );
            let mut cwe_warning = CweWarning::new("CWE119", super::CWE_MODULE.version, description);
            cwe_warning.tids = vec![format!("{}", self.jump.tid)];
            cwe_warning.addresses = vec![self.jump.tid.address.to_string()];
            cwe_warning.other = vec![warnings];
            self.context.log_collector.send(cwe_warning.into()).unwrap();
        }
    }

    /// Check whether the buffer parameter is at least as large as the access size given by the size parameter.
    fn check_buffer_size(
        &mut self,
        buffer_param_index: usize,
        size_param_index: usize,
    ) -> Vec<String> {
        let size = match self.compute_buffer_size_from_param(size_param_index) {
            Some(size) => size,
            None => ByteSize::new(1),
        };
        self.check_buffer_with_concrete_size(buffer_param_index, size)
    }

    /// Check whether the buffer parameter is at least `size * count` bytes large,
    /// where `size` and `count` are given by the corresponding parameters.
    fn check_buffer_size_and_count(
        &mut self,
        buffer_param_index: usize,
        size_param_index: usize,
        count_param_index: usize,
    ) -> Vec<String> {
        let size = match self
            .compute_buffer_size_from_size_and_count_params(size_param_index, count_param_index)
        {
            Some(size) => size,
            None => ByteSize::new(1),
        };
        self.check_buffer_with_concrete_size(buffer_param_index, size)
    }

    /// Checker whether the given buffer parameter is at least as large as the provided concrete size.
    fn check_buffer_with_concrete_size(
        &mut self,
        buffer_param_index: usize,
        size: ByteSize,
    ) -> Vec<String> {
        let buffer_param = match self.fn_symbol.parameters.get(buffer_param_index) {
            Some(buffer_param) => buffer_param,
            None => {
                self.context
                    .log_debug(&self.jump.tid, "Missing parameter argument.");
                return Vec::new();
            }
        };
        let buffer = match self
            .context
            .pointer_inference
            .eval_parameter_arg_at_call(&self.jump.tid, buffer_param)
        {
            Some(buffer) => buffer,
            None => return Vec::new(),
        };

        self.state.check_address_access(&buffer, size, self.context)
    }

    /// Compute the size of a buffer from a corresponding size parameter of an extern function.
    /// Returns `None` if no absolute size value could be determined for any reason.
    fn compute_buffer_size_from_param(&self, size_param_index: usize) -> Option<ByteSize> {
        let size = self.context.pointer_inference.eval_parameter_arg_at_call(
            &self.jump.tid,
            self.fn_symbol.parameters.get(size_param_index)?,
        )?;
        self.compute_buffer_size_from_data_domain(size)
    }

    /// Compute the size of a buffer as the product from corresponding size and count parameters of an extern function.
    /// Returns `None` if no absolute size value could be determined for any reason.
    fn compute_buffer_size_from_size_and_count_params(
        &self,
        size_param_index: usize,
        count_param_index: usize,
    ) -> Option<ByteSize> {
        let size_param = self.context.pointer_inference.eval_parameter_arg_at_call(
            &self.jump.tid,
            self.fn_symbol.parameters.get(size_param_index)?,
        )?;
        let count_param = self.context.pointer_inference.eval_parameter_arg_at_call(
            &self.jump.tid,
            self.fn_symbol.parameters.get(count_param_index)?,
        )?;
        let size = size_param.bin_op(BinOpType::IntMult, &count_param);
        self.compute_buffer_size_from_data_domain(size)
    }

    /// Compute the size of a buffer from a corresponding size value.
    /// Returns `None` if no absolute size value could be determined for any reason.
    ///
    /// If a range of possible sizes is detected, use the smallest possible size,
    /// as using larger sizes would lead to too many false positive CWE warnings.
    fn compute_buffer_size_from_data_domain(&self, size: Data) -> Option<ByteSize> {
        let size = self.context.recursively_substitute_param_values(&size);
        let (lower_bound, _upper_bound) =
            size.get_absolute_value()?.try_to_offset_interval().ok()?;
        // FIXME: Currently we need to use the lower bound,
        // because using the upper bound would lead to too many false positives.
        // To fix this we probably need to implement tracking linear dependencies between values.
        if lower_bound > 0 {
            Some((lower_bound as u64).into())
        } else {
            None
        }
    }

    /// Generic call handler.
    /// Assumes that the first byte of every parameter memory object is accessed by the called function.
    fn handle_generic_call(&mut self) {
        for param in &self.fn_symbol.parameters {
            self.context.check_param_at_call(
                self.state,
                param,
                &self.jump.tid,
                Some(&self.fn_symbol.name),
            );
        }
    }
}
