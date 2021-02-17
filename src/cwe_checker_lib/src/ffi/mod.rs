/*!
# Foreign Function Interface

This module contains all functions that interact with Ocaml via the foreign function interface.
*/

use std::rc::Rc;

pub mod analysis;
pub mod serde;

/// Helper function for catching panics at the ffi-border.
/// If a panic occurs while executing F and that panic unwinds the stack,
/// the panic is caught and an Ocaml failwith exception is thrown instead.
///
/// Stack unwinding through a panic across a ffi-boundary is undefined behaviour.
/// As of Rust 1.41 catching panics at ffi-borders is still not the default behaviour,
/// since it would break backwards compatibility with some crates depending on this undefined behaviour.
/// Throwing an Ocaml failwith exception instead allows stack unwinding and better error messages.
/// Note that the Ocaml exception should *not* be caught,
/// since recovering from it may lead to undefined behavior on the Rust side.
fn failwith_on_panic<F, T>(closure: F) -> T
where
    F: FnOnce() -> T,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(closure)) {
        Ok(value) => value,
        Err(_) => {
            // Throw an Ocaml failwith-exception.
            // This may not be safe if the exception is caught and recovered from on the Ocaml side!
            // We assume that these errors are only caught for error printing but not for recovering from it.
            ocaml::runtime::failwith("Rust-Panic catched at FFI-boundary");
            std::process::abort();
        }
    }
}

/// This is a convenience trait for objects that may be sent as opaque objects across the ffi-boundary to Ocaml.
/// For that they are wrapped as Rc<T>.
/// Note that this trait does not prevent memory leaks in itself!
/// Whenever such an object is created and sent across the ffi-boundary,
/// the finalizer must be attached to it on the Ocaml side!
trait OcamlSendable: std::marker::Sized {
    /// Pack the object into an Ocaml value
    fn into_ocaml(self) -> ocaml::Value {
        let boxed_val = Rc::new(self);
        ocaml::Value::nativeint(Rc::into_raw(boxed_val) as isize)
    }

    /// Unpack an object that is stored as a `Rc<T>` wrapped in an Ocaml value.
    ///
    /// Note that the caller has to ensure that the wrapped object has the correct type.
    unsafe fn from_ocaml(ocaml_val: &ocaml::Value) -> &Self {
        let ptr: *const Self = ocaml_val.nativeint_val() as *const Self;
        ptr.as_ref().unwrap()
    }

    /// Unpack a `Rc<T>` object wrapped in an Ocaml value and return a clone of it.
    ///
    /// Note that the caller has to ensure that the wrapped object has the correct type.
    unsafe fn from_ocaml_rc(ocaml_val: &ocaml::Value) -> Rc<Self> {
        let ptr: *const Self = ocaml_val.nativeint_val() as *const Self;
        let rc_box = Rc::from_raw(ptr);
        let rc_clone = rc_box.clone(); // Increasing the reference count by 1
        let _ = Rc::into_raw(rc_box); // Do not decrease the reference count when rc_box goes out of scope!
        rc_clone
    }

    fn ocaml_finalize(ocaml_val: ocaml::Value) {
        let ptr: *const Self = ocaml_val.nativeint_val() as *const Self;
        let _ = unsafe { Rc::from_raw(ptr) };
    }
}
