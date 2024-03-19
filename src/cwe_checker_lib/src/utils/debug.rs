//! Little helpers for developers that try to understand what their code is
//! doing.

/// Central utility for debug printing in the `cwe_checker`.
///
/// The canonical way to do printf-debugging in `cwe_checker` development is to
/// implement this trait for the type you want to inspect and then print it
/// via `value.print_compact_json()`.
pub trait ToJsonCompact {
    /// Returns a json representation of values of type `self` that is
    /// suitable for debugging purposes.
    ///
    /// The idea is that printing of complex types is facilitated by
    /// implementing `to_json_compact` for all of their constituent parts.
    fn to_json_compact(&self) -> serde_json::Value;

    /// Print values of type `Self` for debugging purposes.
    fn print_compact_json(&self) {
        println!("{:#}", self.to_json_compact())
    }
}
