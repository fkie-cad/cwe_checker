/// A set of functions that all abstract string domains should implement.
pub trait DomainInsertion {
    /// Inserts a string domain at a certain position if order is considered.
    fn append_string_domain(&self, string_domain: &Self) -> Self;
    /// Creates a string domain with characters that usually appear in an integer value.
    fn create_integer_domain() -> Self;
    /// Creates a string domain with characters that usually appear in a char value.
    fn create_char_domain() -> Self;
    /// Creates a string domain with characters that usually appear in a float value.
    fn create_float_value_domain() -> Self;
    /// Creates a string domain with characters that usually appear in a String value.
    fn create_pointer_value_domain() -> Self;
    /// Creates a top value of the currently used domain.
    fn create_top_value_domain() -> Self;
    /// Creates an empty string domain.
    fn create_empty_string_domain() -> Self;
}
