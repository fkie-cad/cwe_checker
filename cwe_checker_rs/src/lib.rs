/*!
# cwe_checker_rs

Parts of the cwe_checker that are written in Rust.
*/

#[macro_use]
extern crate ocaml;

mod bil;
mod term;
pub mod ffi;



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
