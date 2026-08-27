import re
import os

with open("shared/src/lib.rs", "r") as f:
    text = f.read()

ensure_macro = """
/// Ensure a condition is true, returning an Error early if not.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $err:expr) => {
        if !($cond) {
            return Err($err);
        }
    };
    ($cond:expr, $err:expr, $msg:expr) => {
        if !($cond) {
            // in a real environment we'd log the message
            return Err($err);
        }
    };
}
"""

text += ensure_macro

with open("shared/src/lib.rs", "w") as f:
    f.write(text)

