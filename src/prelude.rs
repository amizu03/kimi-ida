pub(crate) use crate::ida::*;
pub(crate) use crate::kimi::*;
pub(crate) use crate::{println, dbg};
pub(crate) use serde::{Serializer, Deserialize, Serialize};
pub(crate) use spin::{Mutex, MutexGuard};
pub(crate) use rayon::prelude::*;

#[macro_export]
macro_rules! println {
    () => {
        $crate::ida::msg_str(c"\n")
    };
    ($($arg:tt)*) => {{
        let msg = "[KIMI] ".to_string() + &format_args!($($arg)*).to_string() + "\n\0";
        $crate::ida::msg_str(msg.as_ptr() as _);
    }};
}

#[macro_export]
macro_rules! dbg {
    // NOTE: We cannot use `concat!` to make a static string as a format argument
    // of `eprintln!` because `file!` could contain a `{` or
    // `$val` expression could be a block (`{ .. }`), in which case the `eprintln!`
    // will be malformed.
    () => {
        $crate::println!("[{}:{}:{}]", file!(), line!(), column!())
    };
    ($val:expr $(,)?) => {
        // Use of `match` here is intentional because it affects the lifetimes
        // of temporaries - https://stackoverflow.com/a/48732525/1063961
        match $val {
            tmp => {
                $crate::println!("[{}:{}:{}] {} = {:#X?}", file!(), line!(), column!(), stringify!($val), &tmp);
                tmp
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}
