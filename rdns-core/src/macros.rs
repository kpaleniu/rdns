//! `read_be!` returns `Err` from the *caller*, so it is a macro rather than
//! a function: the early return is the point.

macro_rules! read_be {
    ($dt:ty, $data:expr) => {{
        let sz = std::mem::size_of::<$dt>();
        if $data.len() < sz {
            return Err($crate::error::WireError::Truncated {
                what: stringify!($dt),
                need: sz,
                have: $data.len(),
            });
        }
        (
            <$dt>::from_be_bytes($data[..sz].try_into().unwrap()),
            &$data[sz..],
        )
    }};
}
// An ordinary import rather than `#[macro_use]`, whose macros reach only
// what is declared after it — an ordering the module list must not have to
// respect (`TODO.md` #39d).
pub(crate) use read_be;
