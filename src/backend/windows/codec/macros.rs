macro_rules! marshal_be {
    ($($value:expr),+ $(,)?) => {{
        let mut out = ::std::vec::Vec::new();

        $(
            out.extend_from_slice(&$value.to_be_bytes());
        )+

        out
    }};
}

pub(crate) use marshal_be;
