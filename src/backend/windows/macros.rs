macro_rules! reject_trailing_bytes {
    ($len:expr) => {{
        tracing::error!(
            remaining = $len,
            "unexpected trailing bytes in TPM response",
        );
        return Err($crate::error::Error::InvalidData);
    }};
}

pub(super) use reject_trailing_bytes;
