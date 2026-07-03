use zeroize::Zeroizing;

pub(crate) struct Digest(Zeroizing<Vec<u8>>);
