macro_rules! unknown_tpm_data {
    ($value:expr, $what:literal) => {{
        tracing::debug!(
            value = ?$value,
            concat!("unknown TPM ", $what)
        );

        Err($crate::Error::InvalidData)
    }};
}

macro_rules! tpm2b_type {
    ($name:ident,$max:expr) => {
        #[derive(Debug, Default, Clone)]
        pub(crate) struct $name(Vec<u8>);

        impl $name {
            pub(crate) const MAX_BYTES: usize = $max;
 
            pub(crate) fn into_bytes(self) -> Vec<u8> {
                self.0
            }
        }

        $crate::macros::impl_buffer_methods!($name);
        $crate::macros::impl_try_from_bytes!($name);
    };
    ($name:ident($inner:ty),$max:expr) => {
        #[derive(Debug, Clone)]
        pub(crate) struct $name($inner);

        impl $name {
            pub(crate) const MAX_BYTES: usize = $max;

            pub(crate) fn into_inner(self) -> $inner {
                self.0
            }

            pub(crate) fn as_inner(&self) -> &$inner {
                &self.0
            }
        }

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }
    };
}

macro_rules! tpm2b_zeroize_type {
    ($name:ident,$max:expr) => {
        #[derive(Default)]
        pub(crate) struct $name(zeroize::Zeroizing<Vec<u8>>);

        impl $name {
            pub(crate) const MAX_BYTES: usize = $max;
        }

        $crate::macros::impl_buffer_methods!($name);
        $crate::macros::impl_try_from_bytes!($name);
    };
    ($name:ident($inner:ty),$max:expr) => {
        pub(crate) struct $name($inner);

        impl $name {
            pub(crate) const MAX_BYTES: usize = $max;
            
            pub(crate) fn as_inner(&self) -> &$inner {
                &self.0
            }
        }

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }
    };
}

macro_rules! impl_try_from_bytes {
    ($name:ty) => {
        impl TryFrom<Vec<u8>> for $name {
            type Error = $crate::error::Error;

            fn try_from(value: Vec<u8>) -> $crate::error::Result<Self> {
                if value.len() <= <$name>::MAX_BYTES {
                    Ok(Self(value.into()))
                } else {
                    Err($crate::error::Error::conversion::<Vec<u8>, $name>(None))
                }
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = $crate::error::Error;

            fn try_from(value: &[u8]) -> $crate::error::Result<Self> {
                if value.len() <= <$name>::MAX_BYTES {
                    Ok(Self(value.to_vec().into()))
                } else {
                    Err($crate::error::Error::conversion::<&[u8], $name>(None))
                }
            }
        }
    };
}

macro_rules! impl_redacted_debug {
    ($name:ident) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

macro_rules! impl_buffer_methods {
    ($name:ty) => {
        impl $name {
            pub(crate) fn as_bytes(&self) -> &[u8] {
                &self.0
            }
            
            pub(crate) fn len(&self) -> usize {
                self.0.len()
            }

            pub(crate) fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }
    };
}

macro_rules! impl_from_bytes {
    ($name:ident) => {
        impl From<Vec<u8>> for $name {
            fn from(value: Vec<u8>) -> Self {
                Self(value)
            }
        }

        impl From<&[u8]> for $name {
            fn from(value: &[u8]) -> Self {
                Self(value.to_vec())
            }
        }
    };
}

macro_rules! tpm_list_type {
    ($name:ident($item:ty);) => {
        #[derive(Debug, Default, Clone, PartialEq, Eq)]
        pub(crate) struct $name {
            items: Vec<$item>,
        }

        impl $name {
            pub(crate) fn len(&self) -> usize {
                self.items.len()
            }

            pub(crate) fn is_empty(&self) -> bool {
                self.items.is_empty()
            }

            pub(crate) fn items(&self) -> &[$item] {
                &self.items
            }

            pub(crate) fn into_items(self) -> Vec<$item> {
                self.items
            }
        }

        impl From<Vec<$item>> for $name {
            fn from(items: Vec<$item>) -> Self {
                Self { items }
            }
        }

        impl From<&[$item]> for $name {
            fn from(items: &[$item]) -> Self {
                Self {
                    items: items.into(),
                }
            }
        }
    };
}

macro_rules! newtype {
    ($name:ident(TpmAlgId)) => {
        newtype!($name(TpmAlgId) => u16);
    };
    ($name:ident(TpmHandle)) => {
        newtype!($name(TpmHandle) => u32);
    };
    ($name:ident($raw:ty)) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub(crate) struct $name($raw);

        impl $name {
            pub(crate) fn raw(&self) -> $raw {
                self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "0x{:0width$X}",
                    self.raw(),
                    width = std::mem::size_of::<$raw>() * 2,
                )
            }
        }
    };
    ($name:ident($inner:ty) => $raw:ty) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub(crate) struct $name($inner);

        impl $name {
            pub(crate) fn raw(&self) -> $raw {
                self.0.raw()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "0x{:0width$X}",
                    self.raw(),
                    width = std::mem::size_of::<$raw>() * 2,
                )
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

pub(crate) use {
    impl_buffer_methods, impl_try_from_bytes, newtype, tpm_list_type,
    tpm2b_type, tpm2b_zeroize_type, unknown_tpm_data,
};
