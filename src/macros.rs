macro_rules! unknown_tpm_data {
    ($value:expr, $what:literal) => {{
        tracing::error!(
            value = ?$value,
            concat!("unknown TPM ", $what)
        );

        Err($crate::Error::InvalidData)
    }};
}

macro_rules! tpm2b_bytes_type {
    ($name:ident) => {
        #[derive(Default, Clone)]
        pub(crate) struct $name(Vec<u8>);

        impl $name {
            pub(crate) fn into_bytes(self) -> Vec<u8> {
                self.0
            }
        }

        $crate::macros::impl_tpm2b_common!($name);
    };
    ($name:ident($inner:ty)) => {
        #[derive(Clone)]
        pub(crate) struct $name($inner);

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        $crate::macros::impl_into_inner!($name, $inner);
    };
}

macro_rules! tpm2b_secret_type {
    ($name:ident) => {
        #[derive(Default, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
        pub(crate) struct $name(Vec<u8>);

        $crate::macros::impl_tpm2b_common!($name);
    };
    ($name:ident($inner:ty)) => {
        #[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
        pub(crate) struct $name($inner);

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }
    }
}

macro_rules! impl_tpm2b_common {
    ($name:ident) => {
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

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("len", &self.0.len())
                    .finish()
            }
        }
    };
}

macro_rules! tpm_list_type {
    ($name:ident($item:ty);) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) struct $name {
            items: Vec<$item>,
        }

        impl $name {
            pub(crate) fn default() -> Self {
                Self { items: Vec::new() }
            }
            
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
                Self { items: items.into() }
            }
        }
    };
}

macro_rules! newtype {
    ($name:ident($raw:ty)) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) struct $name($raw);

        impl $name {
            pub(crate) fn raw(&self) -> $raw {
                self.0
            }
        }
    };
    ($name:ident($inner:ty) => $raw:ty) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) struct $name($inner);

        impl $name {
            pub(crate) fn raw(&self) -> $raw {
                self.0.raw()
            }
        }

        $crate::macros::impl_into_inner!($name, $inner);
    };
}

macro_rules! impl_into_inner {
    ($from:ty, $to:ty) => {
        impl From<$from> for $to {
            fn from(value: $from) -> Self {
                value.0
            }
        }
    };
}

pub(crate) use {
    impl_into_inner, impl_tpm2b_common, newtype, tpm_list_type, tpm2b_secret_type, 
    tpm2b_bytes_type, unknown_tpm_data,
};
