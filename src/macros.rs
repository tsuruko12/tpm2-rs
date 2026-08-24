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
    ($name:ident, $max:expr) => {
        $crate::macros::tpm2b_type!(pub(crate) $name, $max);
    };

    ($vis:vis $name:ident, $max:expr) => {
        #[derive(Debug, Default, Clone)]
        $vis struct $name(Vec<u8>);

        $crate::macros::impl_tpm2b_size_consts!($name, $max);

        impl $name {
            pub(crate) fn size(&self) -> usize {
                self.0.len()
            }

            pub(crate) fn into_bytes(self) -> Vec<u8> {
                self.0
            }
        }

        $crate::macros::impl_buffer_methods!($name);
        $crate::macros::impl_try_from_bytes!($name);
        $crate::macros::impl_tpm2b_codec!($name);
    };

    ($name:ident($inner:ty), $max:expr) => {
        $crate::macros::tpm2b_type!(pub(crate) $name($inner), $max);
    };

    ($vis:vis $name:ident($inner:ty), $max:expr) => {
        #[derive(Debug, Clone)]
        $vis struct $name($inner);

        $crate::macros::impl_tpm2b_size_consts!($name, $max);

        impl $name {
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

        $crate::macros::impl_tpm2b_inner_codec!($name, $inner);
    };

    ($name:ident($inner:ty)) => {
        $crate::macros::tpm2b_type!(pub(crate) $name($inner));
    };

    ($vis:vis $name:ident($inner:ty)) => {
        #[derive(Debug, Clone)]
        $vis struct $name($inner);

        impl $name {
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

macro_rules! tpm2b_type_in_win {
    ($($tt:tt)*) => {
        $crate::macros::tpm2b_type!(pub(in crate::backend::windows) $($tt)*);
    };
}

macro_rules! tpm2b_zeroize_type {
    ($name:ident, $max:expr) => {
        $crate::macros::tpm2b_zeroize_type!(pub(crate) $name, $max);
    };

    ($vis:vis $name:ident, $max:expr) => {
        #[derive(Default)]
        $vis struct $name(zeroize::Zeroizing<Vec<u8>>);

        $crate::macros::impl_tpm2b_size_consts!($name, $max);

        impl $name {
            pub(crate) fn size(&self) -> u16 {
                self.0.len() as u16
            }
        }

        $crate::macros::impl_buffer_methods!($name);
        $crate::macros::impl_try_from_bytes!($name);
        $crate::macros::impl_tpm2b_codec!($name);
    };

    ($name:ident($inner:ty), $max:expr) => {
        $crate::macros::tpm2b_zeroize_type!(pub(crate) $name($inner), $max);
    };

    ($vis:vis $name:ident($inner:ty), $max:expr) => {
        $vis struct $name($inner);

        $crate::macros::impl_tpm2b_size_consts!($name, $max);

        impl $name {
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

    ($name:ident($inner:ty)) => {
        $crate::macros::tpm2b_zeroize_type!(pub(crate) $name($inner));
    };

    ($vis:vis $name:ident($inner:ty)) => {
        $vis struct $name($inner);

        impl $name {
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

macro_rules! tpm2b_zeroize_type_in_win {
    ($($tt:tt)*) => {
        $crate::macros::tpm2b_zeroize_type!(pub(in crate::backend::windows) $($tt)*);
    };
}

macro_rules! impl_tpm2b_size_consts {
    ($name:ident, $max:expr) => {
        impl $name {
            pub(crate) const MAX_SIZE: usize = $crate::types::tpm::TPM2B_SIZE_BYTES + $max;
            pub(crate) const MAX_BYTES: usize = $max;
        }
    };
}

macro_rules! impl_tpm2b_codec {
    ($name:ty) => {
        impl $crate::types::tpm::TpmMarshal for $name {
            fn marshal(&self, buf: &mut Vec<u8>) -> $crate::error::Result<()> {
                buf.extend_from_slice(&self.size().to_be_bytes());
                buf.extend_from_slice(self.as_bytes());

                Ok(())
            }
        }

        impl $crate::types::tpm::TpmUnmarshal for $name {
            fn unmarshal(input: &mut &[u8]) -> $crate::error::Result<Self> {
                $crate::types::tpm::read_tpm2b(input)?.try_into()
            }
        }
    };
}

macro_rules! impl_tpm2b_inner_codec {
    ($name:ident($inner:ty)) => {
        impl $crate::types::tpm::TpmMarshal for $name {
            fn marshal(&self, buf: &mut Vec<u8>) -> $crate::error::Result<()> {
                $crate::types::tpm::marshal_tpm2b(buf, self.as_inner())
            }
        }

        impl $crate::types::tpm::TpmUnmarshal for $name {
            fn unmarshal(input: &mut &[u8]) -> $crate::error::Result<Self> {
                let payload = $crate::types::tpm::read_tpm2b(input)?;
                let mut payload = payload.as_slice();
                let inner = <$inner as $crate::types::tpm::TpmUnmarshal>::unmarshal(&mut payload)?;
                $crate::types::tpm::ensure_consumed(payload)?;

                Ok(Self::from(inner))
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

macro_rules! tpm_list_type {
    ($name:ident($item:ty)) => {
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
        $crate::macros::newtype!(pub(crate) $name(TpmAlgId));
    };

    ($vis:vis $name:ident(TpmAlgId)) => {
        $crate::macros::newtype!(@raw $vis $name(TpmAlgId) => u16);

        impl From<&$name> for TpmAlgId {
            fn from(value: &$name) -> Self {
                value.0
            }
        }

        impl $crate::types::tpm::TpmMarshal for $name {
            fn marshal(&self, buf: &mut Vec<u8>) -> $crate::Result<()> {
                $crate::types::tpm::TpmMarshal::marshal(&self.0, buf)
            }
        }

        impl $crate::types::tpm::TpmUnmarshal for $name {
            fn unmarshal(input: &mut &[u8]) -> $crate::Result<Self> {
                <$crate::types::tpm::TpmAlgId as $crate::types::tpm::TpmUnmarshal>::unmarshal(input)?
                    .try_into()
            }
        }
    };

    ($name:ident(TpmHandle)) => {
        $crate::macros::newtype!(pub(crate) $name(TpmHandle));
    };

    ($vis:vis $name:ident(TpmHandle)) => {
        $crate::macros::newtype!(@raw $vis $name(TpmHandle) => u32);

        impl From<&$name> for TpmHandle {
            fn from(value: &$name) -> Self {
                value.0
            }
        }

        impl $crate::types::tpm::TpmMarshal for $name {
            fn marshal(&self, buf: &mut Vec<u8>) -> $crate::Result<()> {
                $crate::types::tpm::TpmMarshal::marshal(&self.0, buf)
            }
        }

        impl $crate::types::tpm::TpmUnmarshal for $name {
            fn unmarshal(input: &mut &[u8]) -> $crate::Result<Self> {
                <$crate::types::tpm::TpmHandle as $crate::types::tpm::TpmUnmarshal>::unmarshal(input)?
                    .try_into()
            }
        }
    };

    ($name:ident($value:ty)) => {
        $crate::macros::newtype!(pub(crate) $name($value));
    };

    ($vis:vis $name:ident($value:ty)) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        $vis struct $name($value);

        impl $name {
            $vis fn value(&self) -> $value {
                self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "0x{:0width$X}",
                    self.value(),
                    width = std::mem::size_of::<$value>() * 2,
                )
            }
        }

        impl $crate::types::tpm::TpmMarshal for $name {
            fn marshal(&self, buf: &mut Vec<u8>) -> $crate::Result<()> {
                <$value as $crate::types::tpm::TpmMarshal>::marshal(&self.0, buf)
            }
        }

        impl $crate::types::tpm::TpmUnmarshal for $name {
            fn unmarshal(input: &mut &[u8]) -> $crate::Result<Self> {
                Ok(Self(<$value as $crate::types::tpm::TpmUnmarshal>::unmarshal(input)?))
            }
        }
    };

    ($name:ident($inner:ty) => $value:ty) => {
        $crate::macros::newtype!(pub(crate) $name($inner) => $value);
    };

    ($vis:vis $name:ident($inner:ty) => $value:ty) => {
        $crate::macros::newtype!(@raw $vis $name($inner) => $value);

        impl $crate::types::tpm::TpmMarshal for $name {
            fn marshal(&self, buf: &mut Vec<u8>) -> $crate::Result<()> {
                <$value as $crate::types::tpm::TpmMarshal>::marshal(&self.value(), buf)
            }
        }

        impl $crate::types::tpm::TpmUnmarshal for $name {
            fn unmarshal(input: &mut &[u8]) -> $crate::Result<Self> {
                <$value as $crate::types::tpm::TpmUnmarshal>::unmarshal(input)?.try_into()
            }
        }
    };

    (@raw $vis:vis $name:ident($inner:ty) => $value:ty) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        $vis struct $name($inner);

        impl $name {
            pub(crate) fn value(&self) -> $value {
                self.0.value()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "0x{:0width$X}",
                    self.value(),
                    width = std::mem::size_of::<$value>() * 2,
                )
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };

    ($vis:vis $name:ident($inner:ty)) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        $vis struct $name($inner);
    };
}

macro_rules! newtype_in_win {
    ($($tt:tt)*) => {
        $crate::macros::newtype!(pub(in crate::backend::windows) $($tt)*);
    };
}

pub(crate) use {
    impl_buffer_methods, impl_tpm2b_codec, impl_try_from_bytes, impl_tpm2b_size_consts, 
    impl_tpm2b_inner_codec, newtype, newtype_in_win, 
    tpm_list_type, tpm2b_type, tpm2b_type_in_win, tpm2b_zeroize_type_in_win,
    tpm2b_zeroize_type, unknown_tpm_data,
};
