use tracing::debug;

use crate::{Error, Result};
use super::tpm::TpmiRhHierarchy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hierarchy {
    Storage,
    Platform,
    Endorsement,
}

impl Hierarchy {
    const OWNER_STR: &str = "owner";
    const PLATFORM_STR: &str = "platform";
    const ENDORSEMENT_STR: &str = "endorsement";

    pub(crate) fn from_db(name: &str) -> Result<Self> {
        match name {
            Self::OWNER_STR => Ok(Self::Storage),
            Self::PLATFORM_STR => Ok(Self::Platform),
            Self::ENDORSEMENT_STR => Ok(Self::Endorsement),
            _ => {
                debug!(%name, "invalid stored TPM key hierarchy");
                Err(Error::corrupted_store())
            }
        }
    }

    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Hierarchy::Storage => Self::OWNER_STR,
            Hierarchy::Platform => Self::PLATFORM_STR,
            Hierarchy::Endorsement => Self::ENDORSEMENT_STR,
        }
    }
}

impl From<Hierarchy> for TpmiRhHierarchy {
    fn from(hierarchy: Hierarchy) -> Self {
        match hierarchy {
            Hierarchy::Endorsement => Self::ENDORSEMENT,
            Hierarchy::Platform => Self::PLATFORM,
            Hierarchy::Storage => Self::OWNER,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HierarchyParseError;

impl std::str::FromStr for Hierarchy {
    type Err = HierarchyParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim() {
            "storage" => Ok(Hierarchy::Storage),
            "endorsement" => Ok(Hierarchy::Endorsement),
            "platform" => Ok(Hierarchy::Platform),
            _ => Err(HierarchyParseError),
        }
    }
}
