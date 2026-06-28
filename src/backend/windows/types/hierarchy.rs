#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hierarchy {
    Storage,
    Platform,
    Endorsement,
}

impl Hierarchy {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Hierarchy::Storage => "owner",
            Hierarchy::Platform => "platform",
            Hierarchy::Endorsement => "endorsement",
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
