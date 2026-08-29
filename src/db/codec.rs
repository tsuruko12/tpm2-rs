use tracing::debug;

use crate::{
    types::{
        algorithm::HashAlgorithm,
        policy::{PcrSelection, PcrSlot, PolicyBranchData, PolicyCommand, PolicyData},
        tpm::{ensure_consumed, TpmCc, TpmMarshal, TpmUnmarshal, TpmiAlgHash, TpmlDigest},
    },
    Error, Result,
};

const POLICY_DATA_FORMAT_VERSION: u8 = 2;

pub(super) trait StoreEncode {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<()>;
}

pub(super) trait StoreDecode: Sized {
    fn decode(input: &mut &[u8]) -> Result<Self>;
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyTag {
    Pcr = 0,
    Command = 1,
    AuthValue = 2,
    Password = 3,
    Or = 4,
    Sequence = 5,
}

impl TryFrom<u8> for PolicyTag {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Pcr),
            1 => Ok(Self::Command),
            2 => Ok(Self::AuthValue),
            3 => Ok(Self::Password),
            4 => Ok(Self::Or),
            5 => Ok(Self::Sequence),
            _ => Err(Error::conversion::<u8, PolicyTag>(None)),
        }
    }
}

impl StoreEncode for PolicyTag {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        (*self as u8).marshal(buf)
    }
}

impl StoreDecode for PolicyTag {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let tag = u8::unmarshal(input).map_err(Error::corrupted_store_with_source)?;
        Self::try_from(tag)
    }
}

impl StoreEncode for PolicyCommand {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        TpmCc::from(*self).marshal(buf)
    }
}

impl StoreDecode for PolicyCommand {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let command_code = TpmCc::unmarshal(input).map_err(Error::corrupted_store_with_source)?;
        Self::try_from(command_code).map_err(Error::corrupted_store_with_source)
    }
}

impl StoreEncode for PcrSlot {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        (*self as u8).marshal(buf)
    }
}

impl StoreDecode for PcrSlot {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let slot = u8::unmarshal(input).map_err(Error::corrupted_store_with_source)?;
        Self::try_from(slot).map_err(Error::corrupted_store_with_source)
    }
}

impl StoreEncode for PcrSelection {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        TpmiAlgHash::from(self.hash_alg()).marshal(buf)?;

        let slots = self.slots();
        debug_assert!(slots.len() <= usize::from(PcrSlot::MAX) + 1);
        (slots.len() as u8).marshal(buf)?;

        for slot in slots {
            slot.encode(buf)?;
        }

        Ok(())
    }
}

impl StoreDecode for PcrSelection {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let hash_alg = TpmiAlgHash::unmarshal(input).map_err(Error::corrupted_store_with_source)?;
        let hash_alg = HashAlgorithm::try_from(hash_alg)
            .map_err(Error::corrupted_store_with_source)?;
        let slot_count =
            usize::from(u8::unmarshal(input).map_err(Error::corrupted_store_with_source)?);
        if slot_count > usize::from(PcrSlot::MAX) + 1 {
            debug!("stored policy PCR slot count is invalid");
            return Err(Error::corrupted_store());
        }

        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            slots.push(PcrSlot::decode(input)?);
        }

        Self::new(hash_alg, &slots).map_err(Error::corrupted_store_with_source)
    }
}

pub(super) fn marshal_policy_data(policy: &PolicyData) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    POLICY_DATA_FORMAT_VERSION.marshal(&mut buf)?;
    policy.encode(&mut buf)?;

    Ok(buf)
}

pub(super) fn unmarshal_policy_data(bytes: &[u8]) -> Result<PolicyData> {
    let mut input = bytes;
    let version = u8::unmarshal(&mut input).map_err(Error::corrupted_store_with_source)?;
    if version != POLICY_DATA_FORMAT_VERSION {
        debug!(version, "unsupported stored policy data format version");
        return Err(Error::corrupted_store());
    }

    let policy = PolicyData::decode(&mut input)?;
    ensure_consumed(input).map_err(Error::corrupted_store_with_source)?;

    Ok(policy)
}

impl StoreEncode for PolicyData {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            PolicyData::AuthValue => PolicyTag::AuthValue.encode(buf),
            PolicyData::Password => PolicyTag::Password.encode(buf),
            PolicyData::Pcr(selection) => {
                PolicyTag::Pcr.encode(buf)?;
                selection.encode(buf)
            }
            PolicyData::Command(command) => {
                PolicyTag::Command.encode(buf)?;
                command.encode(buf)
            }
            PolicyData::Or {
                branches,
                branch_digests,
                ..
            } => {
                PolicyTag::Or.encode(buf)?;
                branch_digests.marshal(buf)?;
                encode_policy_branch_list(branches, buf)
            }
            PolicyData::Sequence(steps) => {
                PolicyTag::Sequence.encode(buf)?;
                encode_policy_data_list(steps, buf)
            }
        }
    }
}

impl StoreDecode for PolicyData {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        match PolicyTag::decode(input)? {
            PolicyTag::AuthValue => Ok(PolicyData::AuthValue),
            PolicyTag::Password => Ok(PolicyData::Password),
            PolicyTag::Pcr => Ok(PolicyData::Pcr(PcrSelection::decode(input)?)),
            PolicyTag::Command => Ok(PolicyData::Command(PolicyCommand::decode(input)?)),
            PolicyTag::Or => Ok(PolicyData::Or {
                branch_digests: TpmlDigest::unmarshal(input)
                    .map_err(Error::corrupted_store_with_source)?,
                branches: decode_policy_branch_list(input)?,
                selected_label: None,
            }),
            PolicyTag::Sequence => Ok(PolicyData::Sequence(decode_policy_data_list(input)?)),
        }
    }
}

fn encode_policy_data_list(policies: &[PolicyData], buf: &mut Vec<u8>) -> Result<()> {
    let count = u32::try_from(policies.len())
        .map_err(|_| Error::InvalidPolicy("policy contains too many entries to store"))?;
    count.marshal(buf)?;

    for policy in policies {
        policy.encode(buf)?;
    }

    Ok(())
}

fn decode_policy_data_list(input: &mut &[u8]) -> Result<Vec<PolicyData>> {
    let count = u32::unmarshal(input).map_err(Error::corrupted_store_with_source)? as usize;
    if count > input.len() {
        debug!("stored policy item count is invalid");
        return Err(Error::corrupted_store());
    }

    let mut policies = Vec::with_capacity(count);
    for _ in 0..count {
        policies.push(PolicyData::decode(input)?);
    }

    Ok(policies)
}

impl StoreEncode for PolicyBranchData {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        encode_policy_branch_label(&self.label, buf)?;
        self.policy.encode(buf)
    }
}

impl StoreDecode for PolicyBranchData {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            label: decode_policy_branch_label(input)?,
            policy: PolicyData::decode(input)?,
        })
    }
}

fn encode_policy_branch_list(branches: &[PolicyBranchData], buf: &mut Vec<u8>) -> Result<()> {
    let count = u32::try_from(branches.len())
        .map_err(|_| Error::InvalidPolicy("policy contains too many entries to store"))?;
    count.marshal(buf)?;

    for branch in branches {
        branch.encode(buf)?;
    }

    Ok(())
}

fn decode_policy_branch_list(input: &mut &[u8]) -> Result<Vec<PolicyBranchData>> {
    let count = u32::unmarshal(input).map_err(Error::corrupted_store_with_source)? as usize;
    if count > input.len() {
        debug!("stored policy branch count is invalid");
        return Err(Error::corrupted_store());
    }

    let mut branches = Vec::with_capacity(count);
    for _ in 0..count {
        branches.push(PolicyBranchData::decode(input)?);
    }

    Ok(branches)
}

fn encode_policy_branch_label(label: &str, buf: &mut Vec<u8>) -> Result<()> {
    let bytes = label.as_bytes();
    let len = u32::try_from(bytes.len())
        .map_err(|_| Error::InvalidPolicy("policy branch label is too long to store"))?;
    len.marshal(buf)?;
    buf.extend_from_slice(bytes);

    Ok(())
}

fn decode_policy_branch_label(input: &mut &[u8]) -> Result<String> {
    let len = u32::unmarshal(input).map_err(Error::corrupted_store_with_source)? as usize;
    if len > input.len() {
        debug!("stored policy branch label length is invalid");
        return Err(Error::corrupted_store());
    }

    let (bytes, remaining) = input.split_at(len);
    *input = remaining;

    String::from_utf8(bytes.to_vec()).map_err(Error::corrupted_store_with_source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_data_round_trip_clears_selection() {
        let policy = PolicyData::Sequence(vec![
            PolicyData::Pcr(
                PcrSelection::new(HashAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot7])
                    .expect("PCR selection must be valid"),
            ),
            PolicyData::Command(PolicyCommand::Sign),
            PolicyData::Or {
                branches: vec![
                    PolicyBranchData {
                        label: "auth".to_string(),
                        policy: PolicyData::AuthValue,
                    },
                    PolicyBranchData {
                        label: "password".to_string(),
                        policy: PolicyData::Password,
                    },
                ],
                branch_digests: TpmlDigest::default(),
                selected_label: Some("auth".to_string()),
            },
        ]);

        let bytes = marshal_policy_data(&policy).expect("policy data must marshal");

        let PolicyData::Sequence(steps) =
            unmarshal_policy_data(&bytes).expect("policy data must unmarshal")
        else {
            panic!("decoded policy must be a sequence");
        };

        assert!(matches!(
            &steps[0],
            PolicyData::Pcr(selection)
                if selection.hash_alg() == HashAlgorithm::Sha256
                    && selection.slots() == &[PcrSlot::Slot0, PcrSlot::Slot7]
        ));
        assert!(matches!(
            &steps[1],
            PolicyData::Command(PolicyCommand::Sign)
        ));
        assert!(matches!(
            &steps[2],
            PolicyData::Or {
                branches,
                selected_label: None,
                ..
            } if matches!(branches.as_slice(), [
                PolicyBranchData {
                    label,
                    policy: PolicyData::AuthValue,
                },
                PolicyBranchData {
                    label: second_label,
                    policy: PolicyData::Password,
                },
            ] if label == "auth" && second_label == "password")
        ));
    }
}
