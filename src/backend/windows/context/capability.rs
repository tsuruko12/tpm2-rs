use crate::{Error, Result, backend::windows::codec::require_len, types::TpmCap};

use super::{CapabilityData, Command, CommandHeader, Context, TPM_CC_GET_CAPABILITY, marshal_be};

const REQUEST_PARAM_SIZE: usize = 12;
const RESPONSE_PARAM_MIN_SIZE: usize = 9;

impl Context {
    pub(crate) fn get_capability_once(
        &mut self,
        capability: TpmCap,
        property: u32,
        property_count: u32,
    ) -> Result<(bool, CapabilityData)> {
        let header = CommandHeader::no_sessions(REQUEST_PARAM_SIZE, TPM_CC_GET_CAPABILITY);
        let request_params = marshal_be!(capability, property, property_count);
        let command = Command::new(header, request_params);

        let response_params = self.submit(command)?;
        unmarshal_capability_response(&response_params, capability)
    }
}

fn unmarshal_capability_response(
    response_params: &[u8],
    capability: TpmCap,
) -> Result<(bool, CapabilityData)> {
    require_len(response_params, RESPONSE_PARAM_MIN_SIZE)?;

    let more_data = match response_params[0] {
        0 => false,
        1 => true,
        _ => {
            return Err(Error::Internal(
                "invalid TPM response: invalid moreData value",
            ));
        }
    };

    let returned_capability = u32::from_be_bytes(response_params[1..5].try_into().unwrap());

    if capability != returned_capability.try_into()? {
        tracing::error!(
            requested = ?capability,
            returned = ?returned_capability,
            "TPM returned unexpected capability type"
        );
        return Err(Error::Internal(
            "invalid TPM response: unexpected capability type",
        ));
    }
    let capability_data = CapabilityData::unmarshal(&response_params[5..], capability)?;

    Ok((more_data, capability_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_params(more_data: u8, capability: TpmCap, count: u32) -> Vec<u8> {
        let mut bytes = vec![more_data];
        bytes.extend_from_slice(&capability.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        
        bytes
    }

    #[test]
    fn rejects_truncated_response() {
        let response = [0; RESPONSE_PARAM_MIN_SIZE - 1];

        assert!(unmarshal_capability_response(&response, TpmCap::Handles).is_err());
    }

    #[test]
    fn rejects_invalid_more_data() {
        let response = response_params(2, TpmCap::Handles, 0);

        assert!(unmarshal_capability_response(&response, TpmCap::Handles).is_err());
    }

    #[test]
    fn rejects_mismatched_capability() {
        let response = response_params(0, TpmCap::Algs, 0);

        assert!(unmarshal_capability_response(&response, TpmCap::Handles).is_err());
    }

    #[test]
    fn accepts_empty_capability_list() {
        let response = response_params(0, TpmCap::Handles, 0);
        let (more_data, capability_data) =
            unmarshal_capability_response(&response, TpmCap::Handles).unwrap();

        assert!(!more_data);
        assert!(matches!(capability_data, CapabilityData::Handles(items) if items.is_empty()));
    }
}
