use super::{Command, CommandResources, Context, GetCapabilityResponse};
use crate::{
    Result,
    types::tpm::{CapabilityData, TpmCap, TpmCc, TpmMarshal},
};

const RESPONSE_HANDLE_COUNT: usize = 0;

impl Context {
    pub(super) fn get_capability_once(
        &mut self,
        capability: TpmCap,
        property: u32,
        property_count: u32,
    ) -> Result<(CapabilityData, bool)> {
        let mut command_params = Vec::new();
        capability.marshal(&mut command_params)?;
        property.marshal(&mut command_params)?;
        property_count.marshal(&mut command_params)?;

        let mut command = Command::new(TpmCc::GET_CAPABILITY)
            .with_parameters(&mut command_params);

        let response_body = self.submit(
            &mut command, 
            RESPONSE_HANDLE_COUNT, 
            &mut CommandResources::default(),
        )?;

        GetCapabilityResponse::parse(response_body, capability)
            .map(|response| (response.capability_data, response.more_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_params(more_data: u8, capability: TpmCap, count: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        bytes.push(more_data);
        bytes.extend_from_slice(&capability.value().to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());

        bytes
    }

    fn parse_response_params(
        response: &[u8],
        capability: TpmCap,
    ) -> Result<(bool, CapabilityData)> {
        let response = GetCapabilityResponse::parse(
            super::super::ResponseBody {
                handles: Vec::new(),
                parameters: response.to_vec(),
            },
            capability,
        )?;
        Ok((response.more_data, response.capability_data))
    }

    #[test]
    fn rejects_mismatched_capability() {
        let response = response_params(0, TpmCap::Algorithms, 0);
        assert!(parse_response_params(&response, TpmCap::Handles).is_err());
    }
}
