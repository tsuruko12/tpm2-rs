use crate::{
    Result, backend::windows::codec::TpmMarshal, types::{CapabilityData, TpmCap, TpmCc},
};
use super::Context;
use super::super::{
    commands::Command,
    codec::GetCapabilityResponse,
};

impl Context {
    pub(crate) fn get_capability_once(
        &mut self,
        capability: TpmCap,
        property: u32,
        property_count: u32,
    ) -> Result<(bool, CapabilityData)> {
        let mut request_params = Vec::new();

        capability.raw().marshal(&mut request_params)?;
        property.marshal(&mut request_params)?;
        property_count.marshal(&mut request_params)?;

        let command = Command::new(TpmCc::GET_CAPABILITY)
            .with_parameters(&request_params);

        let response_body = self.submit(command)?;
        
        GetCapabilityResponse::parse(&response_body, capability)
            .map(|response| (response.more_data, response.capability_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_params(more_data: u8, capability: TpmCap, count: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        bytes.push(more_data);
        bytes.extend_from_slice(&capability.raw().to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());

        bytes
    }

    fn parse_response_params(
        response: &[u8],
        capability: TpmCap,
    ) -> Result<(bool, CapabilityData)> {
        let response = GetCapabilityResponse::parse(response, capability)?;
        Ok((response.more_data, response.capability_data))
    }

    #[test]
    fn rejects_truncated_response() {
        let response = [0; 8];

        assert!(parse_response_params(&response, TpmCap::Handles).is_err());
    }

    #[test]
    fn rejects_invalid_more_data() {
        let response = response_params(2, TpmCap::Handles, 0);

        assert!(parse_response_params(&response, TpmCap::Handles).is_err());
    }

    #[test]
    fn rejects_mismatched_capability() {
        let response = response_params(0, TpmCap::Algorithms, 0);

        assert!(parse_response_params(&response, TpmCap::Handles).is_err());
    }

    #[test]
    fn accepts_empty_capability_list() {
        let response = response_params(0, TpmCap::Handles, 0);
        let (more_data, capability_data) =
            parse_response_params(&response, TpmCap::Handles).unwrap();

        assert!(!more_data);
        assert!(matches!(capability_data, CapabilityData::Handles(items) if items.is_empty()));
    }

    #[test]
    fn rejects_trailing_response_bytes() {
        let mut response = response_params(0, TpmCap::Handles, 0);
        response.push(0);

        assert!(parse_response_params(&response, TpmCap::Handles).is_err());
    }
}
