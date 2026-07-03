use super::CommandHeader;

#[derive(Debug)]
pub(crate) struct Command {
    header: CommandHeader,
    params: Vec<u8>, // marshaled parameters
}

impl Command {
    pub(crate) fn new(
        header: CommandHeader,
        params: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            header,
            params: params.into(),
        }
    }

    pub(crate) fn marshal(&self) -> Vec<u8> {
        let mut buf = self.header.marshal();
        buf.extend_from_slice(&self.params);

        buf
    }
}
