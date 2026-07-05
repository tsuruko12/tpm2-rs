use super::{
    TpmAlgId, TpmCc, TpmEccCurve, TpmHandle, TpmaAlgorithm, TpmaCc, TpmlAlgProperty, TpmlCc,
    TpmlCca, TpmlEccCurve, TpmlHandle, TpmlPcrSelection, TpmlTaggedPcrProperty,
    TpmlTaggedTpmProperty, TpmsAlgProperty, TpmsPcrSelection, TpmsTaggedPcrSelect,
    TpmsTaggedProperty,
};
use crate::error::{Error, Result};

pub(crate) fn require_len(bytes: &[u8], required: usize) -> Result<()> {
    if bytes.len() < required {
        return Err(Error::Internal(
            "invalid TPM response: parameters are truncated",
        ));
    }

    Ok(())
}

pub(crate) fn unmarshal_tpm2b(mut bytes: &[u8]) -> Result<Vec<u8>> {
    let size = read_u16(&mut bytes)? as usize;
    let value = read_vec(&mut bytes, size)?;

    ensure_consumed(bytes)?;

    Ok(value)
}

pub(crate) fn unmarshal_algs(mut bytes: &[u8], count: usize) -> Result<TpmlAlgProperty> {
    validate_count(bytes.len(), count, 6)?;

    let mut items = Vec::with_capacity(count);

    for _ in 0..count {
        let alg_id = TpmAlgId::try_from(read_u16(&mut bytes)?)?;
        let alg_properties = TpmaAlgorithm::new(read_u32(&mut bytes)?);

        items.push(TpmsAlgProperty::new(alg_id, alg_properties));
    }

    ensure_consumed(bytes)?;

    Ok(TpmlAlgProperty::new(items))
}

pub(crate) fn unmarshal_handles(mut bytes: &[u8], count: usize) -> Result<TpmlHandle> {
    validate_count(bytes.len(), count, 4)?;

    let mut items = Vec::with_capacity(count);

    for _ in 0..count {
        let handle = read_u32(&mut bytes)?;
        items.push(handle);
    }

    ensure_consumed(bytes)?;

    Ok(TpmlHandle::new(items))
}

pub(crate) fn unmarshal_cca(mut bytes: &[u8], count: usize) -> Result<TpmlCca> {
    validate_count(bytes.len(), count, 4)?;

    let mut items = Vec::with_capacity(count);

    for _ in 0..count {
        let cca = read_u32(&mut bytes)?;
        items.push(TpmaCc::new(cca));
    }

    ensure_consumed(bytes)?;

    Ok(TpmlCca::new(items))
}

pub(crate) fn unmarshal_cc(mut bytes: &[u8], count: usize) -> Result<TpmlCc> {
    validate_count(bytes.len(), count, 4)?;

    let mut items = Vec::with_capacity(count);

    for _ in 0..count {
        let cc = read_u32(&mut bytes)?;
        items.push(cc);
    }

    ensure_consumed(bytes)?;

    Ok(TpmlCc::new(items))
}

pub(crate) fn unmarshal_pcrs(mut bytes: &[u8], count: usize) -> Result<TpmlPcrSelection> {
    validate_count(bytes.len(), count, 3)?;

    let mut items = Vec::with_capacity(count);

    for _ in 0..count {
        let hash = TpmAlgId::try_from(read_u16(&mut bytes)?)?;
        let size_of_select = read_u8(&mut bytes)? as usize;
        let pcr_select = read_vec(&mut bytes, size_of_select)?;

        items.push(TpmsPcrSelection::new(hash, pcr_select));
    }

    ensure_consumed(bytes)?;

    Ok(TpmlPcrSelection::new(items))
}

pub(crate) fn unmarshal_tpm_properties(
    mut bytes: &[u8],
    count: usize,
) -> Result<TpmlTaggedTpmProperty> {
    validate_count(bytes.len(), count, 8)?;

    let mut items = Vec::with_capacity(count);

    for _ in 0..count {
        let property = read_u32(&mut bytes)?;
        let value = read_u32(&mut bytes)?;

        items.push(TpmsTaggedProperty::new(property.try_into()?, value));
    }

    ensure_consumed(bytes)?;

    Ok(TpmlTaggedTpmProperty::new(items))
}

pub(crate) fn unmarshal_pcr_properties(
    mut bytes: &[u8],
    count: usize,
) -> Result<TpmlTaggedPcrProperty> {
    validate_count(bytes.len(), count, 5)?;

    let mut items = Vec::with_capacity(count);

    for _ in 0..count {
        let tag = read_u32(&mut bytes)?;
        let size_of_select = read_u8(&mut bytes)? as usize;
        let pcr_select = read_vec(&mut bytes, size_of_select)?;

        items.push(TpmsTaggedPcrSelect::new(tag.try_into()?, pcr_select));
    }

    ensure_consumed(bytes)?;

    Ok(TpmlTaggedPcrProperty::new(items))
}

pub(crate) fn unmarshal_ecc_curves(mut bytes: &[u8], count: usize) -> Result<TpmlEccCurve> {
    validate_count(bytes.len(), count, 2)?;

    let mut items = Vec::with_capacity(count);

    for _ in 0..count {
        let curve = read_u16(&mut bytes)?;
        items.push(curve.try_into()?);
    }

    ensure_consumed(bytes)?;

    Ok(TpmlEccCurve::new(items))
}

fn validate_count(bytes_len: usize, count: usize, item_size: usize) -> Result<()> {
    let minimum_size = count
        .checked_mul(item_size)
        .ok_or(Error::Internal("TPM item count overflow"))?;

    if minimum_size > bytes_len {
        return Err(Error::Internal("TPM item count exceeds buffer length"));
    }

    Ok(())
}

fn ensure_consumed(input: &[u8]) -> Result<()> {
    if !input.is_empty() {
        return Err(Error::Internal("TPM buffer contains trailing bytes"));
    }

    Ok(())
}

fn read_u8(input: &mut &[u8]) -> Result<u8> {
    let (&value, remaining) = input
        .split_first()
        .ok_or(Error::Internal("invalid TPM response: missing BYTE"))?;

    *input = remaining;

    Ok(value)
}

fn read_u16(input: &mut &[u8]) -> Result<u16> {
    let bytes = input
        .get(..2)
        .ok_or(Error::Internal("invalid TPM response: missing UINT16"))?;
    let value = u16::from_be_bytes(bytes.try_into().unwrap());

    *input = &input[2..];

    Ok(value)
}

fn read_u32(input: &mut &[u8]) -> Result<u32> {
    let bytes = input
        .get(..4)
        .ok_or(Error::Internal("invalid TPM response: missing UINT32"))?;
    let value = u32::from_be_bytes(bytes.try_into().unwrap());

    *input = &input[4..];

    Ok(value)
}

fn read_vec(input: &mut &[u8], len: usize) -> Result<Vec<u8>> {
    let value = input.get(..len).ok_or(Error::Internal(
        "invalid TPM response: BYTE array is truncated",
    ))?;
    let value = value.to_vec();

    *input = &input[len..];

    Ok(value)
}
