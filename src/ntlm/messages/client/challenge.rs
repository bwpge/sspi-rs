use std::{io, slice};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::ntlm::messages::computations::*;
use crate::ntlm::messages::{read_ntlm_header, try_read_version, MessageFields, MessageTypes};
use crate::ntlm::{
    AvId, AvPair, AvValue, ChallengeMessage, NegotiateFlags, Ntlm, NtlmState, CHALLENGE_SIZE, GLOBAL_AV_PAIRS,
};
use crate::SecurityStatus;

const HEADER_SIZE: usize = 48;

struct ChallengeMessageFields {
    target_name: MessageFields,
    target_info: MessageFields,
}

pub(crate) fn read_challenge(context: &mut Ntlm, mut stream: impl io::Read) -> crate::Result<SecurityStatus> {
    check_state(context.state)?;

    let mut buffer = Vec::with_capacity(HEADER_SIZE);
    stream.read_to_end(&mut buffer)?;
    let mut buffer = io::Cursor::new(buffer);

    read_ntlm_header(&mut buffer, MessageTypes::Challenge)?;
    let (mut message_fields, flags, server_challenge) = read_header(&mut buffer)?;
    context.flags = flags;
    let _version = try_read_version(context.flags, &mut buffer)?;
    read_payload(&mut message_fields, &mut buffer)?;
    let timestamp = get_challenge_timestamp_from_response(message_fields.target_info.buffer.as_ref())?;

    let pairs = parse_av_pairs(&message_fields.target_info.buffer);
    if let Ok(mut p) = GLOBAL_AV_PAIRS.lock() {
        *p = pairs;
    }

    let message = buffer.into_inner();
    context.challenge_message = Some(ChallengeMessage::new(
        message,
        message_fields.target_info.buffer,
        server_challenge,
        timestamp,
    ));

    context.state = NtlmState::Authenticate;

    Err(crate::Error {
        error_type: crate::ErrorKind::Unknown,
        description: String::new(),
        nstatus: None,
    })
}

fn check_state(state: NtlmState) -> crate::Result<()> {
    if state != NtlmState::Challenge {
        Err(crate::Error::new(
            crate::ErrorKind::OutOfSequence,
            String::from("Read challenge was fired but the state is not a Challenge"),
        ))
    } else {
        Ok(())
    }
}

fn read_header(
    mut buffer: impl io::Read,
) -> crate::Result<(ChallengeMessageFields, NegotiateFlags, [u8; CHALLENGE_SIZE])> {
    let mut target_name = MessageFields::new();
    let mut target_info = MessageFields::new();

    target_name.read_from(&mut buffer)?;
    let negotiate_flags =
        NegotiateFlags::from_bits(buffer.read_u32::<LittleEndian>()?).unwrap_or_else(NegotiateFlags::empty);
    let mut server_challenge = [0x00; CHALLENGE_SIZE];
    buffer.read_exact(&mut server_challenge)?;
    let _reserved = buffer.read_u64::<LittleEndian>()?;
    target_info.read_from(&mut buffer)?;

    let message_fields = ChallengeMessageFields {
        target_name,
        target_info,
    };

    Ok((message_fields, negotiate_flags, server_challenge))
}

fn read_payload(
    message_fields: &mut ChallengeMessageFields,
    mut buffer: impl io::Read + io::Seek,
) -> crate::Result<()> {
    message_fields.target_name.read_buffer_from(&mut buffer)?;
    message_fields.target_info.read_buffer_from(&mut buffer)?;

    Ok(())
}

// --- AV PAIR PARSING MONKEY PATCH ---

fn parse_av_pairs(buf: &[u8]) -> Vec<AvPair> {
    let mut out = Vec::new();
    let mut offset = 0;

    while offset + 4 <= buf.len() {
        let av_id = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        let av_len = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if av_id == 0 {
            break; // AV_EOL
        }

        if offset + av_len > buf.len() {
            break; // malformed, stop safely
        }

        let value_bytes = &buf[offset..offset + av_len];
        offset += av_len;

        let id = AvId::from(av_id);
        let value = match id {
            AvId::Timestamp if av_len == 8 => {
                let ts = u64::from_le_bytes(value_bytes.try_into().unwrap());
                AvValue::Timestamp(ts)
            }
            AvId::Flags if av_len == 4 => {
                let flags = u32::from_le_bytes(value_bytes.try_into().unwrap());
                AvValue::Flags(flags)
            }
            _ => {
                // Most string values are UTF-16LE
                if av_len >= 2 && av_len % 2 == 0 {
                    let s = utf16le_to_string(value_bytes);
                    AvValue::Utf16(s)
                } else {
                    AvValue::Raw(value_bytes.to_vec())
                }
            }
        };

        out.push(AvPair { id, value });
    }

    out
}

fn utf16le_to_string(bytes: &[u8]) -> String {
    if bytes.len() % 2 != 0 {
        panic!("UTF-16LE data must have an even number of bytes");
    }

    // Convert &[u8] to &[u16] (endianness consideration applies as above)
    let u16_slice: &[u16] = unsafe { slice::from_raw_parts(bytes.as_ptr() as *const u16, bytes.len() / 2) };

    String::from_utf16_lossy(u16_slice)
}
