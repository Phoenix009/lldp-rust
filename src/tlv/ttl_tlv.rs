use crate::tlv::TlvType;
use bytes::{Buf, BufMut};
use std::fmt::Display;

/// Time To Live TLV
///
/// The Time To Live TLV indicates the number of seconds that the recipient LLDP agent is to regard the information
/// associated with the transmitting LLDP agent as valid.
///
/// The Time To Live TLV is mandatory and MUST be the third TLV in the LLDPDU.
/// Each LLDPDU MUST contain one, and only one, TTL TLV.
///
/// # TLV Format:
///
///      0                   1                   2                   3
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |             |                 |                               |
///     |      3      |      Length     |               TTL             |
///     |             |                 |                               |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Clone)]
pub struct TtlTLV {
    /// The type of the TLV
    pub tlv_type: TlvType,
    /// The TTL in seconds
    pub value: u16,
}

impl Display for TtlTLV {
    /// Write a printable representation of the TLV object.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: Implement
        write!(f, "TtlTLV({})", self.value)
    }
}

impl TtlTLV {
    /// Constructor
    pub fn new(ttl: u16) -> TtlTLV {
        // TODO: Implement
        TtlTLV {
            tlv_type: TlvType::Ttl,
            value: ttl,
        }
    }

    /// Create a TLV instance from raw bytes.
    ///
    /// Panics if the provided TLV contains errors (e.g. has the wrong type).
    pub fn new_from_bytes(bytes: &[u8]) -> TtlTLV {
        let mut type_field = bytes[0] & 0b11111110;
        type_field = type_field >> 1;

        if type_field != TlvType::Ttl as u8 {
            panic!("Wrong TLV Type for TTL");
        }

        let mut length = bytes[1] as usize;
        if bytes[0] & 1 == 1 {
            length += 1 << 9;
        }

        assert_eq!(length, 2, "length should be 2 for TTL");

        let value = ((bytes[2] as u16) << 8) | bytes[3] as u16;

        TtlTLV::new(value)
    }

    /// Return the length of the TLV value
    pub fn len(&self) -> usize {
        2
    }

    /// Return the byte representation of the TLV.
    pub fn bytes(&self) -> Vec<u8> {
        let mut type_field = (self.tlv_type as u8) << 1;

        let length_field = self.len();
        if length_field & (1 << 9) == 1 {
            type_field |= 1;
        }

        let length_field = length_field as u8;

        let mut result: Vec<u8> = Vec::new();
        result.push(type_field);
        result.push(length_field);

        result.push(((self.value & 0xFF00) >> 8) as u8);
        result.push((self.value & 0x00FF) as u8);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_up() -> (TtlTLV, u16) {
        let r = 36575;
        (TtlTLV::new(r), r)
    }

    #[test]
    fn test_type() {
        let (ttltlv, _) = set_up();
        assert_eq!(ttltlv.tlv_type as u8, 3);
    }

    #[test]
    fn test_length() {
        let (ttltlv, _) = set_up();
        assert_eq!(ttltlv.len(), 2);
    }

    #[test]
    fn test_value() {
        let (ttltlv, r) = set_up();
        assert_eq!(ttltlv.value, r);
    }

    #[test]
    fn test_dump() {
        let (ttltlv, r) = set_up();
        let mut b = vec![6, 2];
        b.put_u16(r);
        assert_eq!(ttltlv.bytes(), b);
    }

    #[test]
    fn test_load() {
        let ttltlv = TtlTLV::new_from_bytes(b"\x06\x02\x00\x78".as_ref());
        assert_eq!(ttltlv.value, 120);
    }

    #[test]
    #[should_panic]
    fn test_load_invalid_length() {
        TtlTLV::new_from_bytes(b"\x06\x03\x00\x78\x00".as_ref());
    }

    #[test]
    #[should_panic]
    fn test_load_incorrect_length() {
        TtlTLV::new_from_bytes(b"\x06\x01\x00\x78".as_ref());
    }

    #[test]
    fn test_display() {
        let (tlv, _) = set_up();
        assert_eq!(format!("{}", tlv), "TtlTLV(36575)");
    }
}
