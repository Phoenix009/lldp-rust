use std::{convert::TryInto, fmt::Display};

use crate::tlv::TlvType;

/// Port Description TLV
///
/// The Port Description TLV allows network management to advertise the device's port description.
///
/// It is an optional TLV and as such may be included in an LLDPDU zero or more times between
/// the TTL TLV and the End of LLDPDU TLV.
///
/// # TLV Format:
///
///      0                   1                   2
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+
///     |             |                 |                           |
///     |      4      |      Length     |     Port Description      |
///     |             |                 |                           |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+
///
///                                             0 - 255 byte
#[derive(Debug, Clone)]
pub struct PortDescriptionTLV {
    /// The type of the TLV
    pub tlv_type: TlvType,
    /// The port description
    pub value: String,
}

impl Display for PortDescriptionTLV {
    /// Write a printable representation of the TLV object.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: Implement
        write!(f, "PortDescriptionTLV(\"{}\")", self.value)
    }
}

impl PortDescriptionTLV {
    /// Constructor
    pub fn new(value: String) -> PortDescriptionTLV {
        PortDescriptionTLV {
            tlv_type: TlvType::PortDescription,
            value: value,
        }
    }

    /// Create a TLV instance from raw bytes.
    ///
    /// Panics if the provided TLV contains errors (e.g. has the wrong type).
    pub fn new_from_bytes(bytes: &[u8]) -> PortDescriptionTLV {
        let mut type_field = bytes[0] & 0b11111110;
        type_field = type_field >> 1;

        if type_field != TlvType::PortDescription as u8 {
            panic!("Wrong TLV Type for PortDescription");
        }

        let mut length = bytes[1] as usize;
        if bytes[0] & 1 == 1 {
            length += 1 << 9;
        }

        assert!(length < 512, "length overflow");

        let vec = bytes[2..].to_vec();

        let value = match String::from_utf8(vec) {
            Ok(value) => value,
            Err(_) => panic!("could not parse value for PortDescription"),
        };

        assert_eq!(length, value.len(), "Length field is incorrect");

        PortDescriptionTLV {
            tlv_type: TlvType::PortDescription,
            value: value,
        }
    }

    /// Return the length of the TLV value
    pub fn len(&self) -> usize {
        self.value.len()
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

        let value_bytes: Vec<u8> = self.value.as_bytes().to_vec();
        result.extend_from_slice(&value_bytes);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_up() -> (PortDescriptionTLV, String) {
        let string = String::from("Unittest");
        (PortDescriptionTLV::new(string.clone()), string)
    }

    #[test]
    fn test_type() {
        let (tlv, _) = set_up();
        assert_eq!(tlv.tlv_type as u8, TlvType::PortDescription as u8);
        assert_eq!(tlv.tlv_type as u8, 4);
    }

    #[test]
    fn test_length() {
        let (tlv, _) = set_up();
        assert_eq!(tlv.len(), 8);
    }

    #[test]
    fn test_value() {
        let (tlv, s) = set_up();
        assert_eq!(tlv.value, s);
    }

    #[test]
    fn test_dump() {
        let (tlv, _) = set_up();
        assert_eq!(tlv.bytes(), b"\x08\x08Unittest".to_vec());
    }

    #[test]
    fn test_load() {
        let tlv = PortDescriptionTLV::new_from_bytes(b"\x08\x0FAnotherUnittest".as_ref());
        assert_eq!(tlv.len(), 15);
        assert_eq!(tlv.value, String::from("AnotherUnittest"));
    }

    #[test]
    fn test_display() {
        let (tlv, _) = set_up();
        assert_eq!(format!("{}", tlv), "PortDescriptionTLV(\"Unittest\")");
    }
}
