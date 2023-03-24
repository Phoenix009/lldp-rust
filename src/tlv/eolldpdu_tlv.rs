use std::fmt::Display;

use crate::tlv::TlvType;

/// End of LLDP Data Unit TLV
///
/// The End of LLDPDU TLV is an optional TLV marking the end of an LLDP data unit (LLDPDU).
/// It MUST be the last TLV in an LLDPDU and can only be included once.
///
/// # TLV Format:
///
///      0                   1
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |             |                 |
///     |      0      |       0x0       |
///     |             |                 |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Clone)]
pub struct EndOfLLDPDUTLV {
    /// The type of the TLV
    pub tlv_type: TlvType,
}

impl Display for EndOfLLDPDUTLV {
    /// Write a printable representation of the TLV object.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: Implement
        write!(f, "EndOfLLDPDUTLV")
    }
}

impl EndOfLLDPDUTLV {
    /// Constructor
    pub fn new() -> EndOfLLDPDUTLV {
        EndOfLLDPDUTLV {
            tlv_type: TlvType::EndOfLLDPDU,
        }
    }

    /// Create a TLV instance from raw bytes.
    ///
    /// Panics if the provided TLV contains errors (e.g. has the wrong type).
    pub fn new_from_bytes(bytes: &[u8]) -> EndOfLLDPDUTLV {
        let mut type_field = bytes[0] & 0b11111110;
        type_field = type_field >> 1;

        if type_field != 0u8 {
            panic!("Wrong TLV Type for EndOfLLDPDU");
        }
        EndOfLLDPDUTLV::new()
    }

    /// Return the length of the TLV value
    pub fn len(&self) -> usize {
        return 0;
    }

    /// Return the byte representation of the TLV.
    pub fn bytes(&self) -> Vec<u8> {
        vec![0, 0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_up() -> EndOfLLDPDUTLV {
        EndOfLLDPDUTLV::new()
    }

    #[test]
    fn test_eolldpdu_type() {
        let tlv = set_up();
        assert_eq!(tlv.tlv_type as u8, 0);
    }
    #[test]
    fn test_eolldpdu_length() {
        let tlv = set_up();
        assert_eq!(tlv.len(), 0);
    }
    #[test]
    fn test_eolldpdu_dump() {
        let tlv = set_up();
        assert_eq!(tlv.bytes(), b"\x00\x00".to_vec());
    }
    #[test]
    fn test_eolldpdu_load() {
        let tlv = EndOfLLDPDUTLV::new_from_bytes(b"\x00\x00".as_ref());
        assert_eq!(tlv.tlv_type as u8, 0);
    }

    #[test]
    fn test_eolldpdu_display() {
        assert_eq!(format!("{}", EndOfLLDPDUTLV::new()), "EndOfLLDPDUTLV");
    }
}
