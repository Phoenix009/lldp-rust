use std::fmt::Display;

use crate::tlv::TlvType;
use bytes::BufMut;

/// Organizationally Specific TLV
///
/// This TLV type is provided to allow organizations, software developers and equipment vendors to define TLVs
/// to advertise information to remote devices which can not be included in other TLV types.
///
/// It is an optional TLV and as such may be included in an LLDPDU zero or more times between the TTL TLV and the
/// End of LLDPDU TLV.
///
/// # TLV Format:
///
///      0               1               2               5               6
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-|
///     |             |                 |    Organiz.   |    Organiz.   |   Organizationally  |
///     |     127     |      Length     |   Unique ID   |    Defined    | Defined Information |
///     |             |                 |     (OUI)     |    Subtype    |       (Value)       |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-|
///
///                                                                          0 - 507 byte
///
/// The OUI is a 24 bit number uniquely identifying a vendor, manufacturer or organization.
///
/// The subtype should be a unique subtype value assigned by the defining organization.
#[derive(Debug, Clone)]
pub struct OrganizationallySpecificTLV {
    /// The type of the TLV
    pub tlv_type: TlvType,
    /// Organizationally unique identifier
    pub oui: Vec<u8>,
    /// Organizationally defined subtype
    pub subtype: u8,
    /// Organizationally defined information
    pub value: Vec<u8>,
}

impl Display for OrganizationallySpecificTLV {
    /// Write a printable representation of the TLV object.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut oui = String::new();
        for i in &self.oui {
            oui.push_str(&format!("{:X}", i));
        }

        let mut value = String::new();
        for i in &self.value {
            value.push_str(&format!("{:X}", i));
        }

        write!(
            f,
            "OrganizationallySpecificTLV(\"{}\", {}, \"{}\")",
            oui, self.subtype, value
        )
    }
}

impl OrganizationallySpecificTLV {
    /// Constructor
    pub fn new(oui: Vec<u8>, subtype: u8, value: Vec<u8>) -> OrganizationallySpecificTLV {
        // TODO: Implement
        OrganizationallySpecificTLV {
            tlv_type: TlvType::OrganizationallySpecific,
            oui: oui,
            subtype: subtype,
            value: value,
        }
    }

    /// Create a TLV instance from raw bytes.
    ///
    /// Panics if the provided TLV contains errors (e.g. has the wrong type).
    pub fn new_from_bytes(bytes: &[u8]) -> OrganizationallySpecificTLV {
        let mut type_field = bytes[0] & 0b11111110;
        type_field = type_field >> 1;

        if type_field != TlvType::OrganizationallySpecific as u8 {
            panic!("Wrong TLV Type for ChassisId_Tlv");
        }

        let mut length = bytes[1] as usize;
        if bytes[0] & 1 == 1 {
            length += 1 << 9;
        }

        assert_eq!(length, bytes[2..].len());

        let oui = bytes[2..5].to_vec();
        let subtype = bytes[5];
        let value = bytes[6..].to_vec();
        println!("{:?}", value);

        OrganizationallySpecificTLV::new(oui, subtype, value)
    }

    /// Return the length of the TLV value
    pub fn len(&self) -> usize {
        4 + self.value.len()
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

        result.extend_from_slice(&self.oui);
        result.push(self.subtype);
        result.extend_from_slice(&self.value);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_up() -> (OrganizationallySpecificTLV, Vec<u8>, u8, String) {
        let oui = b"\xAA\xBB\xCC".to_vec();
        let subtype = 5;
        let data = String::from("HURZ!");
        let tlv = OrganizationallySpecificTLV::new(oui.clone(), subtype, data.as_bytes().to_vec());
        (tlv, oui, subtype, data)
    }

    #[test]
    fn test_type() {
        let (tlv, _, _, _) = set_up();
        assert_eq!(tlv.tlv_type as u8, TlvType::OrganizationallySpecific as u8);
    }

    #[test]
    fn test_length() {
        let (tlv, _, _, data) = set_up();
        assert_eq!(tlv.len(), data.len() + 4);
    }

    #[test]
    fn test_value() {
        let (tlv, _, _, data) = set_up();
        assert_eq!(tlv.value, data.as_bytes().to_vec());
    }

    #[test]
    fn test_subtype() {
        let (tlv, _, subtype, _) = set_up();
        assert_eq!(tlv.subtype, subtype);
    }

    #[test]
    fn test_dump() {
        let (tlv, oui, subtype, data) = set_up();
        let mut bytes = b"\xFE".to_vec();
        bytes.put_u8(data.as_bytes().len() as u8 + 4);
        bytes.put(oui.as_slice());
        bytes.put_u8(subtype);
        bytes.put(data.as_bytes());

        assert_eq!(tlv.bytes(), bytes);
    }

    #[test]
    fn test_load() {
        let tlv = OrganizationallySpecificTLV::new_from_bytes(
            b"\xFE\x1D\xAA\xBB\xCC\x1A0118 999 88199 9119 725 3".as_ref(),
        );
        assert_eq!(tlv.len(), 29);
        assert_eq!(tlv.value, b"0118 999 88199 9119 725 3".to_vec());
        assert_eq!(tlv.oui, b"\xAA\xBB\xCC".to_vec());
        assert_eq!(tlv.subtype, 0x1A);
    }

    #[test]
    fn test_display() {
        let (tlv, _, _, _) = set_up();
        assert_eq!(
            format!("{}", tlv),
            "OrganizationallySpecificTLV(\"AABBCC\", 5, \"4855525A21\")"
        );
    }
}
