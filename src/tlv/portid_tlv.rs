use crate::tlv::TlvType;
use bytes::BufMut;

use std::convert::{TryFrom, TryInto};
use std::fmt::Display;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PortIdSubtype {
    InterfaceAlias = 1,
    PortComponent = 2,
    MacAddress = 3,
    NetworkAddress = 4,
    InterfaceName = 5,
    CircuitId = 6,
    Local = 7,
}

impl TryFrom<u8> for PortIdSubtype {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == PortIdSubtype::InterfaceAlias as u8 => Ok(PortIdSubtype::InterfaceAlias),
            x if x == PortIdSubtype::PortComponent as u8 => Ok(PortIdSubtype::PortComponent),
            x if x == PortIdSubtype::MacAddress as u8 => Ok(PortIdSubtype::MacAddress),
            x if x == PortIdSubtype::NetworkAddress as u8 => Ok(PortIdSubtype::NetworkAddress),
            x if x == PortIdSubtype::InterfaceName as u8 => Ok(PortIdSubtype::InterfaceName),
            x if x == PortIdSubtype::CircuitId as u8 => Ok(PortIdSubtype::CircuitId),
            x if x == PortIdSubtype::Local as u8 => Ok(PortIdSubtype::Local),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum PortIdValue {
    Mac(Vec<u8>),
    IpAddress(IpAddr),
    Other(String),
}

/// Port ID TLV
///
/// The port ID TLV identifies the sending port used by the LLDP agent.
///
/// The port ID TLV is mandatory and MUST be the second TLV in the LLDPDU.
/// Each LLDPDU MUST contain one, and only one, Port ID TLV.
///
/// # TLV Format:
///
///         0               1               2               3
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+
///        |             |                 |               |               |
///        |      2      |      Length     |    Subtype    |    Port ID    |
///        |             |                 |               |               |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+
///
///                                                            1 - 255 byte
///
/// # Subtypes
///
/// There are several ways in which a port may be identified.
/// A port ID subtype is used to indicate how the port is being referenced in the Port ID field.
///
/// | Subtype | ID Basis          | Example                    |
/// | ------- | ----------------- | -------------------------- |
/// | 0       | Reserved          |                            |
/// | 1       | Interface Alias   | Ethernet Interface         |
/// | 2       | Port Component    | backplane1                 |
/// | 3       | MAC Address       | 02:04:df:88:a2:b4          |
/// | 4       | Network Address   | 134.96.86.110              |
/// | 5       | Interface Name    | eth0                       |
/// | 6       | Agent Circuit ID  |                            |
/// | 7       | Locally Assigned  | Frank's Computer           |
/// | 8 - 255 | Reserved          |                            |
///
/// With the exception of subtypes 3 (MAC Address) and 4 (Network Address) the subtype is a string
/// as far as the LLDP agent is concerned. A distinction between these types is only made by a human observer.
///
/// ## MAC Address Subtype:
///
/// MAC addresses are represented as raw bytes, e.g. the MAC address 02:04:df:88:a2:b4 corresponds to a value of
/// `b"\x02\x04\xDF\x88\xA2\xB4"`.
///
/// ## Network Address Subtype:
///
/// Network addresses are represented as raw bytes.
///
/// In practice there are many different network protocols, each with their own address format with e.g. a different
/// length.
///
/// To determine the type of network protocol and the appropriate length of the network address transmitted in the
/// port ID TLV, network addresses are prefixed with an extra byte identifying the address family.
///
/// For this implementation we only consider IPv4 and IPv6.
///
/// | Protocol | Family Number |
/// | -------- | ------------- |
/// |   IPv4   |             1 |
/// |   IPv6   |             2 |
///
///     Examples (Address -> Bytes -> Prefixed Bytes):
///         134.96.86.110  ->  b"\x86\x60\x56\x6E"  -> b"\x01\x86\x60\x56\x6E"
///
///         20db::1        ->  b"\x20\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
///                        ->  b"\x02\x20\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
///
/// The full list of registered protocol families is available at:
/// <https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml>
#[derive(Debug, Clone)]
pub struct PortIdTLV {
    /// The type of the TLV
    pub tlv_type: TlvType,
    /// The port ID subtype
    pub subtype: PortIdSubtype,
    /// The port ID.
    ///
    /// The type of the value field depends on the subtype
    /// * Mac Address -> `PortIdValue::Mac(Vec<u8>)`,
    /// * Network Address -> `PortIdValue::IpAddress(IpAddr)`,
    /// * Otherwise -> `PortIdValue::Other(String)`
    pub value: PortIdValue,
}

impl Display for PortIdTLV {
    /// Write a printable representation of the TLV object.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match &self.value {
            PortIdValue::Mac(mac) => {
                let mut result = String::new();
                for (index, i) in mac.iter().enumerate() {
                    result.push_str(&format!("{:X}", i));
                    if index != mac.len() - 1 {
                        result.push_str(&":");
                    }
                }
                result
            }
            PortIdValue::Other(s) => s.clone(),
            PortIdValue::IpAddress(addr) => addr.to_string(),
        };

        write!(f, "PortIdTLV({}, \"{}\")", self.subtype as u8, value)
    }
}

impl PortIdTLV {
    /// Constructor
    ///
    /// The type of the id argument depends on the subtype
    /// * Mac Address -> `PortIdValue::Mac(Vec<u8>)`,
    /// * Network Address -> `PortIdValue::IpAddress(IpAddr)`,
    /// * Otherwise -> `PortIdValue::Other(String)`
    pub fn new(subtype: PortIdSubtype, id: PortIdValue) -> PortIdTLV {
        // TODO: Implement
        PortIdTLV {
            tlv_type: TlvType::PortId,
            subtype: subtype,
            value: id,
        }
    }

    /// Create a TLV instance from raw bytes.
    ///
    /// Panics if the provided TLV contains errors (e.g. has the wrong type).
    pub fn new_from_bytes(bytes: &[u8]) -> PortIdTLV {
        let mut type_field = bytes[0] & 0b11111110;
        type_field = type_field >> 1;

        if type_field != TlvType::PortId as u8 {
            panic!("Wrong TLV Type for ChassisId_Tlv");
        }

        let mut length = bytes[1] as usize;
        if bytes[0] & 1 == 1 {
            length += 1 << 9;
        }

        let subtype = match PortIdSubtype::try_from(bytes[2]) {
            Ok(val) => val,
            Err(_) => panic!("invalid subtype field"),
        };

        let id = match subtype {
            PortIdSubtype::MacAddress => {
                assert_eq!(6, bytes[3..].len());
                PortIdValue::Mac(bytes[3..].to_vec())
            }
            PortIdSubtype::NetworkAddress => match bytes[3] {
                1u8 => {
                    assert_eq!(4, bytes[4..].len());
                    let addr: [u8; 4] = bytes[4..].try_into().unwrap();
                    PortIdValue::IpAddress(IpAddr::from(addr))
                }
                2u8 => {
                    assert_eq!(16, bytes[4..].len());
                    let addr: [u8; 16] = bytes[4..].try_into().unwrap();
                    PortIdValue::IpAddress(IpAddr::from(addr))
                }
                _ => panic!("Expected IP Address specifier"),
            },
            _ => match String::from_utf8(bytes[3..].to_vec()) {
                Ok(value) => PortIdValue::Other(value),
                Err(_) => panic!("Invlaid value for PortId::Other type "),
            },
        };

        PortIdTLV::new(subtype, id)
    }

    /// Return the length of the TLV value
    pub fn len(&self) -> usize {
        1 + match &self.value {
            PortIdValue::Mac(_) => 6,
            PortIdValue::Other(s) => s.len(),
            PortIdValue::IpAddress(IpAddr::V4(_)) => 4 + 1,
            PortIdValue::IpAddress(IpAddr::V6(_)) => 16 + 1,
        }
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

        let subtype_field = self.subtype.clone() as u8;
        result.push(subtype_field);

        let value_field = match &self.value {
            PortIdValue::Mac(addr) => addr.clone(),
            PortIdValue::Other(value) => value.as_bytes().to_vec(),
            PortIdValue::IpAddress(IpAddr::V4(address)) => address.octets().to_vec(),
            PortIdValue::IpAddress(IpAddr::V6(address)) => address.octets().to_vec(),
        };

        if let PortIdValue::IpAddress(IpAddr::V4(_)) = self.value {
            result.push(1);
        }

        if let PortIdValue::IpAddress(IpAddr::V6(_)) = self.value {
            result.push(2);
        }

        result.extend_from_slice(&value_field);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    fn set_up() -> (PortIdTLV, String, PortIdSubtype) {
        let s: String = String::from("Bla bla bla, Mr.Freeman.");
        let st: PortIdSubtype = PortIdSubtype::Local;
        (PortIdTLV::new(st, PortIdValue::Other(s.clone())), s, st)
    }

    #[test]
    fn test_type() {
        let (pidtlv, _, _) = set_up();
        assert_eq!(pidtlv.tlv_type as u8, 2);
    }

    #[test]
    fn test_length() {
        let (pidtlv, value, _) = set_up();
        assert_eq!(pidtlv.len(), value.len() + 1);
    }

    #[test]
    fn test_value() {
        let (pidtlv, value, _) = set_up();
        match pidtlv.value {
            PortIdValue::Other(s) => assert_eq!(s, value),
            v => panic!("Expected OTHER, got {:?}", v),
        }
    }

    #[test]
    fn test_subtype() {
        let (pidtlv, _, subtype) = set_up();
        assert_eq!(pidtlv.subtype, subtype);
    }

    #[test]
    fn test_generic_subtypes() {
        for subtype in [
            PortIdSubtype::InterfaceAlias,
            PortIdSubtype::PortComponent,
            PortIdSubtype::InterfaceName,
            PortIdSubtype::CircuitId,
            PortIdSubtype::Local,
        ] {
            let pidtlv = PortIdTLV::new(
                subtype,
                PortIdValue::Other(String::from("Bla bla bla, Mr.Freeman.")),
            );
            match pidtlv.value {
                PortIdValue::Other(s) => assert_eq!(s, "Bla bla bla, Mr.Freeman."),
                v => panic!("Expected OTHER, got {:?}", v),
            }
            assert_eq!(pidtlv.subtype, subtype);
        }
    }

    #[test]
    fn test_generic_subtypes_dump() {
        for subtype in [
            PortIdSubtype::InterfaceAlias,
            PortIdSubtype::PortComponent,
            PortIdSubtype::InterfaceName,
            PortIdSubtype::CircuitId,
            PortIdSubtype::Local,
        ] {
            let value = String::from("Bla bla bla, Mr.Freeman.");
            let mut buf = b"\x04".to_vec();
            buf.put_u8(value.len() as u8 + 1);
            buf.put_u8(subtype as u8);
            buf.put(&value.as_bytes().to_vec()[..]);
            let pidtlv = PortIdTLV::new(subtype, PortIdValue::Other(value));
            assert_eq!(pidtlv.bytes(), buf);
        }
    }

    #[test]
    fn test_address_subtype_ipv4_dump() {
        let value: Ipv4Addr = "192.0.2.100".parse().unwrap();

        let pidtlv = PortIdTLV::new(
            PortIdSubtype::NetworkAddress,
            PortIdValue::IpAddress(IpAddr::V4(value)),
        );
        assert_eq!(pidtlv.bytes(), b"\x04\x06\x04\x01\xC0\x00\x02\x64".to_vec());
    }

    #[test]
    fn test_address_subtype_ipv6_dump() {
        let value: Ipv6Addr = "20db::1".parse().unwrap();
        let pidtlv = PortIdTLV::new(
            PortIdSubtype::NetworkAddress,
            PortIdValue::IpAddress(IpAddr::V6(value)),
        );
        assert_eq!(
            pidtlv.bytes(),
            b"\x04\x12\x04\x02\x20\xDB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                .to_vec()
        );
    }

    #[test]
    fn test_load() {
        let tlv = PortIdTLV::new_from_bytes(b"\x04\x0C\x07Abracadabra".as_ref());
        assert_eq!(tlv.len(), 12);
        assert_eq!(tlv.subtype, PortIdSubtype::Local);
        match tlv.value {
            PortIdValue::Other(s) => assert_eq!(s, "Abracadabra"),
            v => panic!("Expected OTHER, got {:?}", v),
        };
    }

    #[test]
    fn test_load_ipv4() {
        let tlv = PortIdTLV::new_from_bytes(b"\x04\x06\x04\x01\xC0\x02\x00\x01".as_ref());
        assert_eq!(tlv.len(), 6);
        assert_eq!(tlv.subtype, PortIdSubtype::NetworkAddress);
        match tlv.value {
            PortIdValue::IpAddress(ip) => match ip {
                IpAddr::V4(ip) => {
                    assert_eq!(ip.octets(), [192, 2, 0, 1]);
                }
                addr => panic!("Expected IPv4 address, got {:?}", addr),
            },
            v => panic!("Expected IPADDRESS, got {:?}", v),
        };
    }

    #[test]
    #[should_panic]
    fn test_load_invalid_ipv4() {
        PortIdTLV::new_from_bytes(b"\x04\x07\x04\x01\xC0\x02\x00\x01\x99".as_ref());
    }

    #[test]
    fn test_load_ipv6() {
        let tlv = PortIdTLV::new_from_bytes(
            b"\x04\x12\x04\x02\x20\x01\x00\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x78"
                .as_ref(),
        );
        assert_eq!(tlv.len(), 18);
        assert_eq!(tlv.subtype, PortIdSubtype::NetworkAddress);
        match tlv.value {
            PortIdValue::IpAddress(ip) => match ip {
                IpAddr::V6(ip) => {
                    let parsed: Ipv6Addr = "2001:db::78".parse().unwrap();
                    assert_eq!(ip.octets(), parsed.octets());
                }
                addr => panic!("Expected IPv6 address, got {:?}", addr),
            },
            v => panic!("Expected IPADDRESS, got {:?}", v),
        };
    }

    #[test]
    #[should_panic]
    fn test_load_invalid_ipv6() {
        PortIdTLV::new_from_bytes(b"\x04\x06\x04\x02\xC0\x02\x00\x01".as_ref());
    }

    #[test]
    fn test_display1() {
        let tlv = PortIdTLV::new(
            PortIdSubtype::Local,
            PortIdValue::Other("Bla bla bla, Mr. Freeman".into()),
        );

        assert_eq!(
            format!("{}", tlv),
            "PortIdTLV(7, \"Bla bla bla, Mr. Freeman\")"
        )
    }

    #[test]
    fn test_chassisid_display2() {
        let tlv = PortIdTLV::new(
            PortIdSubtype::MacAddress,
            PortIdValue::Mac(vec![0x66, 0x6F, 0x6F, 0x62, 0x61, 0x72]),
        );

        assert_eq!(
            format!("{}", tlv).to_lowercase(),
            "portidtlv(3, \"66:6f:6f:62:61:72\")"
        )
    }

    #[test]
    fn test_chassisid_display3() {
        let tlv = PortIdTLV::new(
            PortIdSubtype::NetworkAddress,
            PortIdValue::IpAddress(Ipv4Addr::new(127, 0, 0, 1).into()),
        );

        assert_eq!(format!("{}", tlv), "PortIdTLV(4, \"127.0.0.1\")")
    }
}
