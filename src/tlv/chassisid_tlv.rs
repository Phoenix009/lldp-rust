use crate::tlv::TlvType;

use std::convert::{TryFrom, TryInto};
use std::fmt::Display;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum ChassisIdSubType {
    ChassisComponent = 1,
    InterfaceAlias = 2,
    PortComponent = 3,
    MacAddress = 4,
    NetworkAddress = 5,
    InterfaceName = 6,
    Local = 7,
}

impl TryFrom<u8> for ChassisIdSubType {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == ChassisIdSubType::ChassisComponent as u8 => {
                Ok(ChassisIdSubType::ChassisComponent)
            }
            x if x == ChassisIdSubType::InterfaceAlias as u8 => {
                Ok(ChassisIdSubType::InterfaceAlias)
            }
            x if x == ChassisIdSubType::PortComponent as u8 => Ok(ChassisIdSubType::PortComponent),
            x if x == ChassisIdSubType::MacAddress as u8 => Ok(ChassisIdSubType::MacAddress),
            x if x == ChassisIdSubType::NetworkAddress as u8 => {
                Ok(ChassisIdSubType::NetworkAddress)
            }
            x if x == ChassisIdSubType::InterfaceName as u8 => Ok(ChassisIdSubType::InterfaceName),
            x if x == ChassisIdSubType::Local as u8 => Ok(ChassisIdSubType::Local),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ChassisIdValue {
    Mac(Vec<u8>),
    IpAddress(IpAddr),
    Other(String),
}
/// Chassis ID TLV
///
/// The chassis ID TLV identifies the chassis (i.e. device) running the LLDP agent.
///
/// The chassis ID TLV is mandatory and MUST be the first TLV in the LLDPDU.
/// Each LLDPDU MUST contain one, and only one, Chassis ID TLV.
///
/// # TLV Format:
///
///      0                   1                   2
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...+-+-+-+
///     |             |                 |               |               |
///     |      1      |      Length     |    Subtype    |   Chassis ID  |
///     |             |                 |               |               |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...+-+-+-+
///
///                                                        1 - 255 byte
///
/// # Subtypes:
///
///  A chassis may be identified in several ways, e.g. by its IP address, MAC address or a name specified by an
///  administrator. The type of identification is determined by the subtype value.
///
/// | Subtype | ID Basis          | Example                    |
/// | ------- | ----------------- | -------------------------- |
/// | 0       | Reserved          |                            |
/// | 1       | Chassis Component | cl-SJ17-3-006:rack1:rtr-U3 |
/// | 2       | Interface Alias   | office net                 |
/// | 3       | Port Component    | backplane1                 |
/// | 4       | MAC Address       | 02:04:df:88:a2:b4          |
/// | 5       | Network Address*  | 134.96.86.110              |
/// | 6       | Interface Name    | eth0                       |
/// | 7       | Locally Assigned  | Frank's Computer           |
/// | 8 - 255 | Reserved          |                            |
///
///  Depending on the subtype the value is to be interpreted in a certain way.
///
///  With the exception of subtypes 4 (MAC Address) and 5 (Network Address), as far as the LLDP agent is concerned,
///  the value is a string. A distinction between these subtypes is only made by a human observer.
///
///  ## MAC Address Subtype:
///
///  MAC addresses are represented as raw bytes, e.g. the MAC address `02:04:df:88:a2:b4` corresponds to a value of
///  `b"\x02\x04\xDF\x88\xA2\xB4"`.
///
///  ## Network Address Subtype:
///
///  Network addresses are represented as raw bytes.
///
///  In practice there are many different network protocols, each with their own address format with e.g. a different
///  length.
///
///  To determine the type of network protocol and the appropriate length of the network address transmitted in the
///  Chassis ID TLV, network addresses are prefixed with an extra byte identifying the address family.
///
///  For this implementation we only consider IPv4 and IPv6.
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
///  The full list of registered protocol families is available at:
///  <https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml>
#[derive(Debug, Clone)]
pub struct ChassisIdTLV {
    /// The type of the TLV
    pub tlv_type: TlvType,
    /// The chassis ID subtype
    pub subtype: ChassisIdSubType,
    /// The chassis ID
    ///
    /// The type of this field depends on the subtype
    /// * MAC Address -> `ChassisIdValue::Mac(Vec<u8>)`,
    /// * Network Address -> `ChassisIdValue::IpAddress(IpAddr)`,
    /// * Otherwise -> `ChassisIdValue::Other(String)`
    pub value: ChassisIdValue,
}

impl Display for ChassisIdTLV {
    /// Write a printable representation of the TLV object.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match &self.value {
            ChassisIdValue::Mac(mac) => {
                let mut result = String::new();
                for (index, i) in mac.iter().enumerate() {
                    result.push_str(&format!("{:X}", i));
                    if index != mac.len() - 1 {
                        result.push_str(&":");
                    }
                }
                result
            }
            ChassisIdValue::Other(s) => s.clone(),
            ChassisIdValue::IpAddress(addr) => addr.to_string(),
        };

        write!(
            f,
            "ChassisIdTLV({}, \"{}\")",
            self.subtype.clone() as u8,
            value
        )
    }
}

impl ChassisIdTLV {
    /// Constructor
    ///
    /// The type of the `id` argument depends on the subtype
    /// * MAC Address -> `ChassisIdValue::Mac(Vec<u8>)`,
    /// * Network Address -> `ChassisIdValue::IpAddress(IpAddr)`,
    /// * Otherwise -> `ChassisIdValue::Other(String)`
    pub fn new(subtype: ChassisIdSubType, id: ChassisIdValue) -> ChassisIdTLV {
        // TODO: Implement
        ChassisIdTLV {
            tlv_type: TlvType::ChassisId,
            subtype: subtype,
            value: id,
        }
    }

    /// Create a TLV instance from raw bytes.
    ///
    /// Panics if the provided TLV contains errors (e.g. has the wrong type).
    pub fn new_from_bytes(bytes: &[u8]) -> ChassisIdTLV {
        let mut type_field = bytes[0] & 0b11111110;
        type_field = type_field >> 1;

        if type_field != TlvType::ChassisId as u8 {
            panic!("Wrong TLV Type for ChassisId_Tlv");
        }

        let mut length = bytes[1] as usize;
        if bytes[0] & 1 == 1 {
            length += 1 << 9;
        }

        assert_eq!(length, bytes[2..].len());

        let subtype = bytes[2];

        let subtype = match ChassisIdSubType::try_from(subtype) {
            Ok(subtype) => subtype,
            Err(_) => panic!("Invalid ChassisSubtype"),
        };

        let value = match subtype {
            ChassisIdSubType::MacAddress => {
                assert_eq!(6, bytes[3..].len());
                ChassisIdValue::Mac(bytes[3..].to_vec())
            }
            ChassisIdSubType::NetworkAddress => match bytes[3] {
                1u8 => {
                    assert_eq!(4, bytes[4..].len());
                    let addr: [u8; 4] = bytes[4..8].try_into().unwrap();
                    ChassisIdValue::IpAddress(IpAddr::from(addr))
                }
                2u8 => {
                    assert_eq!(16, bytes[4..].len());
                    let addr: [u8; 16] = bytes[4..20].try_into().unwrap();
                    ChassisIdValue::IpAddress(IpAddr::from(addr))
                }
                _ => panic!("Expected IP Address specifier"),
            },
            _ => match String::from_utf8(bytes[3..].to_vec()) {
                Ok(value) => ChassisIdValue::Other(value),
                Err(_) => panic!("Invlaid value for Chasis::Other type "),
            },
        };

        ChassisIdTLV {
            tlv_type: TlvType::ChassisId,
            subtype: subtype,
            value: value,
        }
    }

    /// Return the length of the TLV value
    pub fn len(&self) -> usize {
        1 + match &self.value {
            ChassisIdValue::Mac(_) => 6,
            ChassisIdValue::Other(s) => s.len(),
            ChassisIdValue::IpAddress(IpAddr::V4(_)) => 4 + 1,
            ChassisIdValue::IpAddress(IpAddr::V6(_)) => 16 + 1,
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
            ChassisIdValue::Mac(addr) => addr.clone(),
            ChassisIdValue::Other(value) => value.as_bytes().to_vec(),
            ChassisIdValue::IpAddress(IpAddr::V4(address)) => address.octets().to_vec(),
            ChassisIdValue::IpAddress(IpAddr::V6(address)) => address.octets().to_vec(),
        };

        if let ChassisIdValue::IpAddress(IpAddr::V4(_)) = self.value {
            result.push(1);
        }

        if let ChassisIdValue::IpAddress(IpAddr::V6(_)) = self.value {
            result.push(2);
        }

        result.extend_from_slice(&value_field);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn set_up() -> (ChassisIdTLV, ChassisIdSubType, ChassisIdValue) {
        let value: ChassisIdValue = ChassisIdValue::Other(String::from("Terok Nor"));
        let subtype: ChassisIdSubType = ChassisIdSubType::Local;
        (
            ChassisIdTLV::new(subtype.clone(), value.clone()),
            subtype,
            value,
        )
    }

    #[test]
    fn test_type() {
        let (cidtlv, _, _) = set_up();
        assert_eq!(cidtlv.tlv_type as u8, TlvType::ChassisId as u8);
        assert_eq!(cidtlv.tlv_type as u8, 1);
    }

    #[test]
    fn test_length() {
        let (cidtlv, _, value) = set_up();
        match value {
            ChassisIdValue::Other(s) => assert_eq!(cidtlv.len(), s.len() + 1),
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_value() {
        let (cidtlv, _, value) = set_up();

        let value_str = match value {
            ChassisIdValue::Other(s) => s,
            _ => unreachable!(),
        };

        match cidtlv.value {
            ChassisIdValue::Other(cidtlv_value) => {
                assert_eq!(cidtlv_value, value_str)
            }
            v => panic!("expected OTHER, got {:?}", v),
        }
    }

    #[test]
    fn test_subtype() {
        let (cidtlv, subtype, _) = set_up();
        assert_eq!(cidtlv.subtype as u8, subtype as u8);
    }

    #[test]
    fn test_generic_subtypes() {
        let value_string = "Terok Nor";
        let value = ChassisIdValue::Other(String::from(value_string));
        for subtype in [
            ChassisIdSubType::ChassisComponent,
            ChassisIdSubType::InterfaceAlias,
            ChassisIdSubType::PortComponent,
            ChassisIdSubType::InterfaceName,
            ChassisIdSubType::Local,
        ] {
            let tlv = ChassisIdTLV::new(subtype.clone(), value.clone());
            assert_eq!(tlv.subtype as u8, subtype as u8);
            match tlv.value {
                ChassisIdValue::Other(s) => assert_eq!(s, value_string),
                v => panic!("expected OTHER, got {:?}", v),
            }
        }
    }

    #[test]
    fn test_mac_subtype_dump() {
        let tlv = ChassisIdTLV::new(
            ChassisIdSubType::MacAddress,
            ChassisIdValue::Mac(b"\x00\x22\x12\xAA\xBB\xCC".to_vec()),
        );
        assert_eq!(
            tlv.bytes(),
            b"\x02\x07\x04\x00\x22\x12\xAA\xBB\xCC".to_vec()
        );
    }

    #[test]
    fn test_mac_subtype_load() {
        let tlv = ChassisIdTLV::new_from_bytes(b"\x02\x07\x04\x00\x22\x12\xAA\xBB\xCC".as_ref());
        assert_eq!(tlv.subtype as u8, ChassisIdSubType::MacAddress as u8);
        match tlv.value {
            ChassisIdValue::Mac(mac) => assert_eq!(mac, b"\x00\x22\x12\xAA\xBB\xCC".to_vec()),
            v => panic!("expected MAC, got {:?}", v),
        }
    }

    #[test]
    fn test_address_subtype_ipv4_dump() {
        let value: Ipv4Addr = "192.0.2.100".parse().unwrap();
        let tlv = ChassisIdTLV::new(
            ChassisIdSubType::NetworkAddress,
            ChassisIdValue::IpAddress(IpAddr::V4(value)),
        );

        assert_eq!(tlv.bytes(), b"\x02\x06\x05\x01\xc0\x00\x02\x64".to_vec());
    }

    #[test]
    fn test_address_subtype_ipv6_dump() {
        let value: Ipv6Addr = "20db::1".parse().unwrap();
        let tlv = ChassisIdTLV::new(
            ChassisIdSubType::NetworkAddress,
            ChassisIdValue::IpAddress(IpAddr::V6(value)),
        );
        assert_eq!(
            tlv.bytes(),
            b"\x02\x12\x05\x02\x20\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                .to_vec()
        );
    }

    #[test]
    fn test_load_generic() {
        let tlv = ChassisIdTLV::new_from_bytes(b"\x02\x09\x07Unittest".as_ref());
        assert_eq!(tlv.subtype as u8, ChassisIdSubType::Local as u8);
        match tlv.value {
            ChassisIdValue::Other(s) => assert_eq!(s, String::from("Unittest")),
            v => panic!("expected OTHER, got {:?}", v),
        }
    }

    #[test]
    fn test_load_generic_unicode() {
        let tlv = ChassisIdTLV::new_from_bytes(
            b"\x02\x0d\x07\xe5\x8d\x95\xe5\x85\x83\xe6\xb5\x8b\xe8\xaf\x95".as_ref(),
        );
        assert_eq!(tlv.subtype as u8, ChassisIdSubType::Local as u8);
        match tlv.value {
            ChassisIdValue::Other(s) => assert_eq!(s, String::from("单元测试")),
            v => panic!("expected OTHER, got {:?}", v),
        }
    }

    #[test]
    fn test_load_mac() {
        let tlv = ChassisIdTLV::new_from_bytes(b"\x02\x07\x04\xc8\xbc\xc8\x94\x92\xca".as_ref());
        assert_eq!(tlv.subtype as u8, ChassisIdSubType::MacAddress as u8);
        match tlv.value {
            ChassisIdValue::Mac(mac) => assert_eq!(mac, b"\xc8\xbc\xc8\x94\x92\xca".to_vec()),
            v => panic!("expected MAC, got {:?}", v),
        }
    }

    #[test]
    fn test_load_ipv4() {
        let tlv = ChassisIdTLV::new_from_bytes(b"\x02\x06\x05\x01\xc0\x00\x02\x0e".as_ref());
        assert_eq!(tlv.subtype as u8, ChassisIdSubType::NetworkAddress as u8);
        match tlv.value {
            ChassisIdValue::IpAddress(ip) => match ip {
                IpAddr::V4(ip) => {
                    assert_eq!(ip.octets(), [192, 0, 2, 14]);
                }
                addr => panic!("expected Ipv4 address, got {:?}", addr),
            },
            v => panic!("expected IPADDRESS, got {:?}", v),
        };
    }

    #[test]
    fn test_load_ipv6() {
        let tlv = ChassisIdTLV::new_from_bytes(
            b"\x02\x12\x05\x02\x20\x01\x00\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x12"
                .as_ref(),
        );
        assert_eq!(tlv.subtype as u8, ChassisIdSubType::NetworkAddress as u8);
        match tlv.value {
            ChassisIdValue::IpAddress(ip) => match ip {
                IpAddr::V6(ip) => {
                    let parsed: Ipv6Addr = "2001:db::ff:12".parse().unwrap();
                    assert_eq!(ip.octets(), parsed.octets());
                }
                addr => panic!("expected Ipv4 address, got {:?}", addr),
            },
            v => panic!("expected IPADDRESS, got {:?}", v),
        };
    }

    #[test]
    #[should_panic]
    fn test_load_invalid_generic() {
        ChassisIdTLV::new_from_bytes(b"\x02\x0a\x07\x55\x6e\x69\x74\x74\x65\x73\x74".as_ref());
    }

    #[test]
    #[should_panic]
    fn test_load_invalid_mac() {
        ChassisIdTLV::new_from_bytes(b"\x02\x08\x04\xc8\xbc\xc8\x94\x92\xca\x11".as_ref());
    }

    #[test]
    #[should_panic]
    fn test_load_invalid_ipv4() {
        ChassisIdTLV::new_from_bytes(b"\x02\x04\x05\xc0\x00\x02".as_ref());
    }

    #[test]
    #[should_panic]
    fn test_load_invalid_ipv6() {
        ChassisIdTLV::new_from_bytes(
            b"\x02\x10\x05\x20\x01\x00\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00".as_ref(),
        );
    }

    #[test]
    fn test_display1() {
        let tlv = ChassisIdTLV::new(
            ChassisIdSubType::Local,
            ChassisIdValue::Other("Pablo's Computer".into()),
        );

        assert_eq!(format!("{}", tlv), "ChassisIdTLV(7, \"Pablo's Computer\")")
    }

    #[test]
    fn test_display2() {
        let tlv = ChassisIdTLV::new(
            ChassisIdSubType::MacAddress,
            ChassisIdValue::Mac(vec![0x66, 0x6F, 0x6F, 0x62, 0x61, 0x72]),
        );

        let s = format!("{}", tlv);
        let addr = s.get(17..34).unwrap();

        assert_eq!(addr.to_lowercase(), "66:6f:6f:62:61:72");
    }

    #[test]
    fn test_display3() {
        let tlv = ChassisIdTLV::new(
            ChassisIdSubType::NetworkAddress,
            ChassisIdValue::IpAddress(Ipv4Addr::new(127, 0, 0, 1).into()),
        );

        assert_eq!(format!("{}", tlv), "ChassisIdTLV(5, \"127.0.0.1\")")
    }
}
