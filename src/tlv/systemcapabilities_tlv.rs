use crate::tlv::TlvType;
use std::{convert::TryFrom, fmt::Display};

/// Capability bit values
///
/// This enum can be used to construct a capability bitmap in a descriptive way.
///
/// To create a capability bitmap the enum values can be ORed with each other, e.g. for a WLAN router the
/// capabilities might look like this:
///
///     caps = Capability.WLAN_AP | Capability.ROUTER
#[derive(Debug, Clone)]
pub enum SystemCapability {
    Other = 1,
    Repeater = 2,
    Bridge = 4,
    WlanAP = 8,
    Router = 16,
    Telephone = 32,
    DocsisDevice = 64,
    StationOnly = 128,
    CVlanComponent = 256,
    SVlanComponent = 512,
    TwoPortMacRelay = 1024,
}

impl TryFrom<u16> for SystemCapability {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == SystemCapability::Other as u16 => Ok(SystemCapability::Other),
            x if x == SystemCapability::Repeater as u16 => Ok(SystemCapability::Repeater),
            x if x == SystemCapability::Bridge as u16 => Ok(SystemCapability::Bridge),
            x if x == SystemCapability::WlanAP as u16 => Ok(SystemCapability::WlanAP),
            x if x == SystemCapability::Router as u16 => Ok(SystemCapability::Router),
            x if x == SystemCapability::Telephone as u16 => Ok(SystemCapability::Telephone),
            x if x == SystemCapability::DocsisDevice as u16 => Ok(SystemCapability::DocsisDevice),
            x if x == SystemCapability::StationOnly as u16 => Ok(SystemCapability::StationOnly),
            x if x == SystemCapability::CVlanComponent as u16 => {
                Ok(SystemCapability::CVlanComponent)
            }
            x if x == SystemCapability::SVlanComponent as u16 => {
                Ok(SystemCapability::SVlanComponent)
            }
            x if x == SystemCapability::TwoPortMacRelay as u16 => {
                Ok(SystemCapability::TwoPortMacRelay)
            }
            _ => Err(()),
        }
    }
}

/// System Capabilities TLV
///
/// The System Capabilities TLV is an optional TLV that identifies the primary function(s) of the system and whether or
/// not these primary functions are enabled.
///
/// It is an optional TLV and as such may be included in an LLDPDU zero or more times between
/// the TTL TLV and the End of LLDPDU TLV.
///
/// # TLV Format:
///
///         0                   1                   2                   3                   4
///         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |             |                 |            System             |            Enabled            |
///        |      7      |      Length     |         Capabilities          |         Capabilities          |
///        |             |                 |                               |                               |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///                                        |                                                               |
///                                        |             2 byte                           2 byte           |
///                                        |                                                               |
///                                        |                                                               |
///                                        |<--------------------------  Value  -------------------------->|
///
/// # Capabilities:
///
/// Capabilities are encoded in a bitmap. A binary one in a bit position indicates that the function associated with
/// the bit is supported / enabled.
///
/// |  Bit  |     Capability      |                           Description                        |
/// | ----- | ------------------- | ------------------------------------------------------------ |
/// |   0   |        Other        |                                                              |
/// |   1   |      Repeater       |                                                              |
/// |   2   |       Bridge        | e.g. an Ethernet switch                                      |
/// |   3   |  WLAN Access Point  |                                                              |
/// |   4   |       Router        |                                                              |
/// |   5   |     Telephone       | i.e. a VoIP phone                                            |
/// |   6   | DOCSIS cable device | i.e. a cable modem                                           |
/// |   7   |    Station Only     | e.g. a PC, should not be set in conjunction with other bits  |
/// | 8-15  |      reserved       |                                                              |
///
/// If the system capabilities field does not indicate the existence of a capability that the enabled capabilities
/// field indicates is enabled, the TLV will be interpreted as containing an error and a ValueError is raised.
#[derive(Debug, Clone)]
pub struct SystemCapabilitiesTLV {
    /// The type of the TLV
    pub tlv_type: TlvType,
    /// Supported and enabled capabilities
    pub value: u32,
}

impl Display for SystemCapabilitiesTLV {
    /// Write a printable representation of the TLV object.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let supports = (self.value & 0xFFFF0000) >> 16;
        let enabled = self.value & 0x0000FFFF;
        println!("{} {}", supports, enabled);
        write!(f, "SystemCapabilitiesTLV({}, {})", supports, enabled)
    }
}

impl SystemCapabilitiesTLV {
    /// Constructor
    ///
    ///    Parameters:
    ///        supported (u16): Bitmap of supported capabilities
    ///        enabled (u16): Bitmap of enabled capabilities
    pub fn new(supported: u16, enabled: u16) -> SystemCapabilitiesTLV {
        let mut mask = 1;

        for _ in 0..16 {
            if (supported & mask == 0) && (enabled & mask != 0) {
                panic!("Invalid Settings");
            }
            mask <<= 1;
        }

        let mut value: u32 = (supported as u32) << 16;
        value |= enabled as u32;

        SystemCapabilitiesTLV {
            tlv_type: TlvType::SystemCapabilities,
            value: value,
        }
    }

    /// Create a TLV instance from raw bytes.
    ///
    /// Panics if the provided TLV contains errors (e.g. has the wrong type).
    pub fn new_from_bytes(bytes: &[u8]) -> SystemCapabilitiesTLV {
        let mut type_field = bytes[0] & 0b11111110;
        type_field = type_field >> 1;

        if type_field != TlvType::SystemCapabilities as u8 {
            panic!("Wrong TLV Type for SystemCapabilities");
        }

        let mut length = bytes[1] as usize;
        if bytes[0] & 1 == 1 {
            length += 1 << 9;
        }

        assert_eq!(length, 4, "length for SystemCapabilitiesTlv should be 4");

        let supported = (((bytes[2] as u16) << 8) | bytes[3] as u16) as u32;
        let enabled = (((bytes[4] as u16) << 8) | bytes[5] as u16) as u32;

        let mut mask = 1;
        for _ in 0..16 {
            if (supported & mask == 0) && (enabled & mask != 0) {
                panic!("Invalid Settings");
            }
            mask <<= 1;
        }

        let value = (supported << 16) as u32 | enabled as u32;

        SystemCapabilitiesTLV {
            tlv_type: TlvType::SystemCapabilities,
            value: value,
        }
    }

    /// Check if the system supports a given set of capabilities.
    ///
    /// Multiple capabilities should be ORed together.
    fn supports(&self, capabilities: u16) -> bool {
        let mut capabilities_mask = 1;
        let mut mask: u32 = 1 << 16;

        for _ in 0..16 {
            if (capabilities & capabilities_mask != 0) && (self.value & mask == 0) {
                return false;
            }
            mask <<= 1;
            capabilities_mask <<= 1;
        }
        true
    }

    /// Check if the system has a given capability enabled.
    ///
    /// Multiple capabilities should be ORed together.
    fn enabled(&self, capabilities: u16) -> bool {
        let mut capabilities_mask = 1;
        let mut mask: u32 = 1;

        for _ in 0..16 {
            if (capabilities & capabilities_mask != 0) && (self.value & mask == 0) {
                return false;
            }
            mask <<= 1;
            capabilities_mask <<= 1;
        }
        true
    }

    /// Return the length of the TLV value
    pub fn len(&self) -> usize {
        return 4usize;
    }

    /// Return the byte representation of the TLV.
    pub fn bytes(&self) -> Vec<u8> {
        let mask: u32 = 0xFF;
        let mut result: Vec<u8> = Vec::new();
        result.push(7 << 1);
        result.push(4);

        result.push(((self.value & (mask << 24)) >> 24) as u8);
        result.push(((self.value & (mask << 16)) >> 16) as u8);
        result.push(((self.value & (mask << 8)) >> 8) as u8);
        result.push((self.value & mask) as u8);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_up() -> SystemCapabilitiesTLV {
        let supported = SystemCapability::WlanAP as u16
            | SystemCapability::Bridge as u16
            | SystemCapability::Router as u16
            | SystemCapability::DocsisDevice as u16;
        let enabled = SystemCapability::Bridge as u16
            | SystemCapability::Router as u16
            | SystemCapability::DocsisDevice as u16;
        SystemCapabilitiesTLV::new(supported, enabled)
    }

    #[test]
    fn test_type() {
        let tlv = set_up();
        assert_eq!(tlv.tlv_type as u8, TlvType::SystemCapabilities as u8);
    }

    #[test]
    fn test_length() {
        let tlv = set_up();
        assert_eq!(tlv.len() as u8, 4);
    }

    #[test]
    fn test_value() {
        let tlv = set_up();
        assert_eq!(tlv.value, 0x005c0054);
    }

    #[test]
    fn test_dump() {
        let tlv = set_up();
        assert_eq!(tlv.bytes(), b"\x0e\x04\x00\x5C\x00\x54".to_vec());
    }

    #[test]
    fn test_load() {
        let tlv = SystemCapabilitiesTLV::new_from_bytes(b"\x0e\x04\x00\x14\x00\x04".as_ref());
        assert_eq!(tlv.tlv_type as u8, TlvType::SystemCapabilities as u8);
        assert_eq!(tlv.len() as u8, 4);
        assert_eq!(
            (tlv.value & 0xFFFF0000) >> 16,
            20,
            "Expected only BRIDGE and ROUTER capabilities to be supported."
        );
        assert_eq!(
            tlv.value & 0xFFFF,
            4,
            "Expected only BRIDGE capability to be enabled."
        );
    }

    #[test]
    fn test_supports() {
        let tlv = set_up();
        assert!(tlv.supports(
            SystemCapability::WlanAP as u16
                | SystemCapability::Bridge as u16
                | SystemCapability::Router as u16
                | SystemCapability::DocsisDevice as u16
        ));
        for cap in [SystemCapability::WlanAP as u16
            | SystemCapability::Bridge as u16
            | SystemCapability::Router as u16
            | SystemCapability::DocsisDevice as u16]
        {
            assert!(tlv.supports(cap));
        }
        for cap in [SystemCapability::Other as u16
            | SystemCapability::Repeater as u16
            | SystemCapability::Telephone as u16
            | SystemCapability::StationOnly as u16
            | SystemCapability::CVlanComponent as u16
            | SystemCapability::SVlanComponent as u16
            | SystemCapability::TwoPortMacRelay as u16]
        {
            assert!(!tlv.supports(cap));
        }
        // Reserved bits should not be used
        assert!(!tlv.supports(0xF800));
    }

    #[test]
    fn test_enabled() {
        let tlv = set_up();
        assert!(tlv.supports(
            SystemCapability::Bridge as u16
                | SystemCapability::Router as u16
                | SystemCapability::DocsisDevice as u16
        ));
        for cap in [SystemCapability::Bridge as u16
            | SystemCapability::Router as u16
            | SystemCapability::DocsisDevice as u16]
        {
            assert!(tlv.supports(cap));
        }
        for cap in [SystemCapability::Other as u16
            | SystemCapability::Repeater as u16
            | SystemCapability::WlanAP as u16
            | SystemCapability::Telephone as u16
            | SystemCapability::StationOnly as u16
            | SystemCapability::CVlanComponent as u16
            | SystemCapability::SVlanComponent as u16
            | SystemCapability::TwoPortMacRelay as u16]
        {
            assert!(!tlv.supports(cap));
        }
        // Reserved bits should not be used
        assert!(!tlv.supports(0xF800));
    }

    #[test]
    #[should_panic]
    fn test_capability_mismatch() {
        SystemCapabilitiesTLV::new(
            SystemCapability::StationOnly as u16,
            SystemCapability::WlanAP as u16,
        );
    }

    #[test]
    #[should_panic]
    fn test_load_capability_mismatch() {
        SystemCapabilitiesTLV::new_from_bytes(b"\x0e\x04\x00\x00\x00\x14".as_ref());
    }

    #[test]
    fn test_display() {
        let tlv = set_up();
        assert_eq!(format!("{}", tlv), "SystemCapabilitiesTLV(92, 84)")
    }
}
