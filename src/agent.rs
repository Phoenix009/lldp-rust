use crate::lldpdu::Lldpdu;
use crate::tlv::chassisid_tlv::*;
use crate::tlv::eolldpdu_tlv::EndOfLLDPDUTLV;
use crate::tlv::portid_tlv::*;
use crate::tlv::ttl_tlv::TtlTLV;
use crate::tlv::Tlv;
use std::time::Instant;

extern crate pnet;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;

/// Logger trait
pub trait Logger {
    fn log(&mut self, msg: &str);
}

/// The `StdoutLogger`. Used as default logger by the LLDPAgent if no other is provided.
#[derive(Debug, Clone)]
pub struct StdoutLogger {}
impl Logger for StdoutLogger {
    fn log(&mut self, msg: &str) {
        println!("{}", msg);
    }
}

/// LLDP agent
///
/// This is the top-level component. It provides two functions.
///
/// It announces its presence on the network by sending LLDP frames in regular intervals.
/// At the same time it listens for LLDP frames from other network devices.
///
/// If a valid frame is received, its contents will be logged for the administrator.
pub struct LLDPAgent {
    mac_address: MacAddr,
    interface_name: String,
    interval: f32,
    channel: (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>),
    logger: Box<dyn Logger>,
}

impl LLDPAgent {
    /// Sets up the network channel and LLDP agent state.
    pub fn new(
        mac_address: MacAddr,
        interface_name: String,
        interval: f32,
        opt_channel: Option<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)>,
        logger: Option<Box<dyn Logger>>,
    ) -> LLDPAgent {
        let logger = logger.unwrap_or_else(|| Box::new(StdoutLogger {}));

        let (tx, rx) = match opt_channel {
            Some((tx, rx)) => (tx, rx),
            None => {
                // Open a pnet channel suitable for transmitting LLDP frames.
                let interface_name = interface_name.clone();
                let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

                // Find the network interface with the provided name
                let interfaces = datalink::interfaces();
                let interface = interfaces
                    .into_iter()
                    .filter(interface_names_match)
                    .next()
                    .unwrap();

                // Create a new channel, dealing with layer 2 packets
                let (tx, rx) = match datalink::channel(&interface, Default::default()) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => panic!("Unhandled channel type"),
                    Err(e) => panic!(
                        "An error occurred when creating the datalink channel: {}",
                        e
                    ),
                };

                (tx, rx)
            }
        };

        LLDPAgent {
            mac_address,
            interface_name,
            interval,
            channel: (tx, rx),
            logger,
        }
    }

    /// Runs the agent
    ///
    /// This is the main loop of the LLDP agent. It takes care of sending as well as receiving LLDP frames.
    ///
    /// The loop continuously checks the socket for new data. If data (in the form of an Ethernet frame)
    /// has been received, it will check if the frame is a valid LLDP frame and, if so, log its contents for the
    /// administrator. All other frames will be ignored.
    ///
    /// Valid LLDP frames have an ethertype of 0x88CC, are directed to one of the LLDP multicast addresses
    /// (01:80:c2:00:00:00, 01:80:c2:00:00:03 and 01:80:c2:00:00:0e) and have not been sent by the local agent.
    ///
    /// After processing received frames, the agent announces itself by calling `LLDPAgent.announce()` if a sufficient
    /// amount of time has passed.
    ///
    /// If `run_once` is set to `true`, stop after the first LLDPDU has been received.
    pub fn run(&mut self, run_once: bool) {
        let mut t_previous = Instant::now();

        let valid_destination = vec![
            MacAddr(0x01, 0x80, 0xc2, 0x00, 0x00, 0x00),
            MacAddr(0x01, 0x80, 0xc2, 0x00, 0x00, 0x03),
            MacAddr(0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e),
        ];

        loop {
            // Get the next frame
            match self.channel.1.next() {
                Ok(frame) => {
                    // Frame has been received
                    let ether_frame = match EthernetPacket::new(frame) {
                        Some(frame) => frame,
                        None => continue,
                    };

                    let source_mac = ether_frame.get_source();
                    if source_mac == self.mac_address {
                        continue;
                    }

                    let destination_mac = ether_frame.get_destination();
                    if !valid_destination.iter().any(|mac| mac == &destination_mac) {
                        continue;
                    }

                    let ether_type = ether_frame.get_ethertype();
                    if ether_type != EtherTypes::Lldp {
                        continue;
                    }

                    // Instantiate Lldpdu struct from raw bytes
                    let lldpdu: Lldpdu = Lldpdu::from_bytes(ether_frame.payload());

                    // Log contents
                    self.logger.log(&format!("{}", lldpdu));

                    if run_once {
                        break;
                    }
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    panic!("An error occurred while reading: {}", e);
                }
            }
            // Announce if the time is right
            let t_now = Instant::now();
            if (t_now - t_previous).as_secs_f32() > self.interval {
                self.announce();
                t_previous = t_now;
            }
        }
    }

    /// Announces the agent.
    ///
    /// Send an LLDP frame using the channel
    ///
    /// Sends an LLDP frame with an LLDPDU containing:
    /// * the agent's MAC address as its chassis id
    /// * the agent's interface name as port id
    /// * a TTL of 60 seconds
    pub fn announce(&mut self) {
        // Construct LLDPDU
        let init_tlvs: Vec<Tlv> = vec![
            Tlv::ChassisId(ChassisIdTLV::new(
                ChassisIdSubType::MacAddress,
                ChassisIdValue::Mac(self.mac_address.octets().to_vec()),
            )),
            Tlv::PortId(PortIdTLV::new(
                PortIdSubtype::InterfaceName,
                PortIdValue::Other(self.interface_name.clone()),
            )),
            Tlv::Ttl(TtlTLV::new(60)),
            // Tlv::EndOfLldpdu(EndOfLLDPDUTLV::new()),
        ];

        let lldpdu: Lldpdu = Lldpdu::new(init_tlvs);

        // Construct Ethernet Frame
        let mut header = [0u8; 14];
        let mut ethernet_header = MutableEthernetPacket::new(&mut header[..]).unwrap();

        let source = self.mac_address;
        ethernet_header.set_source(source);

        let dest = MacAddr(0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e);
        ethernet_header.set_destination(dest);

        ethernet_header.set_ethertype(EtherTypes::Lldp);

        let mut frame = header.to_vec();
        frame.extend_from_slice(&lldpdu.bytes());

        // Send frame
        match self.channel.0.send_to(&frame, None) {
            Some(Ok(_)) => (),
            Some(Err(err)) => panic!("ERROR: Announce failed: {:?}", err),
            None => (),
        };
    }
}

#[cfg(test)]
mod tests {
    use pnet::datalink::dummy::{self, dummy_interface, Config};

    use super::*;
    use crate::tlv::eolldpdu_tlv::EndOfLLDPDUTLV;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_announce() {
        let (tx_sender, tx_receiver) = mpsc::channel();
        let (_, rx_receiver) = mpsc::channel();
        let dummy_loopback = dummy_interface(42);
        let dummy_config = Config::new(rx_receiver, tx_sender);

        let (tx, rx) = {
            match dummy::channel(&dummy_loopback, dummy_config) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                _ => unreachable!("pnet is broken"),
            }
        };

        let mut a = LLDPAgent::new(
            MacAddr::new(102, 111, 111, 98, 97, 114),
            String::from("lo"),
            1.0,
            Some((tx, rx)),
            None,
        );
        a.announce();

        let received = tx_receiver
            .try_recv()
            .expect("No packet received from agent");

        assert_eq!(
            received.as_ref(),
            b"\x01\x80\xc2\x00\x00\x0e\x66\x6F\x6F\x62\x61\x72\x88\xcc\x02\x07\x04foobar\x04\x03\x05lo\x06\x02\x00\x3c"
        );
    }

    #[test]
    fn test_announce2() {
        let (tx_sender, tx_receiver) = mpsc::channel();
        let (_, rx_receiver) = mpsc::channel();
        let dummy_loopback = dummy_interface(42);
        let dummy_config = Config::new(rx_receiver, tx_sender);

        let (tx, rx) = {
            match dummy::channel(&dummy_loopback, dummy_config) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                _ => unreachable!("pnet is broken"),
            }
        };

        let mut a = LLDPAgent::new(
            MacAddr::new(40, 94, 95, 94, 39, 41),
            String::from("enp4s0"),
            1.0,
            Some((tx, rx)),
            None,
        );
        a.announce();

        let received = tx_receiver
            .try_recv()
            .expect("No packet received from agent");

        assert_eq!(
            received.as_ref(),
            b"\x01\x80\xc2\x00\x00\x0e\x28\x5E\x5F\x5E\x27\x29\x88\xcc\x02\x07\x04(^_^')\x04\x07\x05enp4s0\x06\x02\x00\x3c"
        );
    }

    #[test]
    fn test_socket_bind() {
        let _ = LLDPAgent::new(
            MacAddr::new(170, 187, 204, 221, 238, 255),
            String::from("lo"),
            1.0,
            None,
            None,
        );
    }

    struct MockLogger {
        inner: Rc<RefCell<String>>,
    }

    impl Logger for MockLogger {
        fn log(&mut self, msg: &str) {
            self.inner.borrow_mut().push_str(msg);
        }
    }

    #[test]
    fn test_run() {
        let full_log = Rc::new(RefCell::new(String::new()));
        let logger = Box::new(MockLogger {
            inner: full_log.clone(),
        });

        thread::spawn(|| {
            thread::sleep(Duration::from_millis(1000));
            // create a channel.
            let interface_names_match = |iface: &NetworkInterface| iface.name == "lo";
            // Find the network interface with the provided name
            let interfaces = datalink::interfaces();
            let interface = interfaces.into_iter().find(interface_names_match).unwrap();

            let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unhandled channel type"),
                Err(e) => panic!(
                    "An error occurred when creating the datalink channel: {}",
                    e
                ),
            };
            let full_msg = b"\x01\x80\xc2\x00\x00\x0e\xff\xee\xdd\xcc\xbb\xaa\x88\xcc\x02\x07\x04\xff\xee\xdd\xcc\xbb\xaa\x04\x07\x03\xff\xee\xdd\xcc\xbb\xaa\x06\x02\x00x\x00\x00";
            tx.send_to(full_msg, None);
        });

        let mut a = LLDPAgent::new(
            MacAddr::new(170, 187, 204, 221, 238, 255),
            String::from("lo"),
            1.0,
            None,
            Some(logger),
        );
        a.run(true);

        let mut lldpdu = Lldpdu::new(vec![]);
        lldpdu.append(Tlv::ChassisId(ChassisIdTLV::new(
            ChassisIdSubType::MacAddress,
            ChassisIdValue::Mac(b"\xff\xee\xdd\xcc\xbb\xaa".to_vec()),
        )));
        lldpdu.append(Tlv::PortId(PortIdTLV::new(
            PortIdSubtype::MacAddress,
            PortIdValue::Mac(b"\xff\xee\xdd\xcc\xbb\xaa".to_vec()),
        )));
        lldpdu.append(Tlv::Ttl(TtlTLV::new(120)));
        lldpdu.append(Tlv::EndOfLldpdu(EndOfLLDPDUTLV::new()));

        assert_eq!(full_log.borrow().as_str(), "LLDPDU(ChassisIdTLV(4, \"FF:EE:DD:CC:BB:AA\"), PortIdTLV(3, \"FF:EE:DD:CC:BB:AA\"), TtlTLV(120), EndOfLLDPDUTLV)");
    }
}
