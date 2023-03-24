use agent::LLDPAgent;
use pnet::datalink;

mod agent;
mod lldpdu;
mod tlv;

fn main() {
    let interface_name = std::env::args().nth(1).unwrap_or_else(|| "eth0".into());

    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .unwrap_or_else(|| panic!("Interface {} is not present.", interface_name));

    let mac_address = interface
        .mac
        .unwrap_or_else(|| panic!("Interface {} does not have a MAC address", interface_name));

    println!("Starting LLDP Agent on interface {}", interface_name);

    let mut agent = LLDPAgent::new(mac_address, interface_name, 1.0, None, None);

    agent.run(false);
}
