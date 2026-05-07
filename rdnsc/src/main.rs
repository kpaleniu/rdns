use clap::Parser;
use rdns::{DnsMessage, DnsMessageBuilder};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    pub dns_server: Ipv4Addr,
    pub record: String,
    pub hostname: String,
}

fn main() {
    let args = Cli::parse();
    let dns_addr = SocketAddr::from((args.dns_server, 53));
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("failed binding");

    let req = DnsMessageBuilder::new()
        .with_url(&args.hostname, &args.record)
        .build();

    let mut buf = [0u8; 512];
    let _ = req.to_bytes(&mut buf).expect("error serializing");
    sock.send_to(&buf, dns_addr).expect("error sending");

    let mut buf = [0; 512];
    let _ = sock.recv_from(&mut buf).expect("error receiving");

    let msg = DnsMessage::try_from_bytes(&buf).expect("error deserializing");
    if !msg.response {
        println!("not a response, DNS server non-compliant!");
    }
    for r in msg.queries {
        println!("{:?}", r);
    }
    for r in msg.answers {
        println!("{:?}", r);
    }
    for r in msg.authorities {
        println!("{:?}", r);
    }
    for r in msg.additionals {
        println!("{:?}", r);
    }
}
