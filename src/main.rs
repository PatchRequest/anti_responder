
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{TransportChannelType, transport_channel, TransportProtocol, udp_packet_iter, ipv4_packet_iter};


use std::{env, net::Ipv4Addr, net::Ipv6Addr};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::{ IpAddr};
use rand::Rng;
use bit_vec::BitVec;
use std::net::UdpSocket;


fn main() {
    let mut args = env::args();
    if args.len() < 2 {
        println!("Usage:");
        println!("anti-responder <interface name>");
        let interfaces = datalink::interfaces();
        let available_interfaces = interfaces.iter()
            .map(|iface| iface.name.clone())
            .collect::<Vec<String>>()
            .join(", ");
        println!("Available interfaces: {}", available_interfaces);
        return;
    }
    let interface_name = args.nth(1).unwrap();

    println!("Interface name: {}", interface_name);

    let mut interface = get_interface(&interface_name);

    
    let multi = interface.is_multicast();
    println!("Is multicast: {}", multi);


    



    let port:u16 = 5355;
    let dest_ipv4:Ipv4Addr = Ipv4Addr::new(224,0,0,252);
    //let dest_ipv6:Ipv6Addr = Ipv6Addr::new(0xFF02,0,0,0,0,0,1,3);


    
    send_ipv4_packages( &dest_ipv4, &port);
    //send_ipv6_packages( &dest_ipv6, &port);
    receive_upd_multicast(&dest_ipv4);

    //receive_upd_multicast(&dest_ipv4);
    


}

fn receive_upd_multicast(dest_ipv4: &Ipv4Addr){
    let socket = UdpSocket::bind("0.0.0.0:5355");
    socket.as_ref().unwrap().join_multicast_v4(&dest_ipv4, &Ipv4Addr::new(0,0,0,0));
    let mut socket = socket.unwrap();

    loop {
        let mut buf = [0; 4096];
        let res = socket.recv_from(&mut buf);
        let (amt, src) = match res {
            Ok((amt, src)) => (amt, src),
            Err(e) => panic!("couldn't receive a datagram: {}", e),
        };
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf)
                                            .expect("Didn't receive data");
        let filled_buf = &mut buf[..number_of_bytes];


        println!("Received {} bytes from {}", filled_buf.len(), src_addr);

       
        let bit_vec = BitVec::from_bytes(filled_buf);

        // get the first 96 bits and save them in a new BitVec
        let mut first_96_bits = BitVec::from_elem(96, false);
        for i in 0..96 {
            first_96_bits.set(i, bit_vec[i]);
        }

        // remove the first 96 bits from the original BitVec
        let mut new_bit_vec = BitVec::from_elem(bit_vec.len() - 96, false);
        for i in 96..bit_vec.len() {
            new_bit_vec.set(i - 96, bit_vec[i]);
        }

        println!("Header: {:?}", first_96_bits);
        println!("Payload: {:?}", new_bit_vec);
    }
}


fn generate_random_packets<'a>(count : i32,port: &'a u16) -> Vec<UdpPacket>{
    let mut my_packets: Vec<UdpPacket> = vec![];
    for _ in 0..count{
        let a_package = build_llmnr_package(&port);
        let packet = a_package.consume_to_immutable();

        my_packets.push(packet);
    }
    my_packets
}

fn send_ipv4_packages(dest_ipv4: &Ipv4Addr, port: & u16){
    let my_packets = generate_random_packets(3, port);
    let (mut txv4, _) = match transport_channel(4096, TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp))) {
        Ok((txv4, rxv4)) => (txv4, rxv4),
        Err(e) => panic!("An error occurred when creating the transport channel: {}", e),
    };
    for packet in my_packets.into_iter(){
        txv4.send_to(packet, IpAddr::V4(*dest_ipv4)).unwrap();
    }

}

fn send_ipv6_packages(dest_ipv6: &Ipv6Addr,port: & u16){
    let my_packets = generate_random_packets(3, port);
    let (mut txv6, _) = match transport_channel(4096, TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Udp))) {
        Ok((txv6, rxv6)) => (txv6, rxv6),
        Err(e) => panic!("An error occurred when creating the transport channel: {}", e),
    };
    for packet in my_packets.into_iter(){
        txv6.send_to(packet, IpAddr::V6(*dest_ipv6)).unwrap();
    }
}


fn get_interface(name: &str) -> NetworkInterface {
    let interfaces = datalink::interfaces();
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == name;
    interfaces.into_iter()
              .filter(interface_names_match)
              .next()
              .unwrap()
    
}



fn build_llmnr_package<'a>(port: &'a u16) -> MutableUdpPacket<'a>{
    // create a udp package
    let mut vec: Vec<u8> = vec![0; 4096];

    let mut headers = build_header_for_llmnr();
    let mut body = build_payload_for_llmnr();
    headers.append(&mut body);


    vec.resize(headers.len(), 0);
    let byte_len = (headers.len() / 8 + 8) as u16;

    let mut new_packet = MutableUdpPacket::owned(vec).unwrap();

    new_packet.set_source(*port);
    new_packet.set_destination(*port);
    
    new_packet.set_payload(&headers.to_bytes());
    new_packet.set_length(byte_len);

    new_packet


}

fn build_header_for_llmnr() -> BitVec{
    // 16 bit random number
    let mut rng = rand::thread_rng();   
    let n2: u16 = rng.gen();

    
    // map n2 to a bitvector
    let mut complete_headers = BitVec::from_elem(16, false);
    for i in 0..16{
        if n2 & (1 << i) != 0{
            complete_headers.set(i, true);
        }
    }

    let mut headers_bitvec = BitVec::from_elem(80, false);
    let headers = vec![    
        0, //1 bit QR = 0 it is a query so 0
        0, 0, 0, 0, // 4 bit opcode = its always 0
        0, // 1 bit C = 0 because we dont want recursion 
        0, // 1bit tc = 0 because we dont want truncation
        0, // 1bit T = 0 because we are just a query and are not a authoritative answer
        0, 0, 0, 0, //4 bit Z = 0 because we dont want any reserved bits
        0, 0, 0, 0, // 4bit RCODE = 0 because we are just a query
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // 16 bit QDCOUNT = 1 because we have one question
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 bit ANCOUNT = 0 because we are a query and dont have any answers
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 bit NSCOUNT = 0 because we are a query and dont have any authority records
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 bit ARCOUNT = 0 because we are a query and dont have any additional records
        ];
    for i in 0..80{
        if headers[i] == 1{
            headers_bitvec.set(i, true);
        }
    }
    complete_headers.append(&mut headers_bitvec);
    complete_headers
    
}

fn build_payload_for_llmnr() -> BitVec{
    let mut payload = BitVec::new();
    

    let packet_bytes: [u8; 10] = [
    0x04, 0x77, 0x70, 0x61, 0x64, 0x00,
    0x00, 0xff, 0x00, 0x01
    
    ];
    payload.append(&mut BitVec::from_bytes(&packet_bytes));
    payload
}