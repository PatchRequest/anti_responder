use std::{net::{IpAddr, Ipv4Addr, UdpSocket, SocketAddr}, io, thread};

use bit_vec::BitVec;
use pnet::{packet::{udp::{UdpPacket, MutableUdpPacket}, ip::IpNextHeaderProtocols}, transport::{transport_channel, TransportChannelType, TransportProtocol}};
use rand::Rng;


fn generate<'a>(id : &'a u16) -> UdpPacket<'a>{

    
    let mut complete_payload_with_headers = BitVec::from_elem(96, false);


    for i in 0..16{
        if *id & (1 << i) != 0{
            complete_payload_with_headers.set(i, true);
        }
    }
    let headers_flags = vec![    
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
        if headers_flags[i] == 1{
            complete_payload_with_headers.set(i+16, true);
        }
    }


    let mut packet_bytes: [u8; 27] = [
        0x11, 0x00, 0x00, 0x00, 0x00,0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x3, 0x67, 0x67, 0x67,
        0x00,
        0x00, 0xff, 0x00, 0x01
    ];
    let mut rng = rand::thread_rng();   

    for i in 1..18{
        packet_bytes[i] = rng.gen_range(0x61..0x7a);
    }

    complete_payload_with_headers.append(&mut BitVec::from_bytes(&packet_bytes));

    let payload = complete_payload_with_headers.to_bytes();
    let mut buf = vec![0;4096];
    buf.resize(payload.len()+8, 0);

    let mut new_packet = MutableUdpPacket::owned(buf).unwrap();

    new_packet.set_source(5355);
    new_packet.set_destination(5355);
    new_packet.set_payload(&payload);
    new_packet.set_length((payload.len()+8) as u16);
    
    new_packet.consume_to_immutable()

}


fn send_request(packet: UdpPacket) -> io::Result<usize> {
    let (mut txv4, _) = match transport_channel(4096, TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp))) {
        Ok((txv4, rxv4)) => (txv4, rxv4),
        Err(e) => panic!("An error occurred when creating the transport channel: {}", e),
    };
    let dest_ipv4:Ipv4Addr = Ipv4Addr::new(224,0,0,252);
    txv4.send_to(packet, IpAddr::V4(dest_ipv4))

}

fn await_response<'a>(id : &'a u16) -> (BitVec,SocketAddr) {
    // id to bits
    let mut id_bits = BitVec::from_elem(16, false);
    for i in 0..16{
        if *id & (1 << i) != 0{
            id_bits.set(i, true);
        }
    }

    let socket = UdpSocket::bind("0.0.0.0:5355");
    socket.as_ref().unwrap().join_multicast_v4(&Ipv4Addr::new(224,0,0,252), &Ipv4Addr::new(0,0,0,0));
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
        // Get the first 16 bit of header and save them in a new BitVec
        let mut id_from_answer = BitVec::from_elem(16, false);
        for i in 0..16 {
            id_from_answer.set(i, first_96_bits[i]);
        }

        if id_bits == id_from_answer {
            println!("Received LLMNR Answer!");
            return (new_bit_vec,src_addr);
        }
    }
}

fn extract_ip_from_response_body(response: BitVec) -> BitVec {
    // return the last 32 bits of the response
    let mut ip_bits = BitVec::from_elem(32, false);
    for i in 0..32 {
        ip_bits.set(i, response[i + response.len() - 32]);
    }
    ip_bits
}

pub fn search_until_responder_found() -> SocketAddr{
    loop {
        let mut rng = rand::thread_rng();   
        let id: u16 = rng.gen();
        let handler = thread::spawn(move || {
            await_response(&id)
        });
    
        let a_package = generate(&id);
        let result = send_request(a_package);
        match result {
            Ok(_) => println!("Sent request"),
            Err(e) => println!("Error sending request: {}", e),
        }
        
        let (body, src) = handler.join().unwrap();
    
        println!("Suspected Responder at: {}", src.ip());
        
        let octets = match src.ip() {
            IpAddr::V4(ip) => Ok(ip.octets()),
            _ => Err("Not an IPv4 Address"),
        };
    
        let target_ip = extract_ip_from_response_body(body).to_bytes();
        
        // build a string from the octets
        if src.ip().to_string() == format!("{}.{}.{}.{}", target_ip[0], target_ip[1], target_ip[2], target_ip[3]) {
            println!("Responder Detected!");
            return src;
        }
    }
   

}