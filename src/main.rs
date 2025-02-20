use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process;
use std::time::{Duration, Instant};
use socket2::{Domain, Protocol, Socket, Type};

/*
TODO:
    Add IPv6 support 🕸️
    Implement proper packet parsing 🔍
    Add statistics (packet loss, RTT min/max/avg) 📊
    Make it async with tokio ⚡
    happy coding! 😊
*/

// ICMP header structure
#[repr(C, packed)]
struct IcmpHeader {
    type_: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence: u16,
}

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const PACKET_SIZE: usize = 64;

fn main() {
    let target = Ipv4Addr::new(8, 8, 8, 8); // Google DNS
    let timeout = Duration::from_secs(2);
    
    if let Err(e) = send_ping(target, timeout) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn send_ping(target: Ipv4Addr, timeout: Duration) -> Result<(), String> {
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::ICMPV4),
    ).map_err(|e| format!("Socket creation failed: {}", e))?;

    socket.set_read_timeout(Some(timeout));
    socket.set_write_timeout(Some(timeout));

    // Build ICMP packet
    let mut packet = [0u8; PACKET_SIZE];
    let mut icmp_header = IcmpHeader {
        type_: ICMP_ECHO_REQUEST,
        code: 0,
        checksum: 0,
        identifier: 0x1234,
        sequence: 0x0001,
    };

    // Copy header to packet buffer
    let header_size = std::mem::size_of::<IcmpHeader>();
    unsafe {
        std::ptr::copy_nonoverlapping(
            &icmp_header as *const _ as *const u8,
            packet.as_mut_ptr(),
            header_size,
        );
    }

    // Calculate checksum (now with proper byte order)
    icmp_header.checksum = calculate_checksum(&packet).to_be();
    unsafe {
        std::ptr::copy_nonoverlapping(
            &icmp_header as *const _ as *const u8,
            packet.as_mut_ptr(),
            header_size,
        );
    }

    // Send packet
    let dest = SocketAddrV4::new(target, 0);
    let start = Instant::now();
    socket.send_to(&packet, &dest.into())
        .map_err(|e| format!("Send failed: {}", e))?;

    // Receive response
    let mut recv_buf = [MaybeUninit::uninit(); 1024];
    let (size, _) = socket.recv_from(&mut recv_buf)
        .map_err(|e| format!("Receive failed: {}", e))?;

    let rtt = start.elapsed().as_millis();
    let recv_data = unsafe { 
        std::mem::transmute::<&[MaybeUninit<u8>], &[u8]>(&recv_buf[..size])
    };

    // Verify response
    let ip_header_length = (recv_data[0] & 0x0F) as usize * 4;
    if recv_data.len() < ip_header_length + 8 {
        return Err("Received packet too short".into());
    }
    
    let icmp_payload = &recv_data[ip_header_length..];
    if icmp_payload[0] == ICMP_ECHO_REPLY
        && u16::from_be_bytes([icmp_payload[4], icmp_payload[5]]) == 0x3412
        && u16::from_be_bytes([icmp_payload[6], icmp_payload[7]]) == 0x0100
    {
        println!("Reply from {}: bytes={} time={}ms", target, size, rtt);
        Ok(())
    } else {
        println!("Reply from {}: bytes={} time={}ms", target, size, rtt);
        println!("Four and five bytes: {}", u16::from_be_bytes([icmp_payload[4], icmp_payload[5]]) );
        println!("Six  and Seven bytes: {}", u16::from_be_bytes([icmp_payload[6], icmp_payload[7]]) );
        Err("Received invalid ICMP response".into())
    }
}

// Improved checksum calculation
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    let len = data.len();
    
    while i < len {
        let mut word = data[i] as u32;
        word = (word << 8) + if i+1 < len { data[i+1] as u32 } else { 0 };
        sum = sum.wrapping_add(word as u32);
        i += 2;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}