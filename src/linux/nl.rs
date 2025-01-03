use netlink_packet_core::{
  ErrorMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_route::{
  address::AddressMessage,
  link::LinkMessage,
  route::RouteMessage,
  RouteNetlinkMessage::{self, *},
};
use netlink_packet_utils::DecodeError;
use netlink_sys::{Socket, SocketAddr};
use std::{error::Error, io};

fn to_err(e: ErrorMessage) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

fn decode_err(e: DecodeError) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, e)
}

pub struct NetlinkConnection {
  socket: Socket,
}

impl NetlinkConnection {
  pub fn new() -> io::Result<Self> {
    // Create a netlink routing socket
    let mut socket = Socket::new(netlink_sys::constants::NETLINK_ROUTE)?;

    // Bind the socket
    let kernel_addr = SocketAddr::new(0, 0);
    socket.bind(&kernel_addr)?;

    Ok(NetlinkConnection { socket })
  }

  pub fn get_links(&self) -> io::Result<Vec<LinkMessage>> {
    let mut links = Vec::new();

    // Create message header
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    header.sequence_number = 1;

    // Create netlink message
    let payload = GetLink;
    let mut nl_msg = NetlinkMessage::new(
      header,
      NetlinkPayload::from(RouteNetlinkMessage::GetLink(LinkMessage::default())),
    );

    // Send the message
    nl_msg.finalize();
    let mut buf = vec![0; nl_msg.buffer_len()];
    nl_msg.serialize(&mut buf[..]);
    self.socket.send(&buf[..], 0)?;

    // Receive responses
    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    loop {
      let size = self.socket.recv(&mut &mut receive_buffer[..], 0)?;

      loop {
        let bytes = &receive_buffer[offset..];
        let msg: NetlinkMessage<RouteNetlinkMessage> = NetlinkMessage::deserialize(bytes).unwrap();

        match msg.payload {
          NetlinkPayload::InnerMessage(NewLink(link_msg)) => {
            links.push(link_msg);
          }
          NetlinkPayload::Error(err) => {
            return Err(to_err(err));
          }
          NetlinkPayload::Done(_) => return Ok(links),
          _ => {}
        }

        offset += msg.header.length as usize;
        if offset == size || msg.header.length == 0 {
          offset = 0;
          break;
        }
      }
    }
  }

  pub fn get_addresses(&self) -> io::Result<Vec<AddressMessage>> {
    let mut addresses = Vec::new();

    // Create message header
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    header.sequence_number = 1;

    // Create netlink message
    let mut nl_msg = NetlinkMessage::new(
      header,
      NetlinkPayload::from(RouteNetlinkMessage::GetAddress(AddressMessage::default())),
    );

    // Send the message
    nl_msg.finalize();
    let mut buf = vec![0; nl_msg.buffer_len()];
    nl_msg.serialize(&mut buf[..]);
    self.socket.send(&buf[..], 0)?;

    // Receive responses
    // Receive responses
    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    loop {
      let size = self.socket.recv(&mut &mut receive_buffer[..], 0)?;

      loop {
        let bytes = &receive_buffer[offset..];
        let msg: NetlinkMessage<RouteNetlinkMessage> = NetlinkMessage::deserialize(bytes).unwrap();

        match msg.payload {
          NetlinkPayload::InnerMessage(NewAddress(msg)) => {
            addresses.push(msg);
          }
          NetlinkPayload::Error(err) => {
            return Err(to_err(err));
          }
          NetlinkPayload::Done(_) => return Ok(addresses),
          _ => {}
        }

        offset += msg.header.length as usize;
        if offset == size || msg.header.length == 0 {
          offset = 0;
          break;
        }
      }
    }
  }

  pub fn get_routes(&self) -> io::Result<Vec<RouteMessage>> {
    let mut routes = Vec::new();

    // Create message header
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    header.sequence_number = 1;

    // Create netlink message
    let mut nl_msg = NetlinkMessage::new(
      header,
      NetlinkPayload::from(RouteNetlinkMessage::GetRoute(RouteMessage::default())),
    );

    // Send the message
    nl_msg.finalize();
    let mut buf = vec![0; nl_msg.buffer_len()];
    nl_msg.serialize(&mut buf[..]);
    self.socket.send(&buf[..], 0)?;

    // Receive responses
    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    loop {
      let size = self.socket.recv(&mut &mut receive_buffer[..], 0)?;

      loop {
        let bytes = &receive_buffer[offset..];
        let msg: NetlinkMessage<RouteNetlinkMessage> = NetlinkMessage::deserialize(bytes).unwrap();

        match msg.payload {
          NetlinkPayload::InnerMessage(NewRoute(route_msg)) => {
            routes.push(route_msg);
          }
          NetlinkPayload::Error(err) => {
            return Err(to_err(err));
          }
          NetlinkPayload::Done(_) => return Ok(routes),
          _ => {}
        }

        offset += msg.header.length as usize;
        if offset == size || msg.header.length == 0 {
          offset = 0;
          break;
        }
      }
    }
  }
}

#[test]
fn t() -> Result<(), Box<dyn Error>> {
  let netlink = NetlinkConnection::new()?;

  println!("Fetching network links...");
  let links = netlink.get_links()?;
  for link in links {
    println!("Link: {:?}", link);
  }

  println!("\nFetching network addresses...");
  let addresses = netlink.get_addresses()?;
  for addr in addresses {
      println!("Address: {:?}", addr);
  }

  println!("\nFetching routes...");
  let routes = netlink.get_routes()?;
  for route in routes {
      println!("Route: {:?}", route);
  }

  Ok(())
}
