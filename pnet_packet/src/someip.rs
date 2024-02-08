use core::fmt;

use alloc::vec::Vec;

use pnet_macros::packet;
use pnet_macros_support::{packet::PrimitiveValues, types::*};

/// Constants
/// The currently supported protocol version.
pub const SOMEIP_PROTOCOL_VERSION: u8 = 1;

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod SomeipMsgTypes {
    use super::SomeipMsgType;

    pub const Request: SomeipMsgType = SomeipMsgType(0x0);
    pub const RequestNoReturn: SomeipMsgType = SomeipMsgType(0x1);
    pub const Notification: SomeipMsgType = SomeipMsgType(0x2);
    pub const Response: SomeipMsgType = SomeipMsgType(0x80);
    pub const Error: SomeipMsgType = SomeipMsgType(0x81);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SomeipMsgType(pub u8);

impl SomeipMsgType {
    pub fn new(value: u8) -> SomeipMsgType {
        SomeipMsgType(value)
    }
}

impl PrimitiveValues for SomeipMsgType {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

impl fmt::Display for SomeipMsgType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                &SomeipMsgTypes::Request => "Request",
                &SomeipMsgTypes::RequestNoReturn => "RequestNoReturn",
                &SomeipMsgTypes::Notification => "Notication",
                &SomeipMsgTypes::Response => "Response",
                &SomeipMsgTypes::Error => "Error",
                _ => "unknown",
            }
        )
    }
}

#[packet]
pub struct SomeipMsg {
    pub service_id: u16be,
    pub method_id: u16be,
    pub length: u32be,
    pub client_id: u16be,
    pub session_id: u16be,
    pub version: u8,
    pub interface_version: u8,
    #[construct_with(u8)]
    pub msg_type: SomeipMsgType,
    #[payload]
    pub msgs: Vec<u8>,
}

#[packet]
pub struct SomeipMsgs {
    #[length_fn = "someip_msgs_length"]
    pub msgs: Vec<SomeipMsg>,
    #[length_fn = "zero"]
    #[payload]
    pub payload: Vec<u8>,
}

fn zero(_packet_: &SomeipMsgsPacket) -> usize {
    0
}

fn someip_msgs_length(packet: &SomeipMsgsPacket) -> usize {
    let _ = packet;
    0
}
