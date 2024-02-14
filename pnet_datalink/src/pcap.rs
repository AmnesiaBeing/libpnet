//! Support for sending and receiving data link layer packets using libpcap.
//! Also has support for reading pcap files.

use std::io;
use std::marker::{Send, Sync};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pcap::{Activated, Linktype};

use crate::Channel::Ethernet;
use crate::{ChannelType, Config, DataLinkReceiver, NetworkInterface};

/// Configuration for the pcap datalink backend.
// #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
// pub struct Config {
//     /// The size of buffer to use when reading packets. Must be at least
//     /// 65516 with pcap.
//     pub read_buffer_size: usize,

//     /// The read timeout. Defaults to None.
//     pub read_timeout: Option<Duration>,

//     /// Promiscuous mode.
//     pub promiscuous: bool,
// }

// impl<'a> From<&'a super::Config> for Config {
//     fn from(config: &super::Config) -> Config {
//         let mut c = Config {
//             read_buffer_size: config.read_buffer_size,
//             read_timeout: config.read_timeout,
//             promiscuous: config.promiscuous,
//         };
//         // pcap is unique in that the buffer size must be greater or equal to
//         // MAXIMUM_SNAPLEN, which is currently hard-coded to 65536
//         // So, just reset it to the default.
//         if c.read_buffer_size < 65536 {
//             c.read_buffer_size = Config::default().read_buffer_size;
//         }
//         c
//     }
// }

// impl Default for Config {
//     fn default() -> Config {
//         Config {
//             // Just let pcap pick the default size
//             read_buffer_size: 0,
//             read_timeout: None,
//             promiscuous: true,
//         }
//     }
// }

/// Create a datalink channel from the provided pcap device.
#[inline]
pub fn channel(
    network_interface: &NetworkInterface,
    config: &Config,
) -> io::Result<super::Channel> {
    let cap = match pcap::Capture::from_device(&*network_interface.name) {
        Ok(cap) => cap,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    }
    .buffer_size(config.read_buffer_size as i32);
    // Set pcap timeout (in milliseconds).
    // For conversion .as_millis() method could be used as well, but might have
    // a small performance impact as it uses u128 as return type
    let cap = match config.read_timeout {
        Some(to) => cap.timeout((to.as_secs() as u32 * 1000 + to.subsec_millis()) as i32),
        None => cap,
    };
    // Enable promiscuous capture
    let cap = cap.promisc(config.promiscuous);
    let cap = match cap.open() {
        Ok(cap) => cap,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    };
    let cap = Arc::new(Mutex::new(cap));
    Ok(Ethernet(Box::new(DataLinkReceiverImpl {
        capture: cap.clone(),
        ts: Duration::default(),
        read_buffer: vec![0; config.read_buffer_size],
    })))
}

/// Create a datalink channel from a pcap file.
#[allow(dead_code)]
#[inline]
pub fn from_file<P: AsRef<Path>>(path: P, config: &mut Config) -> io::Result<super::Channel> {
    let cap = match pcap::Capture::from_file(path) {
        Ok(cap) => {
            match cap.get_datalink() {
                Linktype::LINUX_SLL => {
                    config.channel_type = ChannelType::Layer3(Linktype::LINUX_SLL.0 as u16)
                }
                _ => config.channel_type = ChannelType::Layer2,
            }
            cap
        }
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    };
    let cap = Arc::new(Mutex::new(cap));
    Ok(Ethernet(Box::new(DataLinkReceiverImpl {
        capture: cap.clone(),
        ts: Duration::default(),
        read_buffer: vec![0; config.read_buffer_size],
    })))
}

struct DataLinkReceiverImpl<T: Activated + Send + Sync> {
    capture: Arc<Mutex<pcap::Capture<T>>>,
    ts: Duration,
    read_buffer: Vec<u8>,
}

impl<T: Activated + Send + Sync> DataLinkReceiver for DataLinkReceiverImpl<T> {
    fn next(&mut self) -> io::Result<(&Duration, &[u8])> {
        let mut cap = self.capture.lock().unwrap();
        match cap.next_packet() {
            Ok(pkt) => {
                self.read_buffer.truncate(0);
                self.read_buffer.extend(pkt.data);
                let tv = pkt.header.ts;
                self.ts = Duration::from_nanos(
                    ((tv.tv_sec as i64) * 1_000_000_000 + (tv.tv_usec as i64) * 1_000) as u64,
                );
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        };
        Ok((&self.ts, &self.read_buffer))
    }
}

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<NetworkInterface> {
    if let Ok(devices) = pcap::Device::list() {
        devices
            .iter()
            .enumerate()
            .map(|(i, dev)| NetworkInterface {
                name: dev.name.clone(),
                description: dev.desc.clone().unwrap_or_else(|| "".to_string()),
                index: i as u32,
                mac: None,
                ips: Vec::new(),
                flags: 0,
            })
            .collect()
    } else {
        vec![]
    }
}
