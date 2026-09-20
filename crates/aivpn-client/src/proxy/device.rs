use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

pub struct VpnDevice {
    pub rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    mtu: usize,
}

impl VpnDevice {
    pub fn new(
        rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
        tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
        mtu: usize,
    ) -> Self {
        Self {
            rx_queue,
            tx_queue,
            mtu,
        }
    }
}

pub struct VpnRxToken {
    packet: Vec<u8>,
}

pub struct VpnTxToken {
    tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl RxToken for VpnRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.packet)
    }
}

impl TxToken for VpnTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.tx_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(buf);
        result
    }
}

impl Device for VpnDevice {
    type RxToken<'a>
        = VpnRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VpnTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = {
            let mut q = self.rx_queue.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                let pkt = q.pop_front()?;
                // IPv4-only iface. smoltcp 0.11 panics in
                // `get_source_address_ipv6` (unwrap on None) if we hand it
                // an IPv6 frame with no IPv6 CIDR configured.
                if pkt.first().map(|b| b >> 4) == Some(4) {
                    break pkt;
                }
            }
        };
        Some((
            VpnRxToken { packet },
            VpnTxToken {
                tx_queue: Arc::clone(&self.tx_queue),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VpnTxToken {
            tx_queue: Arc::clone(&self.tx_queue),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::time::Instant;

    #[test]
    fn receive_skips_ipv6_and_empty_keeps_ipv4() {
        let rx = Arc::new(Mutex::new(VecDeque::from([
            vec![0x60, 0, 0, 0, 0],
            vec![],
            vec![0x45, 0, 0, 20],
        ])));
        let tx = Arc::new(Mutex::new(VecDeque::new()));
        let mut dev = VpnDevice::new(Arc::clone(&rx), tx, 1280);
        let (tok, _) = dev.receive(Instant::from_millis(0)).expect("ipv4");
        assert_eq!(tok.packet[0], 0x45);
        assert!(rx.lock().unwrap().is_empty());
        assert!(dev.receive(Instant::from_millis(1)).is_none());
    }
}
