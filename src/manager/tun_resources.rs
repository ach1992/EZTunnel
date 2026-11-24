//! Resources of the two TUN endpoints. An inventory contains no keys or full configurations.
//! Default routes are deliberately ignored: the TUN engine adds only point-to-point host routes.
use super::{service, store::Store};
use crate::config::{Config, TunConfig};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    process::Command,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "NetworkWire")]
struct Network {
    address: IpAddr,
    prefix: u8,
}

#[derive(Deserialize)]
struct NetworkWire {
    address: IpAddr,
    prefix: u8,
}

impl TryFrom<NetworkWire> for Network {
    type Error = anyhow::Error;

    fn try_from(wire: NetworkWire) -> Result<Self> {
        Self::parse(&format!("{}/{}", wire.address, wire.prefix))
    }
}

impl Network {
    fn parse(text: &str) -> Result<Self> {
        let (ip, prefix) = text
            .split_once('/')
            .map_or((text, None), |(ip, n)| (ip, Some(n)));
        let address: IpAddr = ip
            .parse()
            .with_context(|| format!("invalid network address {ip}"))?;
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.map(str::parse::<u8>).transpose()?.unwrap_or(bits);
        ensure!(prefix <= bits, "invalid prefix in {text}");
        Ok(Self { address, prefix })
    }

    fn range(self) -> (u128, u128) {
        let (number, bits) = number(self.address);
        let host = bits - self.prefix;
        let mask = if host == 128 {
            u128::MAX
        } else {
            (1u128 << host) - 1
        };
        (number & !mask, number | mask)
    }

    fn contains(self, address: IpAddr) -> bool {
        if self.address.is_ipv4() != address.is_ipv4() {
            return false;
        }
        let (start, end) = self.range();
        (start..=end).contains(&number(address).0)
    }
}

fn number(address: IpAddr) -> (u128, u8) {
    match address {
        IpAddr::V4(ip) => (u32::from(ip).into(), 32),
        IpAddr::V6(ip) => (u128::from(ip), 128),
    }
}

fn ip(number: u128, v6: bool) -> IpAddr {
    if v6 {
        Ipv6Addr::from(number).into()
    } else {
        Ipv4Addr::from(number as u32).into()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Inventory {
    interfaces: BTreeSet<String>,
    networks: BTreeSet<Network>,
    tcp_ports: BTreeSet<u16>,
    relay_ports: BTreeSet<u16>,
}

/// Inventory only the information needed for resource allocation, not the contents of the configs.
impl Inventory {
    pub fn saved(store: &Store) -> Result<Self> {
        let mut inventory = Self::default();
        for name in store.names()? {
            inventory
                .add_config(&store.read(&name)?)
                .with_context(|| format!("read saved resources of {name}"))?;
        }
        Ok(inventory)
    }

    /// Ordinary forwarding does not need the complete TUN inventory. Keep its
    /// existing behavior when another configuration is damaged, but honor
    /// every readable saved relay reservation, including stopped tunnels.
    pub fn saved_relays(store: &Store) -> Result<Self> {
        let mut inventory = Self::default();
        for name in store.names()? {
            if let Ok(value) = store.read(&name)
                && let Some(port) = value["tun"]["forwarding_port"]
                    .as_u64()
                    .and_then(|port| u16::try_from(port).ok())
            {
                inventory.relay_ports.insert(port);
            }
        }
        Ok(inventory)
    }

    pub fn add_config(&mut self, value: &Value) -> Result<()> {
        let config: Config = serde_json::from_value(value.clone())?;
        self.tcp_ports.extend(tcp_listeners(&config));
        if let Some(tun) = &config.tun {
            self.interfaces.insert(tun.name.clone());
            self.networks.insert(Network::parse(&tun.address)?);
            self.networks.insert(Network::parse(&tun.peer_address)?);
            if let Some(port) = tun.forwarding_port {
                self.tcp_ports.insert(port);
                self.relay_ports.insert(port);
            }
        }
        Ok(())
    }

    /// The actual kernel state, including addresses, all non-default routes and TCP listeners.
    pub fn collect(store: &Store) -> Result<Self> {
        let mut inventory = Self::saved(store)?;
        if store.system {
            preflight()?;
            inventory.add_host()?;
        }
        Ok(inventory)
    }

    fn add_host(&mut self) -> Result<()> {
        self.add_addresses(&ip_json(&["-j", "address", "show"])?)?;
        for family in ["-4", "-6"] {
            self.add_routes(&ip_json(&["-j", family, "route", "show", "table", "all"])?)?;
        }
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(error)
                    if path.ends_with("tcp6") && error.kind() == std::io::ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => return Err(error).with_context(|| format!("read {path}")),
            };
            // Include bound local ports from live sockets, not only listening sockets.
            for line in text.lines().skip(1) {
                let local = line
                    .split_whitespace()
                    .nth(1)
                    .context("invalid TCP socket table")?;
                let (_, port) = local.rsplit_once(':').context("invalid local TCP socket")?;
                self.tcp_ports.insert(u16::from_str_radix(port, 16)?);
            }
        }
        Ok(())
    }

    fn add_addresses(&mut self, rows: &Value) -> Result<()> {
        for row in rows.as_array().context("invalid ip address output")? {
            let name = row["ifname"].as_str().context("interface name missing")?;
            self.interfaces.insert(name.into());
            for address in row["addr_info"].as_array().into_iter().flatten() {
                if let Some(local) = address["local"].as_str() {
                    let prefix = address["prefixlen"]
                        .as_u64()
                        .context("address prefix missing")?;
                    // The local address and the connected subnet are both occupied; for a
                    // point-to-point interface the prefix describes its peer instead.
                    self.networks.insert(Network::parse(local)?);
                    if let Some(peer) = peer_of(address) {
                        let net = if peer.contains('/') {
                            Network::parse(peer)?
                        } else {
                            Network::parse(&format!("{peer}/{prefix}"))?
                        };
                        self.networks.insert(net);
                    } else {
                        let net = Network::parse(&format!("{local}/{prefix}"))?;
                        if net.prefix != 0 {
                            self.networks.insert(net);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn add_routes(&mut self, rows: &Value) -> Result<()> {
        for route in rows.as_array().context("invalid ip route output")? {
            if let Some(destination) = route["dst"].as_str().filter(|s| *s != "default") {
                let net = Network::parse(destination)?;
                if net.prefix != 0 {
                    self.networks.insert(net);
                }
            }
        }
        Ok(())
    }

    fn occupied(&self, address: IpAddr) -> bool {
        self.networks
            .iter()
            .any(|network| network.contains(address))
    }

    /// A name on each machine, not a shared globally unique interface name.
    pub fn free_name(&self) -> Result<String> {
        (0..=u32::MAX)
            .map(|n| format!("ez{n}"))
            .find(|name| !self.interfaces.contains(name))
            .context("no free TUN interface name")
    }

    /// Same inner TCP relay port on both ends, excluding the new carrier and user maps.
    pub fn relay_port(&self, other: &Self, extra: &[u16]) -> Result<u16> {
        (47475..=u16::MAX)
            .chain(1024..47475)
            .find(|port| {
                !self.tcp_ports.contains(port)
                    && !other.tcp_ports.contains(port)
                    && !extra.contains(port)
            })
            .context("no free TCP forwarding port on both servers")
    }

    pub fn check_pair(&self, first: IpAddr, second: IpAddr) -> Result<()> {
        ensure!(
            first != second && first.is_ipv4() == second.is_ipv4(),
            "TUN addresses must be distinct and use the same IP version"
        );
        for address in [first, second] {
            ensure!(
                !address.is_unspecified()
                    && !address.is_multicast()
                    && !address.is_loopback()
                    && match address {
                        IpAddr::V4(v4) => !v4.is_broadcast() && !v4.is_link_local(),
                        IpAddr::V6(v6) =>
                            !v6.is_unicast_link_local() && v6.to_ipv4_mapped().is_none(),
                    },
                "TUN address {address} is not suitable for a private point-to-point link"
            );
            ensure!(
                !self.occupied(address),
                "TUN address {address} overlaps an existing interface, route or saved tunnel"
            );
        }
        Ok(())
    }

    /// Prefer the familiar 10.77.0.1/.2 (or fd77::1/::2); skip entire conflicting ranges,
    /// rather than scan every host of a large network. The four-address spacing is conventional,
    /// not a configured subnet: the device itself uses only the two host addresses.
    pub fn automatic_pair(&self, other: &Self, v6: bool) -> Result<(IpAddr, IpAddr)> {
        let pools: &[&str] = if v6 {
            &["fd77::/64", "fd00::/8"]
        } else {
            &[
                "10.77.0.0/16",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
            ]
        };
        let occupied: Vec<(u128, u128)> = self
            .networks
            .iter()
            .chain(&other.networks)
            .filter(|net| net.address.is_ipv6() == v6)
            .map(|net| net.range())
            .collect();
        for pool in pools {
            let (start, end) = Network::parse(pool)?.range();
            let mut block = start;
            while block.checked_add(3).is_some_and(|last| last <= end) {
                let first = block + 1;
                let second = block + 2;
                if let Some(last) = occupied
                    .iter()
                    .filter(|(lo, hi)| *lo <= second && *hi >= first)
                    .map(|(_, hi)| *hi)
                    .max()
                {
                    let Some(next) = (last & !3).checked_add(4) else {
                        break;
                    };
                    block = next;
                } else {
                    return Ok((ip(first, v6), ip(second, v6)));
                }
            }
        }
        anyhow::bail!(
            "no free private address pair on both servers; choose unused addresses manually"
        )
    }

    /// Recheck resources just before the new file is saved under the store-wide allocation lock.
    pub fn check_new(&self, config: &Config) -> Result<()> {
        if let Some(tun) = &config.tun {
            ensure!(
                !self.interfaces.contains(&tun.name),
                "TUN interface {} is already in use",
                tun.name
            );
            self.check_pair(tun.address.parse()?, tun.peer_address.parse()?)?;
            if let Some(port) = tun.forwarding_port {
                ensure!(
                    !self.tcp_ports.contains(&port),
                    "TUN forwarding TCP port {port} is already in use"
                );
                ensure!(
                    !tcp_listeners(config).contains(&port),
                    "TUN forwarding TCP port {port} conflicts with this tunnel's listener"
                );
            }
        }
        for port in tcp_listeners(config) {
            ensure!(
                !self.relay_ports.contains(&port),
                "TCP port {port} is reserved by a saved TUN relay"
            );
        }
        Ok(())
    }
}

fn tcp_listeners(config: &Config) -> BTreeSet<u16> {
    let mut ports: BTreeSet<_> = service::listening_ports(config)
        .into_iter()
        .filter(|(_, proto)| *proto == "tcp")
        .map(|(port, _)| port)
        .collect();
    if let Some(bind) = config
        .socks5
        .as_deref()
        .and_then(|bind| bind.parse::<SocketAddr>().ok())
    {
        ports.insert(bind.port());
    }
    ports
}

fn peer_of(address: &Value) -> Option<&str> {
    address["peer"].as_str().or_else(|| {
        address["address"]
            .as_str()
            .filter(|peer| address["local"].as_str() != Some(*peer))
    })
}

fn ip_json(args: &[&str]) -> Result<Value> {
    let result = Command::new("ip")
        .args(args)
        .output()
        .context("run iproute2 (ip is required)")?;
    ensure!(
        result.status.success(),
        "iproute2: {}",
        String::from_utf8_lossy(&result.stderr).trim()
    );
    serde_json::from_slice(&result.stdout).context("read iproute2 JSON")
}

pub fn preflight() -> Result<()> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .context("open /dev/net/tun (Linux TUN support is required)")?;
    let status =
        std::fs::read_to_string("/proc/self/status").context("read process capabilities")?;
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .context("process capabilities unavailable")?;
    ensure!(
        u64::from_str_radix(effective.trim(), 16)? & (1 << 12) != 0,
        "TUN setup requires CAP_NET_ADMIN"
    );
    Ok(())
}

/// True only when the named live interface has the configured local and peer addresses, is
/// administratively up, and has the expected MTU. Never equate this with carrier reachability.
pub fn interface_ready(tun: &TunConfig) -> Result<bool> {
    ensure!(
        !tun.name.is_empty()
            && tun.name.len() < libc::IFNAMSIZ
            && tun
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')),
        "invalid TUN interface name"
    );
    if !std::path::Path::new("/sys/class/net")
        .join(&tun.name)
        .exists()
    {
        return Ok(false);
    }
    let rows = ip_json(&["-j", "address", "show", "dev", &tun.name])?;
    let local: IpAddr = tun.address.parse()?;
    let peer: IpAddr = tun.peer_address.parse()?;
    ready_in(&rows, tun, local, peer)
}

fn ready_in(rows: &Value, tun: &TunConfig, local: IpAddr, peer: IpAddr) -> Result<bool> {
    Ok(rows
        .as_array()
        .context("invalid ip address output")?
        .iter()
        .any(|row| {
            row["ifname"] == tun.name
                && row["mtu"] == tun.mtu
                && row["flags"].as_array().is_some_and(|flags| {
                    flags.iter().any(|flag| flag == "UP")
                        && flags.iter().any(|flag| flag == "POINTOPOINT")
                })
                && row["addr_info"].as_array().is_some_and(|addrs| {
                    addrs.iter().any(|addr| {
                        addr["local"]
                            .as_str()
                            .and_then(|s| s.parse::<IpAddr>().ok())
                            == Some(local)
                            && peer_of(addr)
                                .and_then(|s| Network::parse(s).ok())
                                .map(|net| net.address)
                                == Some(peer)
                    })
                })
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn invalid_peer_inventory_prefix_is_rejected() {
        let value = json!({"interfaces":[], "networks":[{"address":"10.0.0.0","prefix":33}],
            "tcp_ports":[], "relay_ports":[]});
        assert!(serde_json::from_value::<Inventory>(value).is_err());
    }

    #[test]
    fn both_hosts_and_routes_choose_the_next_free_pair() {
        let mut a = Inventory::default();
        let mut b = Inventory::default();
        a.add_routes(&json!([{"dst":"default"}, {"dst":"10.77.0.0/24"}, {"dst":"0.0.0.0/0"}]))
            .unwrap();
        b.add_addresses(&json!([{"ifname":"ez0", "addr_info":[{"local":"10.77.1.1","prefixlen":32,"peer":"10.77.1.2"}]}])).unwrap();
        assert_eq!(
            a.automatic_pair(&b, false).unwrap(),
            ("10.77.1.5".parse().unwrap(), "10.77.1.6".parse().unwrap())
        );
        a.add_routes(&json!([{"dst":"10.0.0.0/8"}])).unwrap();
        assert_eq!(
            a.automatic_pair(&b, false).unwrap().0,
            "172.16.0.1".parse::<IpAddr>().unwrap()
        );
        b.add_routes(&json!([{"dst":"fd77::/64"},{"dst":"::/0"}]))
            .unwrap();
        assert_eq!(
            a.automatic_pair(&b, true).unwrap().0,
            "fd00::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn iproute2_point_to_point_json_is_read_for_both_ip_families() {
        for (local, peer, family, prefix) in [
            ("10.244.248.1", "10.244.248.2", "inet", 32),
            ("fd77:244::1", "fd77:244::2", "inet6", 128),
        ] {
            let tun: TunConfig = serde_json::from_value(json!({"name":"eztest", "address":local,
                "peer_address":peer, "mtu":1400}))
            .unwrap();
            let rows = json!([{"ifname":"eztest","mtu":1400,"flags":["POINTOPOINT","UP"],
                "addr_info":[{"family":family,"local":local,"address":peer,"prefixlen":prefix}]}]);
            assert!(ready_in(&rows, &tun, local.parse().unwrap(), peer.parse().unwrap()).unwrap());
            let mut inventory = Inventory::default();
            inventory.add_addresses(&rows).unwrap();
            assert!(inventory.occupied(local.parse().unwrap()));
            assert!(inventory.occupied(peer.parse().unwrap()));
            let mut wrong = rows.clone();
            wrong[0]["mtu"] = json!(1280);
            assert!(
                !ready_in(&wrong, &tun, local.parse().unwrap(), peer.parse().unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn concurrent_creates_cannot_claim_the_same_stopped_tunnel_resources() {
        use crate::{
            config::Transport,
            manager::plan::{Carry, Direction, Plan, Side, TunPlan},
            tunnel_key::TunnelKey,
        };
        let root = tempfile::tempdir().unwrap();
        let store = Store::for_test(root.path().into());
        let build = |name: &str, address: &str, peer: &str, relay: u16| {
            let mut plan = Plan::new(
                TunnelKey::generate().unwrap().display(),
                Side::Iran,
                Direction::Reverse,
                Transport::Tcp,
            );
            plan.carry = Carry::TunPorts;
            plan.ports = crate::manager::plan::parse_ports("8080").unwrap();
            plan.tun = Some(TunPlan {
                name: name.into(),
                local_ip: address.into(),
                peer_ip: peer.into(),
                mtu: 1400,
                forwarding_port: Some(relay),
                fragment: false,
            });
            plan.to_json().unwrap()
        };
        let config = build("ez0", "10.77.0.1", "10.77.0.2", 47475);
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let save = |name: &str| {
                let _guard = store.lock(name, false).unwrap();
                barrier.wait();
                store.save_new(name, &config)
            };
            let a = scope.spawn(move || save("first"));
            let b = scope.spawn(move || save("second"));
            [a.join().unwrap(), b.join().unwrap()]
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(store.names().unwrap().len(), 1);
        let inventory = Inventory::saved(&store).unwrap();
        assert_eq!(inventory.free_name().unwrap(), "ez1");
        let (a, b) = inventory
            .automatic_pair(&Inventory::default(), false)
            .unwrap();
        assert_eq!(
            (a.to_string(), b.to_string()),
            ("10.77.0.5".into(), "10.77.0.6".into())
        );
        assert_eq!(
            inventory.relay_port(&Inventory::default(), &[]).unwrap(),
            47476
        );
        let second = build("ez1", &a.to_string(), &b.to_string(), 47476);
        store.save_new("third", &second).unwrap();
        let mut ordinary = Plan::new(
            TunnelKey::generate().unwrap().display(),
            Side::Iran,
            Direction::Reverse,
            Transport::Tcp,
        );
        ordinary.ports = crate::manager::plan::parse_ports("47475").unwrap();
        assert!(
            store
                .save_new("reserved-relay", &ordinary.to_json().unwrap())
                .is_err()
        );
        assert_eq!(store.names().unwrap().len(), 2);
    }

    #[test]
    fn names_manual_addresses_and_relay_conflicts_are_checked() {
        let mut a = Inventory::default();
        let mut b = Inventory::default();
        a.interfaces.insert("ez0".into());
        a.networks.insert(Network::parse("10.77.0.0/24").unwrap());
        a.tcp_ports.insert(47475);
        b.tcp_ports.insert(47476);
        assert_ne!(a.free_name().unwrap(), "ez0");
        assert_eq!(a.relay_port(&b, &[47477]).unwrap(), 47478);
        assert!(
            a.check_pair("10.77.0.2".parse().unwrap(), "10.78.0.1".parse().unwrap())
                .is_err()
        );
        assert!(
            a.check_pair("10.78.0.2".parse().unwrap(), "fd77::1".parse().unwrap())
                .is_err()
        );
        assert!(
            a.check_pair("fd77::1".parse().unwrap(), "fd77::2".parse().unwrap())
                .is_ok()
        );
    }
}
