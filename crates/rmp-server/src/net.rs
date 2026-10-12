//! IP/CIDR matching for the connection allow/deny lists.

use std::net::IpAddr;

/// A CIDR network (address + prefix length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `a.b.c.d/len`, `a::b/len`, or a bare address (host route).
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let prefix: u8 = p
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid prefix in {s:?}"))?;
                (a.trim(), Some(prefix))
            }
            None => (s.trim(), None),
        };
        let net: IpAddr = addr
            .parse()
            .map_err(|_| format!("invalid address in {s:?}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return Err(format!("prefix /{prefix} too large for {addr}"));
        }
        Ok(Cidr { net, prefix })
    }

    /// Whether `ip` falls within this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// Parse a list of CIDR strings.
pub fn parse_list(items: &[String]) -> Result<Vec<Cidr>, String> {
    items.iter().map(|s| Cidr::parse(s)).collect()
}

/// Access-control decision for a peer address.
///
/// Deny rules win; if `allowed` is empty, everything not denied is allowed.
pub fn is_allowed(ip: IpAddr, allowed: &[Cidr], denied: &[Cidr]) -> bool {
    if denied.iter().any(|c| c.contains(ip)) {
        return false;
    }
    if allowed.is_empty() {
        return true;
    }
    allowed.iter().any(|c| c.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_and_matches_v4() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains(ip("192.168.1.66")));
        assert!(!c.contains(ip("192.168.2.1")));
        let host = Cidr::parse("10.0.0.5").unwrap();
        assert!(host.contains(ip("10.0.0.5")));
        assert!(!host.contains(ip("10.0.0.6")));
    }

    #[test]
    fn parses_and_matches_v6() {
        let c = Cidr::parse("fe80::/10").unwrap();
        assert!(c.contains(ip("fe80::1")));
        assert!(!c.contains(ip("2001:db8::1")));
        let all = Cidr::parse("::/0").unwrap();
        assert!(all.contains(ip("2001:db8::1")));
    }

    #[test]
    fn deny_wins_and_empty_allow_permits() {
        let allowed = vec![Cidr::parse("0.0.0.0/0").unwrap()];
        let denied = vec![Cidr::parse("10.0.0.0/8").unwrap()];
        assert!(!is_allowed(ip("10.1.2.3"), &allowed, &denied));
        assert!(is_allowed(ip("8.8.8.8"), &allowed, &denied));
        // No allow list → everything not denied.
        assert!(is_allowed(ip("1.2.3.4"), &[], &denied));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Cidr::parse("not-an-ip").is_err());
        assert!(Cidr::parse("10.0.0.0/40").is_err());
    }
}
