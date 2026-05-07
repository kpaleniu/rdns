use crate::ResourceRecordKind;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A single DNS resource record stored in a zone
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub name: String,
    pub ttl: i32,
    pub class: u16, // typically 1 for IN
    pub rdata: ResourceRecordKind,
}

/// In-memory DNS zone storage
#[derive(Debug, Clone)]
pub struct Zone {
    pub origin: String,
    pub records: Vec<ZoneRecord>,
}

impl Zone {
    /// Create a new zone with the given origin (e.g., "example.com.")
    pub fn new(origin: String) -> Self {
        Zone {
            origin: if origin.ends_with('.') {
                origin
            } else {
                format!("{}.", origin)
            },
            records: Vec::new(),
        }
    }

    /// Add a record to the zone
    pub fn add_record(&mut self, record: ZoneRecord) {
        self.records.push(record);
    }

    /// Query records by name and type
    pub fn query(&self, name: &str, qtype: u16) -> Vec<&ZoneRecord> {
        self.records
            .iter()
            .filter(|r| self.matches_query(&r.name, name) && record_type(&r.rdata) == qtype)
            .collect()
    }

    /// Helper to match domain names, handling wildcards and relative names
    fn matches_query(&self, record_name: &str, query_name: &str) -> bool {
        let record_name = self.normalize_name(record_name);
        let query_name = self.normalize_name(query_name);
        
        // Exact match
        if record_name == query_name {
            return true;
        }
        
        // Wildcard match (* matches one label)
        if record_name.starts_with("*.") {
            let wildcard_suffix = &record_name[1..]; // Skip the "*"
            if query_name.ends_with(wildcard_suffix) {
                // Check that wildcard doesn't match multiple labels
                let prefix = &query_name[..query_name.len() - wildcard_suffix.len()];
                if !prefix.contains('.') || prefix.is_empty() {
                    return true;
                }
            }
        }
        
        false
    }

    /// Normalize domain names to absolute form with trailing dot
    fn normalize_name(&self, name: &str) -> String {
        let name = name.trim();
        if name.is_empty() || name == "@" {
            self.origin.clone()
        } else if name.ends_with('.') {
            name.to_string()
        } else {
            // Relative to zone origin
            format!("{}.{}", name, self.origin)
        }
    }
}

/// Parse a BIND-format zone file
pub fn parse_zone_file(content: &str, origin: &str) -> Result<Zone, String> {
    let mut zone = Zone::new(origin.to_string());
    let mut current_name = String::new();
    let mut current_ttl = 3600i32;

    for line in content.lines() {
        // Remove comments
        let line = line.split(';').next().unwrap_or("").trim();
        
        if line.is_empty() {
            continue;
        }

        // Handle $ORIGIN directive
        if line.starts_with("$ORIGIN") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                zone.origin = if parts[1].ends_with('.') {
                    parts[1].to_string()
                } else {
                    format!("{}.", parts[1])
                };
            }
            continue;
        }

        // Handle $TTL directive
        if line.starts_with("$TTL") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                current_ttl = parts[1].parse().unwrap_or(3600);
            }
            continue;
        }

        // Parse zone record line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        // Handle relative names (lines starting with whitespace implicitly use previous name)
        if !line.starts_with(|c: char| c.is_whitespace()) && !parts[0].starts_with('$') {
            current_name = parts[0].to_string();
        }

        // Parse record: [name] [ttl] [class] type rdata...
        let mut idx = 0;
        let record_name = if parts[idx].ends_with('.') || parts[idx].contains(char::is_numeric) {
            // This is likely a TTL or class, use current name
            current_name.clone()
        } else {
            let name = parts[idx].to_string();
            idx += 1;
            if name != "@" {
                current_name = name.clone();
            }
            name
        };

        // Parse TTL and class
        let mut ttl = current_ttl;
        let mut class = 1u16; // IN

        while idx < parts.len() {
            if let Ok(parsed_ttl) = parts[idx].parse::<i32>() {
                ttl = parsed_ttl;
                current_ttl = ttl;
                idx += 1;
            } else if parts[idx].eq_ignore_ascii_case("IN")
                || parts[idx].eq_ignore_ascii_case("CH")
                || parts[idx].eq_ignore_ascii_case("HS")
            {
                class = match parts[idx].to_uppercase().as_str() {
                    "IN" => 1,
                    "CH" => 3,
                    "HS" => 4,
                    _ => 1,
                };
                idx += 1;
            } else {
                break;
            }
        }

        if idx >= parts.len() {
            continue;
        }

        // Parse record type and data
        let record_type = parts[idx].to_uppercase();
        idx += 1;
        let rdata = parts[idx..].join(" ");

        let rdata = match record_type.as_str() {
            "A" => {
                if let Ok(addr) = rdata.parse::<Ipv4Addr>() {
                    Some(ResourceRecordKind::A(addr))
                } else {
                    None
                }
            }
            "AAAA" => {
                if let Ok(addr) = rdata.parse::<Ipv6Addr>() {
                    Some(ResourceRecordKind::AAAA(addr))
                } else {
                    None
                }
            }
            "NS" => Some(ResourceRecordKind::NS(rdata)),
            "CNAME" => Some(ResourceRecordKind::CNAME(rdata)),
            "MX" => {
                let mx_parts: Vec<&str> = rdata.split_whitespace().collect();
                if mx_parts.len() >= 2 {
                    if let Ok(pref) = mx_parts[0].parse::<u16>() {
                        Some(ResourceRecordKind::MX {
                            preference: pref,
                            exchange: mx_parts[1..].join(" "),
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            "TXT" => {
                // Remove quotes from TXT records
                let txt_data = rdata
                    .trim_matches('"')
                    .to_string();
                Some(ResourceRecordKind::TXT(txt_data))
            }
            "PTR" => Some(ResourceRecordKind::PTR(rdata)),
            "SOA" => {
                let soa_parts: Vec<&str> = rdata.split_whitespace().collect();
                if soa_parts.len() >= 7 {
                    if let (Ok(serial), Ok(refresh), Ok(retry), Ok(expire), Ok(minimum)) = (
                        soa_parts[2].parse::<u32>(),
                        soa_parts[3].parse::<i32>(),
                        soa_parts[4].parse::<i32>(),
                        soa_parts[5].parse::<i32>(),
                        soa_parts[6].parse::<u32>(),
                    ) {
                        Some(ResourceRecordKind::SOA {
                            mname: soa_parts[0].to_string(),
                            rname: soa_parts[1].to_string(),
                            serial,
                            refresh,
                            retry,
                            expire,
                            minimum,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(rdata) = rdata {
            zone.add_record(ZoneRecord {
                name: record_name,
                ttl,
                class,
                rdata,
            });
        }
    }

    Ok(zone)
}

/// Get the numeric type ID from ResourceRecordKind
fn record_type(rdata: &ResourceRecordKind) -> u16 {
    match rdata {
        ResourceRecordKind::A(_) => 1,
        ResourceRecordKind::NS(_) => 2,
        ResourceRecordKind::CNAME(_) => 5,
        ResourceRecordKind::SOA { .. } => 6,
        ResourceRecordKind::PTR(_) => 12,
        ResourceRecordKind::MX { .. } => 15,
        ResourceRecordKind::TXT(_) => 16,
        ResourceRecordKind::AAAA(_) => 28,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_creation() {
        let zone = Zone::new("example.com".to_string());
        assert_eq!(zone.origin, "example.com.");
    }

    #[test]
    fn test_simple_zone_file_parse() {
        let zone_content = r#"
$ORIGIN example.com.
$TTL 3600
@   IN  SOA ns1.example.com. admin.example.com. 2021010101 3600 1800 604800 86400
@   IN  NS  ns1.example.com.
@   IN  A   192.0.2.1
www IN  A   192.0.2.2
mail IN A   192.0.2.3
        "#;
        
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        assert_eq!(zone.origin, "example.com.");
        assert!(zone.records.len() >= 4);
    }
}
