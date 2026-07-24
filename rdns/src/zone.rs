use crate::{ParsedRecord, RecordData};
use crate::utils::record_type_code;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A single DNS resource record stored in a zone
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub name: String,
    pub ttl: i32,
    pub class: u16, // typically 1 for IN
    pub rdata: RecordData,
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
            .filter(|r| self.matches_query(&r.name, name) && record_type_code(&r.rdata) == qtype)
            .collect()
    }

    /// Helper to match domain names, handling wildcards and relative names.
    ///
    /// Both sides are normalized to absolute form first, so a record stored as
    /// `@` or `www` matches a query for the origin or `www.<origin>.`.
    pub fn matches_query(&self, record_name: &str, query_name: &str) -> bool {
        // DNS names compare case-insensitively (RFC 4343).
        let record_name = self.normalize_name(record_name).to_lowercase();
        let query_name = self.normalize_name(query_name).to_lowercase();

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
    pub fn normalize_name(&self, name: &str) -> String {
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

fn parse_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    let hex_str = hex_str.trim();
    if !hex_str.len().is_multiple_of(2) {
        return Err("Odd number of hexadecimal digits".to_string());
    }
    let mut res = Vec::with_capacity(hex_str.len() / 2);
    let chars: Vec<char> = hex_str.chars().collect();
    for i in (0..chars.len()).step_by(2) {
        let high = chars[i].to_digit(16).ok_or("Invalid hex digit")? as u8;
        let low = chars[i+1].to_digit(16).ok_or("Invalid hex digit")? as u8;
        res.push((high << 4) | low);
    }
    Ok(res)
}

fn parse_base32_hex(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim().to_uppercase();
    let alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let char_to_val = |c: u8| -> Option<u8> {
        alphabet.iter().position(|&x| x == c).map(|p| p as u8)
    };
    
    let mut bits = 0u64;
    let mut count = 0;
    let mut res = Vec::new();
    
    for &c in input.as_bytes() {
        if c == b'=' {
            break; // Skip padding
        }
        let val = char_to_val(c).ok_or_else(|| format!("Invalid Base32 hex character: {}", c as char))?;
        bits = (bits << 5) | (val as u64);
        count += 5;
        if count >= 8 {
            res.push((bits >> (count - 8)) as u8);
            count -= 8;
        }
    }
    Ok(res)
}

fn parse_dnssec_time(time_str: &str) -> Result<u32, String> {
    if let Ok(epoch) = time_str.parse::<u32>() {
        return Ok(epoch);
    }
    if time_str.len() == 14 {
        let year = time_str[0..4].parse::<i32>().map_err(|e| e.to_string())?;
        let month = time_str[4..6].parse::<i32>().map_err(|e| e.to_string())?;
        let day = time_str[6..8].parse::<i32>().map_err(|e| e.to_string())?;
        let hour = time_str[8..10].parse::<i32>().map_err(|e| e.to_string())?;
        let min = time_str[10..12].parse::<i32>().map_err(|e| e.to_string())?;
        let sec = time_str[12..14].parse::<i32>().map_err(|e| e.to_string())?;
        
        let is_leap = |y| (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        let days_in_month = |m, y| match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => if is_leap(y) { 29 } else { 28 },
            _ => 0,
        };
        
        let mut total_days = 0;
        for y in 1970..year {
            total_days += if is_leap(y) { 366 } else { 365 };
        }
        for m in 1..month {
            total_days += days_in_month(m, year);
        }
        total_days += day - 1;
        
        let epoch = total_days as i64 * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
        return Ok(epoch as u32);
    }
    Err(format!("Invalid DNSSEC time format: {}", time_str))
}

fn construct_type_bitmap(types: &[String]) -> Vec<u8> {
    let mut codes = Vec::new();
    for t in types {
        if let Some(code) = crate::utils::record_type_name_to_code(t) {
            codes.push(code);
        }
    }
    codes.sort();
    codes.dedup();
    
    let mut blocks: std::collections::BTreeMap<u8, Vec<u8>> = std::collections::BTreeMap::new();
    for code in codes {
        let block_num = (code / 256) as u8;
        let block_offset = (code % 256) as u8;
        let byte_offset = (block_offset / 8) as usize;
        let bit_offset = block_offset % 8;
        
        let bitmap = blocks.entry(block_num).or_insert_with(|| vec![0u8; 32]);
        bitmap[byte_offset] |= 1 << (7 - bit_offset);
    }
    
    let mut result = Vec::new();
    for (block_num, bitmap) in blocks {
        let mut len = 32;
        while len > 0 && bitmap[len - 1] == 0 {
            len -= 1;
        }
        if len > 0 {
            result.push(block_num);
            result.push(len as u8);
            result.extend_from_slice(&bitmap[..len]);
        }
    }
    result
}

/// Parse a BIND-format zone file
pub fn parse_zone_file(content: &str, origin: &str) -> Result<Zone, String> {
    let mut zone = Zone::new(origin.to_string());
    let mut current_name = String::new();
    let mut current_ttl = 3600i32;

    for (line_idx, raw_line) in content.lines().enumerate() {
        let ln = line_idx + 1;
        // Strip comments, but read the indentation off the raw line first: a
        // record line that begins with whitespace omits its owner name and
        // inherits the previous record's (RFC 1035 §5.1).
        let uncommented = raw_line.split(';').next().unwrap_or("");
        let omits_owner = uncommented.starts_with(|c: char| c.is_whitespace());
        let line = uncommented.trim();

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
                current_ttl = parts[1]
                    .parse()
                    .map_err(|e| format!("line {ln}: invalid $TTL {:?}: {e}", parts[1]))?;
            }
            continue;
        }

        // Parse zone record line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        // Parse record: [name] [ttl] [class] type rdata...
        //
        // Position is what tells an owner name apart from a TTL/class/type, not
        // the token's shape: a name may end in '.' (an FQDN) or contain digits
        // (`www2`), and common host names collide with type mnemonics (`ns IN A
        // …` — `ns` is the owner there, not an NS record).
        let mut idx = 0;
        if !omits_owner {
            current_name = parts[0].to_string();
            idx += 1;
        } else if current_name.is_empty() {
            return Err(format!(
                "line {ln}: record omits its owner name but no previous record supplies one"
            ));
        }
        let record_name = current_name.clone();

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

        let rdata: RecordData = match record_type.as_str() {
            "A" => {
                let addr = rdata
                    .parse::<Ipv4Addr>()
                    .map_err(|e| format!("line {ln}: invalid A address {rdata:?}: {e}"))?;
                RecordData::from_parsed(&ParsedRecord::A(addr))
                    .map_err(|e| format!("line {ln}: A record: {e}"))?
            }
            "AAAA" => {
                let addr = rdata
                    .parse::<Ipv6Addr>()
                    .map_err(|e| format!("line {ln}: invalid AAAA address {rdata:?}: {e}"))?;
                RecordData::from_parsed(&ParsedRecord::AAAA(addr))
                    .map_err(|e| format!("line {ln}: AAAA record: {e}"))?
            }
            "NS" => RecordData::from_parsed(&ParsedRecord::NS(rdata))
                .map_err(|e| format!("line {ln}: NS record: {e}"))?,
            "CNAME" => RecordData::from_parsed(&ParsedRecord::CNAME(rdata))
                .map_err(|e| format!("line {ln}: CNAME record: {e}"))?,
            "MX" => {
                let mx_parts: Vec<&str> = rdata.split_whitespace().collect();
                if mx_parts.len() < 2 {
                    return Err(format!(
                        "line {ln}: MX record needs preference and exchange, got {:?}",
                        rdata
                    ));
                }
                let preference = mx_parts[0]
                    .parse::<u16>()
                    .map_err(|e| format!("line {ln}: invalid MX preference {:?}: {e}", mx_parts[0]))?;
                RecordData::from_parsed(&ParsedRecord::MX {
                    preference,
                    exchange: mx_parts[1..].join(" "),
                })
                .map_err(|e| format!("line {ln}: MX record: {e}"))?
            }
            "TXT" => {
                // Remove quotes from TXT records
                let txt_data = rdata.trim_matches('"').to_string();
                RecordData::from_parsed(&ParsedRecord::TXT(txt_data))
                    .map_err(|e| format!("line {ln}: TXT record: {e}"))?
            }
            "PTR" => RecordData::from_parsed(&ParsedRecord::PTR(rdata))
                .map_err(|e| format!("line {ln}: PTR record: {e}"))?,
            "SOA" => {
                let soa_parts: Vec<&str> = rdata.split_whitespace().collect();
                if soa_parts.len() < 7 {
                    return Err(format!(
                        "line {ln}: SOA record needs 7 fields, got {}",
                        soa_parts.len()
                    ));
                }
                let serial = soa_parts[2]
                    .parse::<u32>()
                    .map_err(|e| format!("line {ln}: invalid SOA serial {:?}: {e}", soa_parts[2]))?;
                let refresh = soa_parts[3]
                    .parse::<i32>()
                    .map_err(|e| format!("line {ln}: invalid SOA refresh {:?}: {e}", soa_parts[3]))?;
                let retry = soa_parts[4]
                    .parse::<i32>()
                    .map_err(|e| format!("line {ln}: invalid SOA retry {:?}: {e}", soa_parts[4]))?;
                let expire = soa_parts[5]
                    .parse::<i32>()
                    .map_err(|e| format!("line {ln}: invalid SOA expire {:?}: {e}", soa_parts[5]))?;
                let minimum = soa_parts[6]
                    .parse::<u32>()
                    .map_err(|e| format!("line {ln}: invalid SOA minimum {:?}: {e}", soa_parts[6]))?;
                RecordData::from_parsed(&ParsedRecord::SOA {
                    mname: soa_parts[0].to_string(),
                    rname: soa_parts[1].to_string(),
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
                .map_err(|e| format!("line {ln}: SOA record: {e}"))?
            }
            "DNSKEY" => {
                let key_parts = &parts[idx..];
                if key_parts.len() < 4 {
                    return Err(format!(
                        "line {ln}: DNSKEY record needs 4 fields, got {}",
                        key_parts.len()
                    ));
                }
                let flags = key_parts[0]
                    .parse::<u16>()
                    .map_err(|e| format!("line {ln}: invalid DNSKEY flags {:?}: {e}", key_parts[0]))?;
                let protocol = key_parts[1]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid DNSKEY protocol {:?}: {e}", key_parts[1]))?;
                let algorithm = key_parts[2]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid DNSKEY algorithm {:?}: {e}", key_parts[2]))?;
                let b64_key = key_parts[3..].join("");
                let public_key =
                    base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &b64_key)
                        .map_err(|e| format!("line {ln}: invalid DNSKEY base64 key: {e}"))?;
                RecordData::from_parsed(&ParsedRecord::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                })
                .map_err(|e| format!("line {ln}: DNSKEY record: {e}"))?
            }
            "DS" => {
                let ds_parts = &parts[idx..];
                if ds_parts.len() < 4 {
                    return Err(format!(
                        "line {ln}: DS record needs 4 fields, got {}",
                        ds_parts.len()
                    ));
                }
                let key_tag = ds_parts[0]
                    .parse::<u16>()
                    .map_err(|e| format!("line {ln}: invalid DS key tag {:?}: {e}", ds_parts[0]))?;
                let algorithm = ds_parts[1]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid DS algorithm {:?}: {e}", ds_parts[1]))?;
                let digest_type = ds_parts[2]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid DS digest type {:?}: {e}", ds_parts[2]))?;
                let hex_digest = ds_parts[3..].join("");
                let digest = parse_hex(&hex_digest)
                    .map_err(|e| format!("line {ln}: invalid DS digest: {e}"))?;
                RecordData::from_parsed(&ParsedRecord::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                })
                .map_err(|e| format!("line {ln}: DS record: {e}"))?
            }
            "RRSIG" => {
                let rrsig_parts = &parts[idx..];
                if rrsig_parts.len() < 9 {
                    return Err(format!(
                        "line {ln}: RRSIG record needs 9 fields, got {}",
                        rrsig_parts.len()
                    ));
                }
                let type_covered = crate::utils::record_type_name_to_code(rrsig_parts[0])
                    .ok_or_else(|| {
                        format!("line {ln}: unknown RRSIG type covered {:?}", rrsig_parts[0])
                    })?;
                let algorithm = rrsig_parts[1]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid RRSIG algorithm {:?}: {e}", rrsig_parts[1]))?;
                let labels = rrsig_parts[2]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid RRSIG labels {:?}: {e}", rrsig_parts[2]))?;
                let original_ttl = rrsig_parts[3]
                    .parse::<u32>()
                    .map_err(|e| format!("line {ln}: invalid RRSIG original TTL {:?}: {e}", rrsig_parts[3]))?;
                let expiration = parse_dnssec_time(rrsig_parts[4])
                    .map_err(|e| format!("line {ln}: invalid RRSIG expiration {:?}: {e}", rrsig_parts[4]))?;
                let inception = parse_dnssec_time(rrsig_parts[5])
                    .map_err(|e| format!("line {ln}: invalid RRSIG inception {:?}: {e}", rrsig_parts[5]))?;
                let key_tag = rrsig_parts[6]
                    .parse::<u16>()
                    .map_err(|e| format!("line {ln}: invalid RRSIG key tag {:?}: {e}", rrsig_parts[6]))?;
                let signer_name = rrsig_parts[7].to_string();
                let b64_sig = rrsig_parts[8..].join("");
                let signature =
                    base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &b64_sig)
                        .map_err(|e| format!("line {ln}: invalid RRSIG base64 signature: {e}"))?;
                RecordData::from_parsed(&ParsedRecord::RRSIG {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer_name,
                    signature,
                })
                .map_err(|e| format!("line {ln}: RRSIG record: {e}"))?
            }
            "NSEC" => {
                let nsec_parts = &parts[idx..];
                if nsec_parts.len() < 2 {
                    return Err(format!(
                        "line {ln}: NSEC record needs next domain and at least one type, got {}",
                        nsec_parts.len()
                    ));
                }
                let next_domain_name = nsec_parts[0].to_string();
                let type_names: Vec<String> =
                    nsec_parts[1..].iter().map(|s| s.to_string()).collect();
                let type_bitmap = construct_type_bitmap(&type_names);
                RecordData::from_parsed(&ParsedRecord::NSEC {
                    next_domain_name,
                    type_bitmap,
                })
                .map_err(|e| format!("line {ln}: NSEC record: {e}"))?
            }
            "NSEC3" => {
                let nsec3_parts = &parts[idx..];
                if nsec3_parts.len() < 5 {
                    return Err(format!(
                        "line {ln}: NSEC3 record needs at least 5 fields, got {}",
                        nsec3_parts.len()
                    ));
                }
                let hash_algorithm = nsec3_parts[0]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid NSEC3 hash algorithm {:?}: {e}", nsec3_parts[0]))?;
                let flags = nsec3_parts[1]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid NSEC3 flags {:?}: {e}", nsec3_parts[1]))?;
                let iterations = nsec3_parts[2]
                    .parse::<u16>()
                    .map_err(|e| format!("line {ln}: invalid NSEC3 iterations {:?}: {e}", nsec3_parts[2]))?;
                let salt_str = nsec3_parts[3];
                let salt = if salt_str == "-" {
                    Vec::new()
                } else {
                    parse_hex(salt_str)
                        .map_err(|e| format!("line {ln}: invalid NSEC3 salt {:?}: {e}", salt_str))?
                };
                let next_hashed_owner = parse_base32_hex(nsec3_parts[4])
                    .map_err(|e| format!("line {ln}: invalid NSEC3 next hashed owner {:?}: {e}", nsec3_parts[4]))?;
                let type_names: Vec<String> =
                    nsec3_parts[5..].iter().map(|s| s.to_string()).collect();
                let type_bitmap = construct_type_bitmap(&type_names);
                RecordData::from_parsed(&ParsedRecord::NSEC3 {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                    next_hashed_owner,
                    type_bitmap,
                })
                .map_err(|e| format!("line {ln}: NSEC3 record: {e}"))?
            }
            other => {
                return Err(format!("line {ln}: unsupported record type {other:?}"));
            }
        };

        zone.add_record(ZoneRecord {
            name: record_name,
            ttl,
            class,
            rdata,
        });
    }

    Ok(zone)
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

    #[test]
    fn test_malformed_rdata_surfaces_error() {
        // A bad IPv4 address must fail the load, not be silently dropped.
        let zone_content = "www IN A 999.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(err.contains("line 1"), "error should carry line number: {err}");
        assert!(err.contains("A address"), "error should name the failure: {err}");
    }

    #[test]
    fn test_unsupported_record_type_surfaces_error() {
        let zone_content = "www IN WKS 192.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(err.contains("unsupported record type"), "got: {err}");
    }

    #[test]
    fn test_fully_qualified_owner_name_parses() {
        // An FQDN owner ends in '.', which the old lookahead mistook for a
        // TTL/class token and then tried to read as a record type.
        let zone = parse_zone_file("www.example.com. IN A 192.0.2.5\n", "example.com.").unwrap();
        assert_eq!(zone.records.len(), 1);
        assert_eq!(zone.records[0].name, "www.example.com.");
        assert_eq!(zone.query("www.example.com.", 1).len(), 1);
    }

    #[test]
    fn test_owner_name_may_contain_digits() {
        let zone = parse_zone_file("www2 IN A 192.0.2.6\n", "example.com.").unwrap();
        assert_eq!(zone.records[0].name, "www2");
        assert_eq!(zone.query("www2.example.com.", 1).len(), 1);
    }

    #[test]
    fn test_owner_name_may_look_like_a_record_type() {
        // "ns IN A ..." is a host called `ns`, not an NS record — position, not
        // the token's spelling, decides what the first field is.
        let zone = parse_zone_file("ns IN A 192.0.2.7\n", "example.com.").unwrap();
        assert_eq!(zone.records[0].name, "ns");
        assert_eq!(zone.query("ns.example.com.", 1).len(), 1, "should be an A record");
    }

    #[test]
    fn test_indented_line_inherits_previous_owner() {
        // RFC 1035 §5.1: a line beginning with whitespace reuses the last owner.
        let zone_content = "www IN A 192.0.2.1\n    IN A 192.0.2.2\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        assert_eq!(zone.records.len(), 2);
        assert_eq!(zone.records[1].name, "www");
        assert_eq!(zone.query("www.example.com.", 1).len(), 2);
    }

    #[test]
    fn test_indented_line_without_a_previous_owner_errors() {
        let err = parse_zone_file("    IN A 192.0.2.1\n", "example.com.").unwrap_err();
        assert!(err.contains("omits its owner name"), "got: {err}");
    }

    #[test]
    fn test_apex_and_relative_names_match_absolute_queries() {
        let zone_content = "@ IN A 192.0.2.1\nwww IN A 192.0.2.2\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        assert_eq!(zone.query("example.com.", 1).len(), 1, "@ should match the apex");
        assert_eq!(zone.query("www.example.com.", 1).len(), 1);
        // DNS names are case-insensitive (RFC 4343).
        assert_eq!(zone.query("WWW.Example.COM.", 1).len(), 1);
    }

    #[test]
    fn test_malformed_ttl_directive_surfaces_error() {
        let zone_content = "$TTL notanumber\nwww IN A 192.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(err.contains("$TTL"), "got: {err}");
    }
}
