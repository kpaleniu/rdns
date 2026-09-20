//! FNV-1a over ASCII-folded bytes, in one place.
//!
//! Two callers with unequal stakes, which is why this is a module and not a
//! helper in either of them (`TODO.md` #81b, `CLAUDE.md` §7). The name
//! compressor indexes suffixes with it, where a collision or a drift costs a
//! compression pointer and a few bytes in one message. `rdns`'s signer spreads
//! RRSIG expiry with it, where a drift moves *every* signature's expiry in every
//! zone at once — and RFC-wise the signer needs two servers holding the same
//! zone to agree about that slope, which they cannot do if the two copies of
//! this loop ever diverge. They agreed when they were merged; a golden test on
//! each side says so still.
//!
//! Hand-rolled rather than `DefaultHasher`, which is seeded per process: the
//! signer's whole requirement is that the number is a function of the input and
//! nothing else. Not DoS-resistant, on purpose — neither caller's collision is
//! worth an attacker's trouble.

/// FNV-1a (64-bit) over `bytes`, each folded to ASCII lower case (RFC 4343).
///
/// The fold is the point: `Name` compares and hashes case-insensitively, so
/// anything indexing names has to agree with it. A length octet is at most 63
/// (RFC 1035 §2.3.4), below `A`, so folding wire octets cannot touch one.
pub fn folded_hash(bytes: impl IntoIterator<Item = u8>) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(byte.to_ascii_lowercase());
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers, pinned. Both callers depend on this function being the same
    /// function next year: the compressor's index is rebuilt per message and
    /// would only lose a pointer, but the signer's slope is compared across
    /// servers and across reloads.
    #[test]
    fn the_hash_is_the_hash_it_was() {
        assert_eq!(folded_hash(std::iter::empty()), 0xcbf2_9ce4_8422_2325);
        assert_eq!(folded_hash(*b"example.com."), 0xad44_82bd_cc68_8638);
    }

    /// ASCII only, and the KELVIN SIGN is the case that catches
    /// `to_lowercase` (RFC 4343).
    #[test]
    fn folding_is_ascii_only() {
        assert_eq!(folded_hash(*b"EXAMPLE.com."), folded_hash(*b"example.com."));
        assert_ne!(
            folded_hash("\u{212A}".bytes()),
            folded_hash(std::iter::once(b'k'))
        );
    }
}
