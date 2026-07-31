//! Encoding a header block.
//!
//! Deliberately the simplest legal encoder. Every header goes out either as a
//! bare static-table index, when name *and* value match one exactly, or as a
//! literal without indexing — never Huffman-coded, never entered into a table.
//!
//! # Why give up the compression
//!
//! Because the alternative is the hardest bug in HPACK. An encoder that indexes
//! has to keep a table in lockstep with the peer's copy of it, and a divergence
//! does not fail: it makes the peer read subsequent headers as different
//! headers. There is nothing to diverge here.
//!
//! The cost is bytes on a connection that carries two request shapes, both of
//! them tiny next to the map responses coming back the other way. That is a good
//! trade for a class of bug that would be very hard to find.

use crate::Error;
use crate::hpack::static_table;

/// Append a header to `out`, returning the new length.
pub fn encode_header(name: &str, value: &str, out: &mut [u8], len: usize) -> Result<usize, Error> {
    if let Some(index) = static_table::find(name, value) {
        // Indexed header field: one byte for most of the static table.
        return encode_integer(index as u64, 7, 0x80, out, len);
    }

    let mut len = match static_table::find_name(name) {
        // Literal without indexing, name from the table.
        Some(index) => encode_integer(index as u64, 4, 0x00, out, len)?,
        // Literal without indexing, new name.
        None => {
            let len = encode_integer(0, 4, 0x00, out, len)?;
            encode_string(name, out, len)?
        }
    };
    len = encode_string(value, out, len)?;
    Ok(len)
}

/// RFC 7541 section 5.1, with `flags` supplying the bits above the prefix.
pub fn encode_integer(
    value: u64,
    prefix_bits: u32,
    flags: u8,
    out: &mut [u8],
    mut len: usize,
) -> Result<usize, Error> {
    let mask = (1u64 << prefix_bits) - 1;

    if value < mask {
        *out.get_mut(len).ok_or(Error::BufferTooSmall)? = flags | value as u8;
        return Ok(len + 1);
    }

    *out.get_mut(len).ok_or(Error::BufferTooSmall)? = flags | mask as u8;
    len += 1;
    let mut remaining = value - mask;
    while remaining >= 0x80 {
        *out.get_mut(len).ok_or(Error::BufferTooSmall)? = (remaining as u8 & 0x7f) | 0x80;
        len += 1;
        remaining >>= 7;
    }
    *out.get_mut(len).ok_or(Error::BufferTooSmall)? = remaining as u8;
    Ok(len + 1)
}

/// A length-prefixed literal string. The high bit of the length byte is zero,
/// which is what says "not Huffman-coded".
fn encode_string(text: &str, out: &mut [u8], len: usize) -> Result<usize, Error> {
    let mut len = encode_integer(text.len() as u64, 7, 0x00, out, len)?;
    let end = len + text.len();
    out.get_mut(len..end)
        .ok_or(Error::BufferTooSmall)?
        .copy_from_slice(text.as_bytes());
    len = end;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpack::Decoder;

    #[test]
    fn encodes_integers_as_the_rfc_section_5_1_examples_do() {
        let mut out = [0u8; 8];
        assert_eq!(encode_integer(10, 5, 0x00, &mut out, 0).unwrap(), 1);
        assert_eq!(out[0], 0x0a);

        let n = encode_integer(1337, 5, 0x00, &mut out, 0).unwrap();
        assert_eq!(&out[..n], &[0x1f, 0x9a, 0x0a]);

        let n = encode_integer(42, 8, 0x00, &mut out, 0).unwrap();
        assert_eq!(&out[..n], &[0x2a]);
    }

    #[test]
    fn a_header_matching_the_static_table_exactly_costs_one_byte() {
        let mut out = [0u8; 64];
        let n = encode_header(":method", "GET", &mut out, 0).unwrap();
        assert_eq!(&out[..n], &[0x82]);

        let n = encode_header(":scheme", "http", &mut out, 0).unwrap();
        assert_eq!(&out[..n], &[0x86]);
    }

    /// The real test: whatever this encoder produces, the decoder — which was
    /// itself checked against the RFC's own byte sequences — must read back
    /// unchanged.
    #[test]
    fn everything_encoded_here_round_trips_through_the_decoder() {
        let headers = [
            (":method", "POST"),
            (":path", "/machine/register"),
            (":scheme", "http"),
            (":authority", "127.0.0.1:8080"),
            ("content-type", "application/json"),
            ("content-length", "1234"),
            ("x-tailscale-something", "a value with spaces and ünïcode"),
        ];

        let mut block = [0u8; 512];
        let mut len = 0;
        for (name, value) in headers {
            len = encode_header(name, value, &mut block, len).unwrap();
        }

        let mut decoder = Decoder::new(4096);
        let mut seen = 0;
        decoder
            .decode(&block[..len], |name, value| {
                let (expected_name, expected_value) = headers[seen];
                assert_eq!(name, expected_name);
                assert_eq!(value, expected_value);
                seen += 1;
            })
            .unwrap();
        assert_eq!(seen, headers.len());
    }

    #[test]
    fn nothing_we_emit_enters_the_peers_dynamic_table() {
        // The property that makes an encoder-side table unnecessary. If any of
        // these used incremental indexing, the peer's table would grow and our
        // indices would have to track it.
        let mut block = [0u8; 256];
        let mut len = 0;
        len = encode_header(":method", "POST", &mut block, len).unwrap();
        len = encode_header("content-type", "application/json", &mut block, len).unwrap();
        len = encode_header("custom", "value", &mut block, len).unwrap();

        let mut decoder = Decoder::new(4096);
        decoder.decode(&block[..len], |_, _| {}).unwrap();
        assert!(decoder.table().is_empty());
    }

    #[test]
    fn a_buffer_too_small_is_an_error_not_a_truncated_block() {
        let mut out = [0u8; 4];
        assert_eq!(
            encode_header("content-type", "application/json", &mut out, 0),
            Err(Error::BufferTooSmall)
        );
    }
}
