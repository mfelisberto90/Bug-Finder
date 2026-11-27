use crate::security::auth::{constant_time_eq, sha256_hex};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha1::Sha1;
use std::fmt::Write as _;

type HmacSha1 = Hmac<Sha1>;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RECOVERY_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub fn encode_base32(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

pub fn decode_base32(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for ch in input.bytes() {
        if ch.is_ascii_whitespace() || ch == b'-' || ch == b'=' {
            continue;
        }
        let val = match ch.to_ascii_uppercase() {
            b'A'..=b'Z' => ch.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => 26 + (ch - b'2'),
            _ => return Err("Invalid Base32 character".into()),
        };
        buf = (buf << 5) | val as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

pub fn generate_totp_secret_b32() -> String {
    let mut raw = [0u8; 20];
    OsRng.fill_bytes(&mut raw);
    encode_base32(&raw)
}

pub fn totp_code_for_step(secret: &[u8], step: i64) -> String {
    let counter = (step.max(0) as u64).to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC-SHA1 accepts any key size");
    mac.update(&counter);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0F) as usize;
    let bin = ((digest[offset] as u32 & 0x7F) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    format!("{:06}", bin % 1_000_000)
}

pub fn totp_code_at(secret: &[u8], unix_sec: i64) -> String {
    totp_code_for_step(secret, unix_sec.div_euclid(30))
}

/// Verifies a 6-digit RFC 6238 TOTP code within +/- 1 step (30s tolerance).
/// Rejects steps <= `last_used_step` to guarantee single-use anti-replay within a time window.
pub fn verify_totp_window(
    secret: &[u8],
    code: &str,
    unix_sec: i64,
    last_used_step: Option<i64>,
) -> Option<i64> {
    let clean: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if clean.len() != 6 || secret.is_empty() {
        return None;
    }
    let current_step = unix_sec.div_euclid(30);
    for delta in [-1i64, 0, 1] {
        let step = current_step + delta;
        if let Some(last) = last_used_step {
            if step <= last {
                continue;
            }
        }
        let expected = totp_code_for_step(secret, step);
        if constant_time_eq(clean.as_bytes(), expected.as_bytes()) {
            return Some(step);
        }
    }
    None
}

fn pct_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

pub fn build_otpauth_uri(issuer: &str, email: &str, secret_b32: &str) -> String {
    let label = format!("{}:{}", pct_encode(issuer), pct_encode(email));
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits=6&period=30",
        pct_encode(issuer)
    )
}

/// Generate 10 high-entropy single-use recovery codes and their salted SHA-256 hashes.
pub fn generate_recovery_codes() -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(10);
    for _ in 0..10 {
        let mut raw = [0u8; 10];
        OsRng.fill_bytes(&mut raw);
        let mut chars = String::with_capacity(11);
        for (idx, b) in raw.iter().enumerate() {
            if idx == 5 {
                chars.push('-');
            }
            chars.push(RECOVERY_ALPHABET[(b % 32) as usize] as char);
        }
        let norm: String = chars.chars().filter(|&c| c != '-').collect();
        let mut salt = [0u8; 8];
        OsRng.fill_bytes(&mut salt);
        let salt_hex = hex::encode(salt);
        let digest = sha256_hex(format!("{salt_hex}:{norm}").as_bytes());
        out.push((chars, format!("v1:{salt_hex}:{digest}")));
    }
    out
}

pub fn verify_recovery_code(raw_input: &str, stored_hash: &str) -> bool {
    let norm: String = raw_input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if norm.len() != 10 {
        return false;
    }
    let Some(rest) = stored_hash.strip_prefix("v1:") else {
        return false;
    };
    let Some((salt_hex, expected_hex)) = rest.split_once(':') else {
        return false;
    };
    let candidate = sha256_hex(format!("{salt_hex}:{norm}").as_bytes());
    constant_time_eq(candidate.as_bytes(), expected_hex.as_bytes())
}

// ============================================================================
// Pure-Rust ISO/IEC 18004 QR Code SVG Generator (Versions 1..=10, ECC Level L)
// Zero external crates, zero inline `style="..."` attributes (Strict CSP safe).
// ============================================================================

struct QrVersionSpec {
    version: usize,
    data_codewords: usize,
    ec_per_block: usize,
    g1_blocks: usize,
    g1_data: usize,
    g2_blocks: usize,
    g2_data: usize,
    align: &'static [usize],
}

const QR_SPECS_L: &[QrVersionSpec] = &[
    QrVersionSpec {
        version: 1,
        data_codewords: 19,
        ec_per_block: 7,
        g1_blocks: 1,
        g1_data: 19,
        g2_blocks: 0,
        g2_data: 0,
        align: &[],
    },
    QrVersionSpec {
        version: 2,
        data_codewords: 34,
        ec_per_block: 10,
        g1_blocks: 1,
        g1_data: 34,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 18],
    },
    QrVersionSpec {
        version: 3,
        data_codewords: 55,
        ec_per_block: 15,
        g1_blocks: 1,
        g1_data: 55,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 22],
    },
    QrVersionSpec {
        version: 4,
        data_codewords: 80,
        ec_per_block: 20,
        g1_blocks: 1,
        g1_data: 80,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 26],
    },
    QrVersionSpec {
        version: 5,
        data_codewords: 108,
        ec_per_block: 26,
        g1_blocks: 1,
        g1_data: 108,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 30],
    },
    QrVersionSpec {
        version: 6,
        data_codewords: 136,
        ec_per_block: 18,
        g1_blocks: 2,
        g1_data: 68,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 34],
    },
    QrVersionSpec {
        version: 7,
        data_codewords: 156,
        ec_per_block: 20,
        g1_blocks: 2,
        g1_data: 78,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 22, 38],
    },
    QrVersionSpec {
        version: 8,
        data_codewords: 194,
        ec_per_block: 24,
        g1_blocks: 2,
        g1_data: 97,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 24, 42],
    },
    QrVersionSpec {
        version: 9,
        data_codewords: 232,
        ec_per_block: 30,
        g1_blocks: 2,
        g1_data: 116,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 26, 46],
    },
    QrVersionSpec {
        version: 10,
        data_codewords: 274,
        ec_per_block: 18,
        g1_blocks: 2,
        g1_data: 68,
        g2_blocks: 2,
        g2_data: 69,
        align: &[6, 28, 50],
    },
];

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            r ^= a;
        }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    r
}

fn rs_generator(degree: usize) -> Vec<u8> {
    let mut poly = vec![1u8];
    let mut root = 1u8;
    for _ in 0..degree {
        let mut next = vec![0u8; poly.len() + 1];
        for (i, &c) in poly.iter().enumerate() {
            next[i] ^= c;
            next[i + 1] ^= gf_mul(c, root);
        }
        poly = next;
        root = gf_mul(root, 2);
    }
    poly
}

fn rs_remainder(data: &[u8], ec_len: usize) -> Vec<u8> {
    let gen = rs_generator(ec_len);
    let mut rem = vec![0u8; ec_len];
    for &b in data {
        let factor = b ^ rem[0];
        rem.copy_within(1.., 0);
        rem[ec_len - 1] = 0;
        for j in 0..ec_len {
            rem[j] ^= gf_mul(gen[j + 1], factor);
        }
    }
    rem
}

fn encode_qr_matrix(bytes: &[u8]) -> Option<Vec<Vec<bool>>> {
    let spec = QR_SPECS_L.iter().find(|s| {
        let count_bits = if s.version <= 9 { 8 } else { 16 };
        4 + count_bits + bytes.len() * 8 <= s.data_codewords * 8
    })?;

    let mut bits: Vec<bool> = Vec::with_capacity(spec.data_codewords * 8);
    let push_bits = |bits: &mut Vec<bool>, val: usize, count: usize| {
        for i in (0..count).rev() {
            bits.push(((val >> i) & 1) != 0);
        }
    };
    push_bits(&mut bits, 0b0100, 4); // Byte mode
    push_bits(
        &mut bits,
        bytes.len(),
        if spec.version <= 9 { 8 } else { 16 },
    );
    for &b in bytes {
        push_bits(&mut bits, b as usize, 8);
    }
    let cap_bits = spec.data_codewords * 8;
    let term = (cap_bits - bits.len()).min(4);
    bits.resize(bits.len() + term, false);
    while !bits.len().is_multiple_of(8) {
        bits.push(false);
    }
    let mut data_cw = Vec::with_capacity(spec.data_codewords);
    let (chunks, _) = bits.as_chunks::<8>();
    for chunk in chunks {
        let mut b = 0u8;
        for &bit in chunk {
            b = (b << 1) | (bit as u8);
        }
        data_cw.push(b);
    }
    let mut pad_toggle = false;
    while data_cw.len() < spec.data_codewords {
        data_cw.push(if pad_toggle { 0x11 } else { 0xEC });
        pad_toggle = !pad_toggle;
    }

    let mut data_blocks: Vec<&[u8]> = Vec::new();
    let mut ec_blocks: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0;
    for (count, len) in [
        (spec.g1_blocks, spec.g1_data),
        (spec.g2_blocks, spec.g2_data),
    ] {
        for _ in 0..count {
            let blk = &data_cw[offset..offset + len];
            data_blocks.push(blk);
            ec_blocks.push(rs_remainder(blk, spec.ec_per_block));
            offset += len;
        }
    }

    let mut codewords = Vec::with_capacity(
        spec.data_codewords + (spec.g1_blocks + spec.g2_blocks) * spec.ec_per_block,
    );
    let max_d = spec.g1_data.max(spec.g2_data);
    for i in 0..max_d {
        for blk in &data_blocks {
            if i < blk.len() {
                codewords.push(blk[i]);
            }
        }
    }
    for i in 0..spec.ec_per_block {
        for ec in &ec_blocks {
            codewords.push(ec[i]);
        }
    }

    let size = 17 + 4 * spec.version;
    let mut modules = vec![vec![false; size]; size];
    let mut reserved = vec![vec![false; size]; size];

    fn set_mod(
        modules: &mut [Vec<bool>],
        reserved: &mut [Vec<bool>],
        r: usize,
        c: usize,
        val: bool,
    ) {
        modules[r][c] = val;
        reserved[r][c] = true;
    }

    // Finder patterns + white separators
    for (fr, fc) in [(0usize, 0usize), (0, size - 7), (size - 7, 0)] {
        for dr in 0..7 {
            for dc in 0..7 {
                let dark = dr == 0
                    || dr == 6
                    || dc == 0
                    || dc == 6
                    || ((2..=4).contains(&dr) && (2..=4).contains(&dc));
                set_mod(&mut modules, &mut reserved, fr + dr, fc + dc, dark);
            }
        }
        let sep_r0 = fr.saturating_sub(1);
        let sep_r1 = (fr + 7).min(size - 1);
        let sep_c0 = fc.saturating_sub(1);
        let sep_c1 = (fc + 7).min(size - 1);
        for r in sep_r0..=sep_r1 {
            for c in sep_c0..=sep_c1 {
                if !reserved[r][c] {
                    set_mod(&mut modules, &mut reserved, r, c, false);
                }
            }
        }
    }

    // Alignment patterns
    for &ar in spec.align {
        for &ac in spec.align {
            if reserved[ar][ac] {
                continue;
            }
            for dr in 0..5usize {
                for dc in 0..5usize {
                    let r = ar + dr - 2;
                    let c = ac + dc - 2;
                    let dark = dr == 0 || dr == 4 || dc == 0 || dc == 4 || (dr == 2 && dc == 2);
                    set_mod(&mut modules, &mut reserved, r, c, dark);
                }
            }
        }
    }

    // Timing patterns
    for i in 8..size - 8 {
        let dark = i % 2 == 0;
        if !reserved[6][i] {
            set_mod(&mut modules, &mut reserved, 6, i, dark);
        }
        if !reserved[i][6] {
            set_mod(&mut modules, &mut reserved, i, 6, dark);
        }
    }

    // Dark module & reserve format info areas
    set_mod(&mut modules, &mut reserved, size - 8, 8, true);
    for (i, cell) in reserved[8].iter_mut().enumerate().take(9) {
        if i != 6 {
            *cell = true;
        }
    }
    for (i, row) in reserved.iter_mut().enumerate().take(9) {
        if i != 6 {
            row[8] = true;
        }
    }
    for cell in reserved[8].iter_mut().take(size).skip(size - 8) {
        *cell = true;
    }
    for row in reserved.iter_mut().take(size).skip(size - 7) {
        row[8] = true;
    }

    // Version info for versions >= 7
    if spec.version >= 7 {
        let mut vbits = spec.version << 12;
        for shift in (0..6).rev() {
            if (vbits & (1 << (shift + 12))) != 0 {
                vbits ^= 0x1F25 << shift;
            }
        }
        let vinfo = (spec.version << 12) | vbits;
        for i in 0..18 {
            let dark = ((vinfo >> i) & 1) != 0;
            let a = size - 11 + (i % 3);
            let b = i / 3;
            set_mod(&mut modules, &mut reserved, a, b, dark);
            set_mod(&mut modules, &mut reserved, b, a, dark);
        }
    }

    // Place data bits in upward/downward zigzag
    let total_bits = codewords.len() * 8;
    let mut bit_idx = 0usize;
    let mut upward = true;
    let mut col = (size - 1) as isize;
    while col >= 1 {
        if col == 6 {
            col -= 1;
        }
        for step in 0..size {
            let r = if upward { size - 1 - step } else { step };
            for c_off in [0isize, -1] {
                let c = (col + c_off) as usize;
                if !reserved[r][c] {
                    let bit = if bit_idx < total_bits {
                        let byte = codewords[bit_idx / 8];
                        ((byte >> (7 - (bit_idx % 8))) & 1) != 0
                    } else {
                        false
                    };
                    modules[r][c] = bit;
                    bit_idx += 1;
                }
            }
        }
        upward = !upward;
        col -= 2;
    }

    // Evaluate all 8 mask patterns and choose lowest penalty score
    let mut best_mask = 0usize;
    let mut best_score = usize::MAX;
    let mut best_grid = modules.clone();
    for mask in 0..8 {
        let mut grid = modules.clone();
        for r in 0..size {
            for c in 0..size {
                if reserved[r][c] {
                    continue;
                }
                let flip = match mask {
                    0 => (r + c) % 2 == 0,
                    1 => r % 2 == 0,
                    2 => c % 3 == 0,
                    3 => (r + c) % 3 == 0,
                    4 => ((r / 2) + (c / 3)) % 2 == 0,
                    5 => ((r * c) % 2) + ((r * c) % 3) == 0,
                    6 => (((r * c) % 2) + ((r * c) % 3)) % 2 == 0,
                    _ => (((r + c) % 2) + ((r * c) % 3)) % 2 == 0,
                };
                if flip {
                    grid[r][c] = !grid[r][c];
                }
            }
        }
        apply_format_info(&mut grid, size, mask);
        let pen = qr_penalty(&grid, size);
        if pen < best_score {
            best_score = pen;
            best_mask = mask;
            best_grid = grid;
        }
    }
    let _ = best_mask;
    Some(best_grid)
}

fn apply_format_info(grid: &mut [Vec<bool>], size: usize, mask: usize) {
    // ECC L = 0b01
    let data = (0b01usize << 3) | mask;
    let mut rem = data << 10;
    for shift in (0..5).rev() {
        if (rem & (1 << (shift + 10))) != 0 {
            rem ^= 0x537 << shift;
        }
    }
    let fmt = ((data << 10) | rem) ^ 0x5412;
    for i in 0..15 {
        let dark = ((fmt >> i) & 1) != 0;
        if i < 6 {
            grid[i][8] = dark;
        } else if i < 8 {
            grid[i + 1][8] = dark;
        } else {
            grid[size - 15 + i][8] = dark;
        }
        if i < 8 {
            grid[8][size - i - 1] = dark;
        } else if i < 9 {
            grid[8][15 - i] = dark;
        } else {
            grid[8][15 - i - 1] = dark;
        }
    }
}

fn qr_penalty(grid: &[Vec<bool>], size: usize) -> usize {
    let mut score = 0usize;
    let mut dark_count = 0usize;
    for row in grid.iter().take(size) {
        let mut run = 1usize;
        for (c, &cell) in row.iter().enumerate().take(size) {
            if cell {
                dark_count += 1;
            }
            if c > 0 {
                if cell == row[c - 1] {
                    run += 1;
                } else {
                    if run >= 5 {
                        score += run - 2;
                    }
                    run = 1;
                }
            }
        }
        if run >= 5 {
            score += run - 2;
        }
    }
    for c in 0..size {
        let mut run = 1usize;
        for win in grid[..size].windows(2) {
            if win[1][c] == win[0][c] {
                run += 1;
            } else {
                if run >= 5 {
                    score += run - 2;
                }
                run = 1;
            }
        }
        if run >= 5 {
            score += run - 2;
        }
    }
    for r in 0..(size - 1) {
        for c in 0..(size - 1) {
            let b = grid[r][c];
            if grid[r][c + 1] == b && grid[r + 1][c] == b && grid[r + 1][c + 1] == b {
                score += 3;
            }
        }
    }
    let pct = (dark_count * 100) / (size * size);
    score + (pct.abs_diff(50) / 5) * 10
}

/// Renders an inline CSP-safe SVG QR code (zero `style=` attributes) for TOTP provisioning URIs.
pub fn render_qr_svg(data: &str) -> String {
    let Some(grid) = encode_qr_matrix(data.as_bytes()) else {
        return String::new();
    };
    let n = grid.len();
    let quiet = 4usize;
    let total = n + quiet * 2;
    let mut path = String::with_capacity(n * n * 4);
    for (r, row) in grid.iter().enumerate() {
        for (c, &dark) in row.iter().enumerate() {
            if dark {
                let _ = write!(path, "M{},{}h1v1h-1z", c + quiet, r + quiet);
            }
        }
    }
    format!(
        "<svg class=\"qr-svg\" viewBox=\"0 0 {total} {total}\" role=\"img\" aria-label=\"TOTP QR Code\"><rect class=\"qr-bg\" width=\"{total}\" height=\"{total}\"/><path class=\"qr-fg\" d=\"{path}\"/></svg>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors_and_anti_replay() {
        // RFC 6238 Appendix B test vector seed "12345678901234567890"
        let secret = b"12345678901234567890";
        assert_eq!(totp_code_at(secret, 59), "287082");
        assert_eq!(totp_code_at(secret, 1111111109), "081804");
        assert_eq!(totp_code_at(secret, 1234567890), "005924");

        // Tolerates +-1 step & blocks replay on same or earlier step
        let now_sec = 1_700_000_010;
        let code = totp_code_at(secret, now_sec);
        let step1 = verify_totp_window(secret, &code, now_sec, None).expect("first use accepted");
        assert!(verify_totp_window(secret, &code, now_sec, Some(step1)).is_none());
        assert!(verify_totp_window(secret, &code, now_sec, Some(step1 + 1)).is_none());
        let next_code = totp_code_at(secret, now_sec + 30);
        let step2 = verify_totp_window(secret, &next_code, now_sec + 30, Some(step1))
            .expect("next step accepted");
        assert!(step2 > step1);
    }

    #[test]
    fn base32_recovery_codes_and_qr_svg_work() {
        let raw = b"HelloBugFinder!";
        let enc = encode_base32(raw);
        assert_eq!(decode_base32(&enc).unwrap(), raw);

        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), 10);
        assert_eq!(codes[0].0.len(), 11);
        assert!(verify_recovery_code(&codes[0].0, &codes[0].1));
        assert!(verify_recovery_code(
            &codes[0].0.to_ascii_lowercase().replace('-', " "),
            &codes[0].1
        ));
        assert!(!verify_recovery_code("AAAAA-BBBBB", &codes[0].1));

        let uri = build_otpauth_uri(
            "Bug-Finder",
            "owner@alpha.test",
            &generate_totp_secret_b32(),
        );
        let svg = render_qr_svg(&uri);
        assert!(svg.starts_with("<svg class=\"qr-svg\""));
        assert!(!svg.contains("style="));
        assert!(svg.contains("M4,4h1v1h-1z")); // top-left finder corner module (0,0) shifted by quiet=4
    }
}
