use std::env;
use std::process::exit;
use std::convert::TryInto;

// ---------- Adapted from https://github.com/RustCrypto/hashes/blob/master/md5/src/compress.rs ----------
const RC: [u32; 64] = [0x3bcb2ec4, 0x97dc7dad, 0x7fbf88d8, 0x577f129e, 0x91d9bb31, 0x47933969, 0xc4525dba, 0xaf883dec, 0xd16cc010, 0x4b3a21ca, 0x9733fcb8, 0xa64a2af5, 0x29ed3c63, 0x70ae1ee0, 0x727bc379, 0x4dae395b, 0x90edeca5, 0xadc8c656, 0xe0c0abfd, 0x22caf51b, 0x9ee61754, 0x18c535c3, 0x865aa9f3, 0x8eb2728d, 0x6c828dc8, 0xe9f0bb6c, 0x9d52d37f, 0x60541226, 0x75d8eb96, 0x6ea16787, 0xae4dfffa, 0xdb3b14e4, 0x337e4d32, 0x957bcab2, 0xe24ebc08, 0x3065d239, 0x06e5af54, 0x5cce65ea, 0xcea4cd09, 0x9c305131, 0x7fe792d6, 0x17d2b95f, 0x50e63ca3, 0x1429a203, 0x9edfe0eb, 0x2b8176d5, 0x3654265e, 0x013205a9, 0x04c3c75d, 0x7d5c4787, 0xc3cd9ad8, 0xd6635932, 0x1ca719d8, 0x305f8997, 0x4111b65a, 0xe6893e3e, 0x3e11613b, 0x52e763dc, 0xf8bdcac8, 0xb9d772ff, 0x68f629d8, 0xa1578c9c, 0xb1d75427, 0x53d1a3b2];

#[inline(always)]
fn op_f(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    ((x & y) | (!x & z))
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}
#[inline(always)]
fn op_g(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    ((x & z) | (y & !z))
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}

#[inline(always)]
fn op_h(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    (x ^ y ^ z)
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}

#[inline(always)]
fn op_i(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    (y ^ (x | !z))
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}

#[inline]
pub fn compress_block(state: &mut [u32; 4], input: &[u8; 64]) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    let mut data = [0u32; 16];
    for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
        *o = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // round 1
    a = op_f(a, b, c, d, data[0], RC[0], 7);
    d = op_f(d, a, b, c, data[1], RC[1], 12);
    c = op_f(c, d, a, b, data[2], RC[2], 17);
    b = op_f(b, c, d, a, data[3], RC[3], 22);

    a = op_f(a, b, c, d, data[4], RC[4], 7);
    d = op_f(d, a, b, c, data[5], RC[5], 12);
    c = op_f(c, d, a, b, data[6], RC[6], 17);
    b = op_f(b, c, d, a, data[7], RC[7], 22);

    a = op_f(a, b, c, d, data[8], RC[8], 7);
    d = op_f(d, a, b, c, data[9], RC[9], 12);
    c = op_f(c, d, a, b, data[10], RC[10], 17);
    b = op_f(b, c, d, a, data[11], RC[11], 22);

    a = op_f(a, b, c, d, data[12], RC[12], 7);
    d = op_f(d, a, b, c, data[13], RC[13], 12);
    c = op_f(c, d, a, b, data[14], RC[14], 17);
    b = op_f(b, c, d, a, data[15], RC[15], 22);

    // round 2
    a = op_g(a, b, c, d, data[1], RC[16], 5);
    d = op_g(d, a, b, c, data[6], RC[17], 9);
    c = op_g(c, d, a, b, data[11], RC[18], 14);
    b = op_g(b, c, d, a, data[0], RC[19], 20);

    a = op_g(a, b, c, d, data[5], RC[20], 5);
    d = op_g(d, a, b, c, data[10], RC[21], 9);
    c = op_g(c, d, a, b, data[15], RC[22], 14);
    b = op_g(b, c, d, a, data[4], RC[23], 20);

    a = op_g(a, b, c, d, data[9], RC[24], 5);
    d = op_g(d, a, b, c, data[14], RC[25], 9);
    c = op_g(c, d, a, b, data[3], RC[26], 14);
    b = op_g(b, c, d, a, data[8], RC[27], 20);

    a = op_g(a, b, c, d, data[13], RC[28], 5);
    d = op_g(d, a, b, c, data[2], RC[29], 9);
    c = op_g(c, d, a, b, data[7], RC[30], 14);
    b = op_g(b, c, d, a, data[12], RC[31], 20);

    // round 3
    a = op_h(a, b, c, d, data[5], RC[32], 4);
    d = op_h(d, a, b, c, data[8], RC[33], 11);
    c = op_h(c, d, a, b, data[11], RC[34], 16);
    b = op_h(b, c, d, a, data[14], RC[35], 23);

    a = op_h(a, b, c, d, data[1], RC[36], 4);
    d = op_h(d, a, b, c, data[4], RC[37], 11);
    c = op_h(c, d, a, b, data[7], RC[38], 16);
    b = op_h(b, c, d, a, data[10], RC[39], 23);

    a = op_h(a, b, c, d, data[13], RC[40], 4);
    d = op_h(d, a, b, c, data[0], RC[41], 11);
    c = op_h(c, d, a, b, data[3], RC[42], 16);
    b = op_h(b, c, d, a, data[6], RC[43], 23);

    a = op_h(a, b, c, d, data[9], RC[44], 4);
    d = op_h(d, a, b, c, data[12], RC[45], 11);
    c = op_h(c, d, a, b, data[15], RC[46], 16);
    b = op_h(b, c, d, a, data[2], RC[47], 23);

    // round 4
    a = op_i(a, b, c, d, data[0], RC[48], 6);
    d = op_i(d, a, b, c, data[7], RC[49], 10);
    c = op_i(c, d, a, b, data[14], RC[50], 15);
    b = op_i(b, c, d, a, data[5], RC[51], 21);

    a = op_i(a, b, c, d, data[12], RC[52], 6);
    d = op_i(d, a, b, c, data[3], RC[53], 10);
    c = op_i(c, d, a, b, data[10], RC[54], 15);
    b = op_i(b, c, d, a, data[1], RC[55], 21);

    a = op_i(a, b, c, d, data[8], RC[56], 6);
    d = op_i(d, a, b, c, data[15], RC[57], 10);
    c = op_i(c, d, a, b, data[6], RC[58], 15);
    b = op_i(b, c, d, a, data[13], RC[59], 21);

    a = op_i(a, b, c, d, data[4], RC[60], 6);
    d = op_i(d, a, b, c, data[11], RC[61], 10);
    c = op_i(c, d, a, b, data[2], RC[62], 15);
    b = op_i(b, c, d, a, data[9], RC[63], 21);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[inline]
pub fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block)
    }
}
// ------------------------------------------------------------

fn check(a: u8, b: u8, expected: u32) -> bool {
    let mut state: [u32; 4] = [0x81de3ff4, 0x7e5f221f, 0x3be4d5bf, 0xb484dcdc];
    let blocks: [[u8; 64]; 1] = [[b, a, a, b, b, a, a, a, b, a, b, a, a, b, a, a, b, a, b, b, b, a, a, a, b, b, a, a, b, a, a, a, b, a, b, a, a, b, b, b, a, b, b, a, a, b, a, b, b, b, a, a, a, b, a, b, b, a, b, b, a, a, b, b]];
    for _ in 0..(a*b) {
        compress(&mut state, &blocks);
    }
    let r = state[0] ^ state[1] ^ state[2] ^ state[3];
    return r == expected;
}

const EXP: [u32; 13] = [3684424461, 266244018, 3392641979, 2896963000, 1179637477, 1381517329, 3799892737, 1441041400, 194527636, 2990190055, 463283761, 4256548044, 2748753331];

fn main() {
    let args: Vec<String> = env::args().collect();
    let flag = args.get(1);
    if flag.is_none() {
        println!("Usage: {prog} <FLAG>", prog=args.get(0).unwrap());
    }
    let flag = flag.unwrap().as_bytes();
    if flag.len() != 26 {
        println!("No :<");
        exit(-1);
    }
    for i in 0..13 {
        let a = flag.get(i).unwrap();
        let b = flag.get(26-i-1).unwrap();
        if !check(*a, *b, EXP[i]) {
            println!("No :<");
            exit(-1);
        }
    }
    println!("Yes :>");
}
