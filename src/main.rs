use clap::{arg, Command};
use std::fs;
extern crate hex;

const MAX_LEN:usize = 18446744073709551615;

/*
 * From https://datatracker.ietf.org/doc/html/rfc1321#section-3.4
 * 
 * 64-element table T[1 ... 64] constructed from the
 * sine function. Let T[i] denote the i-th element of the table, which
 * is equal to the integer part of 4294967296 times abs(sin(i)), where i
 * is in radians.
 */
const K: [u32; 64] = [
    // floor(232 × abs(sin(i + 1))) for i := 0 -> 63
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/**
 * From https://datatracker.ietf.org/doc/html/rfc1321#section-3.3
 * 
 * A four-word buffer (A,B,C,D) is used to compute the message digest.
 * Here each of A, B, C, D is a 32-bit register. These registers are
 * initialized to the following values in hexadecimal, low-order bytes
 * first):
 * 
 *   word A: 01 23 45 67
 *   word B: 89 ab cd ef
 *   word C: fe dc ba 98
 *   word D: 76 54 32 10
 * 
 * Note: These are converted to little-endian literals
 */
const A_INIT: u32 = 0x67452301;
const B_INIT: u32 = 0xefcdab89;
const C_INIT: u32 = 0x98badcfe;
const D_INIT: u32 = 0x10325476;

// Rotation table
const SHIFT: [u32; 64] = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
];

/*
 * Four 32-bit words maintaining the state of the digest during hashing.
 */
struct State {
    a: u32,
    b: u32,
    c: u32,
    d: u32
}

impl Default for State {

    /**
     * Default constructor; initializes each of the State fields 
     * to the initial values from 3.3
     */
    fn default () -> State {
        State {
            a: A_INIT,
            b: B_INIT,
            c: C_INIT,
            d: D_INIT
        }
    }
}

impl State {

    /**
     * Rotates the state values according to https://datatracker.ietf.org/doc/html/rfc1321#section-3.4
     */
    fn rotate (&mut self, f: u32) {
       self.a = self.d;
       self.d = self.c;
       self.c = self.b;
       self.b = self.b.wrapping_add(f);
    }
}

/** 
 * From https://datatracker.ietf.org/doc/html/rfc1321#section-3.1
 *
 * The message is "padded" (extended) so that its length (in bits) is
 * congruent to 448, modulo 512. That is, the message is extended so
 * that it is just 64 bits shy of being a multiple of 512 bits long.
 * Padding is always performed, even if the length of the message is
 * already congruent to 448, modulo 512.

 * Padding is performed as follows: a single "1" bit is appended to the
 * message, and then "0" bits are appended so that the length in bits of
 * the padded message becomes congruent to 448, modulo 512. In all, at
 * least one bit and at most 512 bits are appended.
 */
fn
pad (message: &mut Vec<u8>) {
    // Get message length in bits; length times 8 since message is in bytes
    let mlen_in_bits = message.len() * 8 % MAX_LEN;

    // Appends 1 << 7, ie 1000 0000, we're working in bytes
    message.push(0x80);

    // Padding to 448 modulo 512 bits
    while (message.len() * 8 % MAX_LEN) % 512 != 448 {
        message.push(0x0);
    }

    /* 
    * From https://datatracker.ietf.org/doc/html/rfc1321#section-3.2
    *
    * A 64-bit representation of b (the length of the message before the
    * padding bits were added) is appended to the result of the previous
    * step. In the unlikely event that b is greater than 2^64, then only
    * the low-order 64 bits of b are used. (These bits are appended as two
    * 32-bit words and appended low-order word first in accordance with the
    * previous conventions.)
     
    * At this point the resulting message (after padding with bits and with
    * b) has a length that is an exact multiple of 512 bits. Equivalently,
    * this message has a length that is an exact multiple of 16 (32-bit)
    * words. Let M[0 ... N-1] denote the words of the resulting message,
    * where N is a multiple of 16.
    */
    let len_in_bytes = mlen_in_bits.to_le_bytes();
    message.extend_from_slice(&len_in_bytes);
}

fn
hash (message: &str) -> String {

    let mut state:State = Default::default();
    let mut message_bytes = message.as_bytes().to_vec();

    // Pad the input message according to specification, so that its length mod 512 == 0
    pad(&mut message_bytes);

    // 512-bit chunks
    for chunk in message_bytes.chunks(64) {

        let a0 = state.a;
        let b0 = state.b;
        let c0 = state.c;
        let d0 = state.d;

        let mut m: [u32; 16] = [0; 16];
        let mut indx = 0;

        // Fill M array with 32-bit words from the outer 512-bit chunk
        for int_chunk in chunk.chunks(4) {
            let (b1, b2, b3, b4) = (int_chunk[0] as u32, int_chunk[1] as u32, int_chunk[2] as u32, int_chunk[3] as u32);
            m[indx] = (b4 << 24) | (b3 << 16) | (b2 << 8) | b1;
            indx += 1;
        }

        indx = 0;
        let mut f:u32;

        /*
         * 64 iterations; 16 rounds each of the following four rounds from 
         * https://datatracker.ietf.org/doc/html/rfc1321#section-3.4
         * 
         *  F(X,Y,Z) = XY v not(X) Z
         *  G(X,Y,Z) = XZ v Y not(Z)
         *  H(X,Y,Z) = X xor Y xor Z
         *  I(X,Y,Z) = Y xor (X v not(Z))
         */
        while indx < 16 {
            f = (state.d ^ (state.b & (state.c ^ state.d)))
                .wrapping_add(state.a)
                .wrapping_add(K[indx])
                .wrapping_add(m[indx])
                .rotate_left(SHIFT[indx]);

            state.rotate(f);
            indx += 1;
        }

        while indx < 32 {
            f = (state.c ^ (state.d & (state.b ^ state.c)))
                .wrapping_add(state.a)
                .wrapping_add(K[indx])
                .wrapping_add(m[(indx * 5 + 1) % 16])
                .rotate_left(SHIFT[indx]);

            state.rotate(f);
            indx += 1;
        }

        while indx < 48 {
            f = (state.b ^ state.c ^ state.d)
                .wrapping_add(state.a)
                .wrapping_add(K[indx])
                .wrapping_add(m[(indx * 3 + 5) % 16])
                .rotate_left(SHIFT[indx]);

            state.rotate(f);
            indx += 1;
        }

        while indx < 64 {
            f = (state.c ^ (state.b | (!state.d)))
                .wrapping_add(state.a)
                .wrapping_add(K[indx])
                .wrapping_add(m[(indx * 7) % 16])
                .rotate_left(SHIFT[indx]);

            state.rotate(f);
            indx += 1;
        }

        state.a = state.a.wrapping_add(a0);
        state.b = state.b.wrapping_add(b0);
        state.c = state.c.wrapping_add(c0);
        state.d = state.d.wrapping_add(d0);
    }

    /*
     * From https://datatracker.ietf.org/doc/html/rfc1321#section-3.5:
     * 
     * The message digest produced as output is A, B, C, D. That is, we
     * begin with the low-order byte of A, and end with the high-order byte
     * of D.
     * 
     * This section converts each u32 into 4 u8s, collecting all of the u8s into a Vec
     */
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&state.a.to_le_bytes());
    bytes.extend_from_slice(&state.b.to_le_bytes());
    bytes.extend_from_slice(&state.c.to_le_bytes());
    bytes.extend_from_slice(&state.d.to_le_bytes());

    let digest: [u8; 16] = bytes.try_into().expect("Wrong length");

    // Encode into base 64
    return hex::encode(&digest); 
}

fn 
tests () {
    assert!(hash("").eq("d41d8cd98f00b204e9800998ecf8427e"));
    assert!(hash("abcde").eq("ab56b4d92b40713acc5af89985d4b786"));
    assert!(hash("abcdefghijklmnopqrstuvwxyz123456789012345678901234567890").eq("68b7c41b350d85fe015fc2602f128c4c"));

    println!("tests completed successfully!");
}

fn 
main () {
    let matches = Command::new("md5")
    .version("0.1")
    .about("Fun with cryptographic hash functions")
    .arg(arg!(--path <VALUE>).required(false))
    .arg(arg!(--string <VALUE>).required(false))
    .arg(arg!(--test).required(false))
    .get_matches();

    let string = matches.get_one::<String>("string");
    let path = matches.get_one::<String>("path");
    let test = matches.get_one::<bool>("test");

    match (string, path, test) {
        (Some(text), None, Some(false)) => {
            let digest = hash(&text);
            println!("{}", digest);
        },
        (None, Some(f), Some(false)) => {
            let contents = fs::read_to_string(f)
                .expect("Should have been able to read the file");
            let digest = hash(&contents);
            println!("{}", digest);
        },
        (None, None, Some(true)) => {
            tests();
        }
        _ => {
            println!("no text provided!");
        }
    }
}
