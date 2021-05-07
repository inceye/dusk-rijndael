// Copyright (C) 2021 by Andy Gozas <andy@gozas.me>
//
// This file is part of Dusk's Rijndael cipher plugin.
//
// Dusk's Rijndael cipher plugin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Dusk's Rijndael cipher plugin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Dusk's Rijndael cipher plugin.  If not, see <https://www.gnu.org/licenses/>.

use crate::*;

// Galois powers of 2 for each byte
const RCON: [u8; 256] = [
    141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154,
    47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57,
    114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58,
    116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216,
    171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239,
    197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204,
    131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27,
    54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179,
    125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148,
    51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32,
    64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53,
    106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159,
    37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4,
    8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99,
    198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189,
    97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141];

fn key_expansion_core (
    array_in: &mut [u8; 4], 
    iteration: usize,
) {

    let tmp: u8 = array_in[0];
    array_in[0] = array_in[1];
    array_in[1] = array_in[2];
    array_in[2] = array_in[3];
    array_in[3] = tmp;

    substitute(array_in);

    array_in[0] = array_in[0] ^ RCON[iteration];
}

pub fn key_expansion (
    key: &[u8], 
    new_len: usize,
) -> Vec<u8> {

    let mut result: Vec<u8> = Vec::new();
    for byte in key {
        result.push(*byte);
    }
    let key_len: usize = key.len();
    let mut len_now: usize = key_len;

    let mut rcon_iteration: usize = 1;
    
    let mut tail: [u8; 4] = [0, 0, 0, 0];

    while len_now < new_len {
        for byte_n in 0..4 {
            tail[byte_n] = result[len_now - 4 + byte_n];
        }
        if len_now % key_len == 0 {
            key_expansion_core(&mut tail, rcon_iteration);
            rcon_iteration += 1;
        } else if ((key_len >= 32) &&
            (len_now % key_len % 16 == 0) && 
            (key_len - (len_now % key_len) >= 16)) {

            substitute(&mut tail);
        }
        for byte in &tail {
            result.push(result[len_now - key_len] ^ byte);
            len_now += 1;
        }
    }
    return result;
}
