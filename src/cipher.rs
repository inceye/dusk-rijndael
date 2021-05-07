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

fn add_key (
    array_in: &mut [u8; 16], 
    key: [u8; 16],
) {

    for element_number in 0..16 {
        array_in[element_number] = 
            array_in[element_number] ^ key[element_number];
    }
}

#[test]
fn test_row_column_convert () {
    let mut a: [u8; 16] = [
        0, 1, 2, 3, 4, 5, 6, 7, 
        8, 9, 10, 11, 12, 13, 14, 15];
    row_column_convert(&mut a);
    assert_eq!(a, [
        0, 4, 8, 12, 1, 5, 9, 13, 
        2, 6, 10, 14, 3, 7, 11, 15]);
    row_column_convert(&mut a);
    assert_eq!(a, [
        0, 1, 2, 3, 4, 5, 6, 7, 
        8, 9, 10, 11, 12, 13, 14, 15]);
}

fn row_column_convert (
    block: &mut [u8; 16]
) {

    let mut tmp: u8 = block[1];
    block[1] = block[4];
    block[4] = tmp;

    tmp = block[2];
    block[2] = block[8];
    block[8] = tmp;

    tmp = block[3];
    block[3] = block[12];
    block[12] = tmp;

    tmp = block[6];
    block[6] = block[9];
    block[9] = tmp;

    tmp = block[7];
    block[7] = block[13];
    block[13] = tmp;

    tmp = block[11];
    block[11] = block[14];
    block[14] = tmp;
}

#[test]
fn test_encrypt_decrypt_128 () {
    let to_be_enced: [u8; 16] = [
        0x01, 0x4B, 0xAF, 0x22, 0x78, 0xA6, 0x9D, 0x33, 
        0x1D, 0x51, 0x80, 0x10, 0x36, 0x43, 0xE9, 0x9A];
    let mut enced: [u8; 16] = to_be_enced.clone();
    let key: [u8; 16] = [
        0xE8, 0xE9, 0xEA, 0xEB, 0xED, 0xEE, 0xEF, 0xF0, 
        0xF2, 0xF3, 0xF4, 0xF5, 0xF7, 0xF8, 0xF9, 0xFA];
    let exp_key: Vec<u8> = key_expansion(&key, 176);

    encrypt(&mut enced, &exp_key);

    let enced_test: [u8; 16] = [
        0x67, 0x43, 0xC3, 0xD1, 0x51, 0x9A, 0xB4, 0xF2, 
        0xCD, 0x9A, 0x78, 0xAB, 0x09, 0xA5, 0x11, 0xBD];
    assert_eq!(enced, enced_test);

    decrypt(&mut enced, &exp_key);
    assert_eq!(enced, to_be_enced);
}

#[test]
fn test_encrypt_decrypt_196 () {
    let to_be_enced: [u8; 16] = [
        0x76, 0x77, 0x74, 0x75, 0xF1, 0xF2, 0xF3, 0xF4, 
        0xF8, 0xF9, 0xE6, 0xE7, 0x77, 0x70, 0x71, 0x72];
    let mut enced: [u8; 16] = to_be_enced.clone();
    let key: [u8; 24] = [
        0x04, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x0C, 
        0x0E, 0x0F, 0x10, 0x11, 0x13, 0x14, 0x15, 0x16, 
        0x18, 0x19, 0x1A, 0x1B, 0x1D, 0x1E, 0x1F, 0x20];
    let exp_key: Vec<u8> = key_expansion(&key, 208);

    encrypt(&mut enced, &exp_key);

    let enced_test: [u8; 16] = [
        0x5d, 0x1e, 0xf2, 0x0d, 0xce, 0xd6, 0xbc, 0xbc, 
        0x12, 0x13, 0x1a, 0xc7, 0xc5, 0x47, 0x88, 0xaa];
    assert_eq!(enced, enced_test);

    decrypt(&mut enced, &exp_key);
    assert_eq!(enced, to_be_enced);
}

#[test]
fn test_encrypt_decrypt_256 () {
    let to_be_enced: [u8; 16] = [
        0x06, 0x9A, 0x00, 0x7F, 0xC7, 0x6A, 0x45, 0x9F, 
        0x98, 0xBA, 0xF9, 0x17, 0xFE, 0xDF, 0x95, 0x21];
    let mut enced: [u8; 16] = to_be_enced.clone();
    let key: [u8; 32] = [
        0x08, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x0F, 0x10, 
        0x12, 0x13, 0x14, 0x15, 0x17, 0x18, 0x19, 0x1A, 
        0x1C, 0x1D, 0x1E, 0x1F, 0x21, 0x22, 0x23, 0x24, 
        0x26, 0x27, 0x28, 0x29, 0x2B, 0x2C, 0x2D, 0x2E];
    let exp_key: Vec<u8> = key_expansion(&key, 240);

    encrypt(&mut enced, &exp_key);

    let enced_test: [u8; 16] = [
        0x08, 0x0e, 0x95, 0x17, 0xeb, 0x16, 0x77, 0x71, 
        0x9a, 0xcf, 0x72, 0x80, 0x86, 0x04, 0x0a, 0xe3];
    assert_eq!(enced, enced_test);

    decrypt(&mut enced, &exp_key);
    assert_eq!(enced, to_be_enced);
}

pub fn encrypt (
    block: &mut [u8; 16],
    key: &Vec<u8>,
) {

    row_column_convert(block);

    let mut round_key: [u8; 16] = [0; 16];
    let key_clone: Vec<u8> = key.clone();

    round_key.clone_from_slice(&key_clone[0..16]);
    row_column_convert(&mut round_key);

    add_key(block, round_key);

    for iteration in 1..((key.len() / 16) - 1) {
        round_key.clone_from_slice(
            &key_clone[(iteration * 16)..((iteration + 1) * 16)]);
        row_column_convert(&mut round_key);

        substitute(block);
        shift_rows(block);
        mix_columns(block);
        add_key(block, round_key);
    }
    
    let iteration: usize = key.len() / 16 - 1;
    round_key.clone_from_slice(
        &key_clone[(iteration * 16)..((iteration + 1) * 16)]);
    row_column_convert(&mut round_key);

    substitute(block);
    shift_rows(block);
    add_key(block, round_key);

    row_column_convert(block);
}

pub fn decrypt (
    block: &mut [u8; 16],
    key: &Vec<u8>,
) {

    row_column_convert(block);

    let mut round_key: [u8; 16] = [0; 16];
    let key_clone: Vec<u8> = key.clone();

    let iteration: usize = key.len() / 16 - 1;

    round_key.clone_from_slice(
        &key_clone[(iteration * 16)..((iteration + 1) * 16)]);
    row_column_convert(&mut round_key);

    add_key(block, round_key);
    inverse_shift_rows(block);
    inverse_substitute(block);

    for iteration in (1..((key.len() / 16) - 1)).rev() {
        round_key.clone_from_slice(
            &key_clone[(iteration * 16)..((iteration + 1) * 16)]);
        row_column_convert(&mut round_key);

        add_key(block, round_key);
        inverse_mix_columns(block);
        inverse_shift_rows(block);
        inverse_substitute(block);
    }

    round_key.clone_from_slice(&key_clone[0..16]);
    row_column_convert(&mut round_key);

    add_key(block, round_key);

    row_column_convert(block);
}
