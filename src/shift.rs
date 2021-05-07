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

#[test]
fn test_shift_rows () {
    let mut a: [u8; 16] = [
        0, 1, 2, 3, 4, 5, 6, 7, 
        8, 9, 10, 11, 12, 13, 14, 15];
    shift_rows(&mut a);
    assert_eq!(a, [
        0, 1, 2, 3, 5, 6, 7, 4, 
        10, 11, 8, 9, 15, 12, 13, 14]);
    inverse_shift_rows(&mut a);
    assert_eq!(a, [
        0, 1, 2, 3, 4, 5, 6, 7, 
        8, 9, 10, 11, 12, 13, 14, 15]);
}

pub fn shift_rows (
    array_in: &mut [u8; 16],
) {

    let mut tmp: u8;

    tmp = array_in[4];
    array_in[4] = array_in[5];
    array_in[5] = array_in[6];
    array_in[6] = array_in[7];
    array_in[7] = tmp;

    tmp = array_in[8];
    array_in[8] = array_in[10];
    array_in[10] = tmp;
    tmp = array_in[9];
    array_in[9] = array_in[11];
    array_in[11] = tmp;

    tmp = array_in[12];
    array_in[12] = array_in[15];
    array_in[15] = array_in[14];
    array_in[14] = array_in[13];
    array_in[13] = tmp;
}

pub fn inverse_shift_rows (
    array_in: &mut [u8; 16],
) {

    let mut tmp: u8;

    tmp = array_in[4];
    array_in[4] = array_in[7];
    array_in[7] = array_in[6];
    array_in[6] = array_in[5];
    array_in[5] = tmp;

    tmp = array_in[8];
    array_in[8] = array_in[10];
    array_in[10] = tmp;
    tmp = array_in[9];
    array_in[9] = array_in[11];
    array_in[11] = tmp;

    tmp = array_in[12];
    array_in[12] = array_in[13];
    array_in[13] = array_in[14];
    array_in[14] = array_in[15];
    array_in[15] = tmp;
}

