// Dusk's plugin, that implements Rijndael Cipher (aka AES)
//
// Copyright (C) 2021 by Andy Gozas <andy@gozas.me>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//#![deny(warnings)]

#![allow(unused_parens)]

#![warn(unreachable_pub)]
#![warn(unused_crate_dependencies)]
#![warn(unused_extern_crates)] 
#![warn(missing_copy_implementations)] 
#![warn(missing_debug_implementations)] 
#![warn(variant_size_differences)] 
#![warn(keyword_idents)]
#![warn(anonymous_parameters)]

#![warn(missing_abi)]

#![warn(meta_variable_misuse)]
#![warn(semicolon_in_expressions_from_macros)]
#![warn(absolute_paths_not_starting_with_crate)]

#![warn(missing_crate_level_docs)]
#![warn(missing_docs)]
#![warn(missing_doc_code_examples)]

#![warn(elided_lifetimes_in_paths)]
#![warn(explicit_outlives_requirements)]
#![warn(invalid_html_tags)]
#![warn(non_ascii_idents)]
#![warn(pointer_structural_match)]
#![warn(private_doc_tests)]
#![warn(single_use_lifetimes)]
#![warn(unaligned_references)]

extern crate dusk_api;

pub mod substitution;
pub mod mix;
pub mod shift;
pub mod keygen;
pub mod cipher;

use substitution::*;
use mix::*;
use shift::*;
pub use keygen::*;
pub use cipher::*;
