#![no_std]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

mod address;
mod wrappers;
mod macros;
mod module;
mod syscall;
mod utils;
mod str;

pub mod data;
pub mod hash;
pub mod parse;
pub mod breakpoint;

#[cfg(feature = "dinvk_panic")]
pub mod panic;

#[cfg(feature = "alloc")]
pub mod allocator;

pub use syscall::*;
pub use wrappers::*;
pub use address::*;
pub use module::*;
pub use utils::*;
pub use str::*;