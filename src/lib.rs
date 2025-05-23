#![no_std]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case, non_camel_case_types)]
#![allow(
    clippy::too_many_arguments,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::missing_transmute_annotations,
    clippy::missing_safety_doc,
    clippy::macro_metavars_in_unsafe
)]

// Allow usage of `alloc` crate for heap-allocated types.
extern crate alloc;

// Internal modules
mod functions;
mod macros;
mod module;
mod syscall;
mod utils;
mod str;

/// Structures and types used across the library.
pub mod data;

/// Runtime hash functions.
pub mod hash;

/// PE Parsing
pub mod parse;

/// Hardware breakpoint management utilities (only for x86/x86_64 targets).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod breakpoint;

/// Custom panic handler support (requires `dinvk_panic` feature).
#[cfg(feature = "dinvk_panic")]
pub mod panic;

/// Heap allocator using Windows native APIs (requires `alloc` feature).
#[cfg(feature = "alloc")]
pub mod allocator;

// Re-exports for easier usage
pub use syscall::*;
pub use functions::*;
pub use module::*;
pub use module::ldr::*;
pub use utils::*;
pub use str::*;