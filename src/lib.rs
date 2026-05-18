//! Boab library surface.
//!
//! Boab is a standalone command-line tool for assessing post-quantum
//! cryptography readiness against the ASD LATICE framework. The library
//! exposes the same code paths that the `boab` binary calls into.

#![deny(rust_2018_idioms)]

pub mod cli;
pub mod config;
pub mod dedup;
pub mod model;
pub mod plan;
pub mod report;
pub mod scanners;
pub mod scoring;
pub mod storage;
pub mod vendor;
pub mod workspace;

mod runner;

pub use runner::run;

/// Exit code for a CLI command that is not yet implemented.
pub const EXIT_NOT_IMPLEMENTED: i32 = 64;
/// Exit code for "workspace not initialised".
pub const EXIT_NO_WORKSPACE: i32 = 3;
/// Exit code for a scanner failure.
pub const EXIT_SCANNER: i32 = 4;
/// Exit code for a report failure.
pub const EXIT_REPORT: i32 = 5;
