//! piifence shared detection library: model + gitleaks pre-pass + wrapper guards.
//!
//! Used by the M1 harness (`src/main.rs`) and the gateway spike (`src/bin/gateway.rs`).

pub mod config;
pub mod detect;
pub mod gitleaks;
pub mod guards;
