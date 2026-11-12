//! piifence: finds secrets in text before Claude Code sends it to the model provider.
//!
//! The secret models (`model` for cbx, `scrub` for Scrub), the key rule (`keyrule`) and gitleaks (`gitleaks`) find candidates, the guards (`guards`) drop the ones that are not secrets, and `detect` runs them together with a per-text cache (`cache`). Used by the gateway (`src/bin/gateway.rs`).

pub mod cache;
pub mod config;
pub mod detect;
pub mod gitleaks;
pub mod guards;
pub mod keyrule;
pub mod model;
pub mod scrub;
