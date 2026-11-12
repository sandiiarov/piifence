//! piifence: finds secrets in text before Claude Code sends it to the model provider.
//!
//! The secret models (`model` for cbx, `scrub` for Scrub), the key rule (`keyrule`) and gitleaks (`gitleaks`) find candidates, the guards (`guards`) drop the ones that are not secrets, and `detect` runs them together with a per-text cache (`cache`). Used by the gateway (`src/bin/gateway.rs`). `control` says where the gateway's private control socket is, for the gateway and the launcher (`src/bin/piifence.rs`). `shellfill` finds the secret names in a shell command that the shell would not expand, for the launcher's `PreToolUse` hook.

pub mod cache;
pub mod config;
pub mod control;
pub mod detect;
pub mod gitleaks;
pub mod guards;
pub mod keyrule;
pub mod model;
pub mod scrub;
pub mod shellfill;
