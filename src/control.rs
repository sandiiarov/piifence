//! The gateway's control socket: a Unix socket in a directory only the user can open.
//!
//! The gateway serves its proxy on `127.0.0.1:<port>`, which every account on the machine can connect to. So `/stats`, every `/control/` path and the `/health` answer that names the upstream are served only on `<state dir>/run/<port>.sock`. The gateway creates `run/` with mode 0700; the launcher, its hooks and the notice plugin connect there.

use std::path::{Path, PathBuf};

use anyhow::Context;

/// `$PIIF_STATE_DIR`, or `~/.local/state/piifence` when that is unset.
pub fn state_dir() -> anyhow::Result<PathBuf> {
    if let Ok(dir) = std::env::var("PIIF_STATE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/state/piifence"))
}

/// The control socket of the gateway on `port`: `run/<port>.sock` in `state_dir`.
pub fn socket_path(state_dir: &Path, port: u16) -> PathBuf {
    state_dir.join("run").join(format!("{port}.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_socket_for_a_port_is_in_the_run_directory_of_the_state_dir() {
        assert_eq!(
            socket_path(Path::new("/state"), 7788),
            Path::new("/state/run/7788.sock")
        );
    }
}
