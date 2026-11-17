//! The extended checker binary: the core DeG CLI plus the NexusTK adapter's
//! compiled-in evidence kinds and the `generate` lane.

use std::process::ExitCode;

fn main() -> ExitCode {
    deg_nexustk::register();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = deg_nexustk::generate::run(&argv) {
        return code;
    }
    deg::cli::run()
}
