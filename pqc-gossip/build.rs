// build.rs — cargo-component generates bindings automatically.
// This file exists to satisfy cargo's build script discovery.
// cargo-component handles WIT binding generation via its own toolchain hook.
fn main() {
    // Tell cargo to re-run if the WIT file changes.
    println!("cargo:rerun-if-changed=wit/gossip-protocol.wit");
}
