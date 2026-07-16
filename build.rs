fn main() {
    println!("cargo:rerun-if-changed=assets/windows/engage.rc");
    println!("cargo:rerun-if-changed=assets/windows/engage.ico");

    #[cfg(windows)]
    embed_resource::compile("assets/windows/engage.rc", embed_resource::NONE)
        .manifest_required()
        .expect("failed to compile Windows resources");
}
