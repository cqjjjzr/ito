//! Embeds `ito-tray.manifest` and `ito.ico` into Windows builds; other targets get nothing.

fn main() {
    embed_resource::compile("ito-tray.rc", embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}
