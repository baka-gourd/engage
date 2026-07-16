# engage

Seekable encrypted archives built from tar, seekable zstd, and age, with a native Windows GUI.

The implementation provides:

- `engage.exe`: a GPUI + gpui-component Windows GUI with an integrated title bar, system/light/dark
  themes, native drag-and-drop, lazy archive browsing, partial extraction, multi-file/multi-folder
  creation, live progress, and local key management.
- `engage-cli.exe`: the command-line interface.
- A Rust library supporting passphrase or hybrid PQ credentials, lazy directory listing,
  cancellation, extraction conflict preflight, and safe partial extraction.

Private keys managed by the GUI are stored as `<name>.agekey` under the current user's `.engage`
directory. Opening an archive tries all valid local keys before asking for a password. Passing a
`.engage` path to `engage.exe` opens it directly.

See [the container format](docs/format.md).

Development checks:

```text
cargo check
cargo lint
cargo test --all-targets
cargo build --release --bins
```

Windows installer:

```powershell
.\scripts\build-installer.ps1
```

The Inno Setup package installs both `engage.exe` and `engage-cli.exe` for the current user and
associates `.engage` files with the GUI. The installer preserves the previous per-user association;
uninstall restores it when Engage is still the active handler. The resulting setup executable is
written to `dist`.
