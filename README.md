# Engage

可部分解压，后量子时代安全的、易用的、高速的、兼容的文件打包格式。主要用于归档和高保密要求的文件传输。

当然，我不是密码学专家，不过我愿意相信别人。

Seekable encrypted archives built from tar, seekable zstd, and age, with a native Windows GUI.

The implementation provides:

- `engage.exe`: Windows GUI
- `engage-cli.exe`: the command-line interface.

Private keys managed by the GUI are stored as `<name>.agekey` under the current user's `.engage` directory. Opening an archive tries all valid local keys before asking for a password. Passing a `.engage` path to `engage.exe` opens it directly.

See [the container format](docs/format.md).

Archive creation selects up to five compression workers automatically. The CLI accepts
`create --threads N` to override the number of zstd workers; `--threads 1` uses the serial encoder.

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
