use std::{path::PathBuf, sync::mpsc, thread};

use age::secrecy::SecretString;
use clipboard_win::Getter as _;
use engage::{
    Archive, CancellationToken, CreateOptions, DecryptCredential, EncryptCredential, EntryId,
    EntryInfo, ExtractOptions, ExtractionConflict, KeyEntry, KeyStore, OperationProgress,
    OverwritePolicy, Selection, create_archive_with_progress,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskKind {
    Create,
    Extract,
}

pub(crate) enum ArchiveCommand {
    OpenWithKeys {
        path: PathBuf,
        store: KeyStore,
        keys: Vec<KeyEntry>,
    },
    OpenWithPassword {
        path: PathBuf,
        password: SecretString,
    },
    List {
        parent: EntryId,
        path: String,
    },
    PlanExtract {
        destination: PathBuf,
        selection: Selection,
        preserve_hierarchy: bool,
    },
    Extract {
        destination: PathBuf,
        selection: Selection,
        overwrite: bool,
        preserve_hierarchy: bool,
        cancellation: CancellationToken,
    },
    CopyToClipboard {
        destination: PathBuf,
        selection: Selection,
        clipboard_paths: Vec<PathBuf>,
        cancellation: CancellationToken,
    },
}

#[derive(Debug)]
pub(crate) enum ServiceEvent {
    ArchiveOpened(Vec<EntryInfo>),
    PasswordRequired(String),
    Listed {
        parent: EntryId,
        path: String,
        entries: Vec<EntryInfo>,
    },
    Conflicts {
        destination: PathBuf,
        selection: Selection,
        preserve_hierarchy: bool,
        conflicts: Vec<ExtractionConflict>,
    },
    Progress {
        kind: TaskKind,
        progress: OperationProgress,
    },
    Finished {
        kind: TaskKind,
        result: Result<(), String>,
    },
    ClipboardReady(Result<usize, String>),
    ClipboardProgress(OperationProgress),
    Error(String),
}

pub(crate) fn spawn_archive_service(
    events: async_channel::Sender<ServiceEvent>,
) -> mpsc::Sender<ArchiveCommand> {
    let (commands, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut archive = None;
        for command in receiver {
            match command {
                ArchiveCommand::OpenWithKeys { path, store, keys } => {
                    archive = None;
                    let mut last_error = "没有可用的本地私钥".to_owned();
                    for key in keys {
                        match store.load_identity(&key).and_then(|identity| {
                            Archive::open(&path, DecryptCredential::PostQuantum(identity), 32 << 20)
                        }) {
                            Ok(mut opened) => match list_all(&mut opened, 0) {
                                Ok(entries) => {
                                    archive = Some(opened);
                                    send(&events, ServiceEvent::ArchiveOpened(entries));
                                    break;
                                }
                                Err(error) => last_error = format!("{error:#?}"),
                            },
                            Err(error) => last_error = format!("{error:#?}"),
                        }
                    }
                    if archive.is_none() {
                        send(&events, ServiceEvent::PasswordRequired(last_error));
                    }
                }
                ArchiveCommand::OpenWithPassword { path, password } => {
                    match Archive::open(&path, DecryptCredential::Passphrase(password), 32 << 20)
                        .and_then(|mut opened| {
                            let entries = list_all(&mut opened, 0)?;
                            Ok((opened, entries))
                        }) {
                        Ok((opened, entries)) => {
                            archive = Some(opened);
                            send(&events, ServiceEvent::ArchiveOpened(entries));
                        }
                        Err(error) => send(
                            &events,
                            ServiceEvent::PasswordRequired(format!("{error:#?}")),
                        ),
                    }
                }
                ArchiveCommand::List { parent, path } => {
                    if let Some(opened) = archive.as_mut() {
                        match list_all(opened, parent) {
                            Ok(entries) => send(
                                &events,
                                ServiceEvent::Listed {
                                    parent,
                                    path,
                                    entries,
                                },
                            ),
                            Err(error) => send(&events, ServiceEvent::Error(format!("{error:#?}"))),
                        }
                    }
                }
                ArchiveCommand::PlanExtract {
                    destination,
                    selection,
                    preserve_hierarchy,
                } => {
                    if let Some(opened) = archive.as_mut() {
                        let options = ExtractOptions {
                            preserve_hierarchy,
                            ..ExtractOptions::default()
                        };
                        match opened.plan_extraction_with_options(
                            &destination,
                            selection.clone(),
                            &options,
                        ) {
                            Ok(conflicts) => send(
                                &events,
                                ServiceEvent::Conflicts {
                                    destination,
                                    selection,
                                    preserve_hierarchy,
                                    conflicts,
                                },
                            ),
                            Err(error) => send(&events, ServiceEvent::Error(format!("{error:#?}"))),
                        }
                    }
                }
                ArchiveCommand::Extract {
                    destination,
                    selection,
                    overwrite,
                    preserve_hierarchy,
                    cancellation,
                } => {
                    if let Some(opened) = archive.as_mut() {
                        let progress_events = events.clone();
                        let mut reporter = move |progress| {
                            let _ = progress_events.try_send(ServiceEvent::Progress {
                                kind: TaskKind::Extract,
                                progress,
                            });
                        };
                        let result = opened
                            .extract_with_progress(
                                destination,
                                selection,
                                ExtractOptions {
                                    overwrite: if overwrite {
                                        OverwritePolicy::ReplaceFiles
                                    } else {
                                        OverwritePolicy::Refuse
                                    },
                                    preserve_hierarchy,
                                },
                                &cancellation,
                                &mut reporter,
                            )
                            .map_err(|error| format!("{error:#?}"));
                        send(
                            &events,
                            ServiceEvent::Finished {
                                kind: TaskKind::Extract,
                                result,
                            },
                        );
                    }
                }
                ArchiveCommand::CopyToClipboard {
                    destination,
                    selection,
                    clipboard_paths,
                    cancellation,
                } => {
                    let result = archive.as_mut().map_or_else(
                        || Err("归档尚未打开".to_owned()),
                        |opened| {
                            let progress_events = events.clone();
                            let mut reporter = move |progress| {
                                let _ = progress_events
                                    .try_send(ServiceEvent::ClipboardProgress(progress));
                            };
                            opened
                                .extract_with_progress(
                                    destination,
                                    selection,
                                    ExtractOptions {
                                        overwrite: OverwritePolicy::Refuse,
                                        preserve_hierarchy: false,
                                    },
                                    &cancellation,
                                    &mut reporter,
                                )
                                .map_err(|error| format!("{error:#?}"))?;
                            if cancellation.is_cancelled() {
                                return Err("operation cancelled".to_owned());
                            }
                            if clipboard_paths.iter().any(|path| !path.exists()) {
                                return Err("复制暂存文件不完整".to_owned());
                            }
                            let paths = clipboard_paths
                                .iter()
                                .map(|path| path.to_string_lossy().into_owned())
                                .collect::<Vec<_>>();
                            write_file_clipboard(&paths)?;
                            Ok(paths.len())
                        },
                    );
                    send(&events, ServiceEvent::ClipboardReady(result));
                }
            }
        }
    });
    commands
}

pub(crate) struct CreateRequest {
    pub inputs: Vec<PathBuf>,
    pub destination: PathBuf,
    pub credential: EncryptCredential,
    pub overwrite: bool,
    pub cancellation: CancellationToken,
}

pub(crate) fn spawn_create(request: CreateRequest, events: async_channel::Sender<ServiceEvent>) {
    thread::spawn(move || {
        let progress_events = events.clone();
        let mut reporter = move |progress| {
            let _ = progress_events.try_send(ServiceEvent::Progress {
                kind: TaskKind::Create,
                progress,
            });
        };
        let result = create_archive_with_progress(
            request.inputs,
            request.destination,
            &request.credential,
            CreateOptions::default(),
            request.overwrite,
            &request.cancellation,
            &mut reporter,
        )
        .map_err(|error| format!("{error:#?}"));
        send(
            &events,
            ServiceEvent::Finished {
                kind: TaskKind::Create,
                result,
            },
        );
    });
}

fn send(events: &async_channel::Sender<ServiceEvent>, event: ServiceEvent) {
    let _ = events.send_blocking(event);
}

fn list_all(archive: &mut Archive, parent: EntryId) -> engage::Result<Vec<EntryInfo>> {
    let mut cursor = None;
    let mut entries = Vec::new();
    loop {
        let page = archive.list_children(parent, cursor, 1024)?;
        entries.extend(page.entries);
        cursor = page.next;
        if cursor.is_none() {
            return Ok(entries);
        }
    }
}

const PREFERRED_DROP_EFFECT: &str = "Preferred DropEffect";
const DROP_EFFECT_COPY: u32 = 1;

fn write_file_clipboard(paths: &[String]) -> Result<(), String> {
    let effect_format = clipboard_win::register_format(PREFERRED_DROP_EFFECT)
        .ok_or_else(|| "注册 Preferred DropEffect 剪贴板格式失败".to_owned())?;
    let _clipboard = clipboard_win::Clipboard::new_attempts(20)
        .map_err(|error| format!("打开文件剪贴板失败：{error}"))?;

    clipboard_win::raw::set_file_list_with(paths, clipboard_win::options::DoClear)
        .map_err(|error| format!("写入 CF_HDROP 文件列表失败：{error}"))?;

    let effect = DROP_EFFECT_COPY.to_le_bytes();
    if let Err(error) = clipboard_win::raw::set_without_clear(effect_format.get(), &effect) {
        let _ = clipboard_win::empty();
        return Err(format!("写入 Preferred DropEffect 失败：{error}"));
    }

    let verification = verify_file_clipboard(paths, effect_format.get());
    if verification.is_err() {
        let _ = clipboard_win::empty();
    }
    verification
}

fn verify_file_clipboard(paths: &[String], effect_format: u32) -> Result<(), String> {
    let mut written_paths = Vec::new();
    clipboard_win::formats::FileList
        .read_clipboard(&mut written_paths)
        .map_err(|error| format!("验证 CF_HDROP 文件列表失败：{error}"))?;
    if written_paths != paths {
        return Err("验证 CF_HDROP 文件列表失败：写入内容不一致".to_owned());
    }

    let mut written_effect = Vec::new();
    clipboard_win::formats::RawData(effect_format)
        .read_clipboard(&mut written_effect)
        .map_err(|error| format!("验证 Preferred DropEffect 失败：{error}"))?;
    if written_effect.get(..4) != Some(DROP_EFFECT_COPY.to_le_bytes().as_slice()) {
        return Err("验证 Preferred DropEffect 失败：复制标志不正确".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::write_file_clipboard;

    #[test]
    #[ignore = "modifies the Windows system clipboard"]
    fn explorer_file_clipboard_formats_round_trip() {
        let staging = tempfile::tempdir().unwrap();
        let file = staging.path().join("clipboard 测试.txt");
        fs::write(&file, b"clipboard test").unwrap();
        let paths = vec![file.to_string_lossy().into_owned()];

        write_file_clipboard(&paths).unwrap();
    }
}
