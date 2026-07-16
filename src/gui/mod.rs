#![allow(clippy::too_many_lines)]

mod archive_table;
mod preferences;
mod service;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::mpsc,
};

use age::secrecy::SecretString;
use engage::{
    CancellationToken, ConflictKind, EncryptCredential, EntryId, EntryInfo, EntryKind, KeyEntry,
    KeyState, KeyStore, OperationProgress, OperationStage, PublicKeyEntry, Selection,
};
use gpui::{
    App, AppContext as _, Application, Bounds, Context, Corner, Entity, ExternalPaths,
    InteractiveElement as _, IntoElement, KeyBinding, MouseButton, ParentElement as _,
    PathPromptOptions, Pixels, Render, StatefulInteractiveElement as _, Styled as _, Window,
    WindowBounds, WindowOptions, div, prelude::FluentBuilder as _, px, relative, rems, size,
};
use gpui_component::{
    ActiveTheme as _, Disableable as _, Icon, IconName, Root, Selectable as _, Theme, ThemeMode,
    TitleBar, WindowExt as _,
    button::{Button, ButtonVariants as _},
    checkbox::Checkbox,
    input::{Input, InputEvent, InputState},
    list::ListItem,
    notification::Notification,
    popover::Popover,
    progress::Progress,
    radio::RadioGroup,
    scroll::ScrollableElement as _,
    skeleton::Skeleton,
    spinner::Spinner,
    table::{Table, TableState},
    tree::{TreeItem, TreeState, tree},
};
use gpui_component_assets::Assets;

gpui::actions!(engage, [CopyArchiveSelection]);

use self::{
    archive_table::{ArchiveTableDelegate, CreateTableDelegate},
    preferences::{Preferences, ThemePreference},
    service::{ArchiveCommand, CreateRequest, ServiceEvent, TaskKind},
};

#[derive(Debug)]
pub(crate) enum UiEvent {
    ToggleEntry(EntryId),
    NavigateDirectory(EntryId),
    NavigateParent,
    SetPreserveHierarchy(bool),
    RemoveInput(usize),
    ToggleAllVisible,
    ToggleRecipient(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Home,
    Decrypt,
    Create,
}

#[derive(Debug, Clone, Copy)]
enum UnlockAttempt {
    AutomaticKeys,
    RetriedKeys,
    Password,
}

struct ActiveTask {
    kind: TaskKind,
    progress: Option<OperationProgress>,
    cancellation: CancellationToken,
}

struct ClipboardTask {
    cancellation: CancellationToken,
    progress: Option<OperationProgress>,
}

struct PendingExtract {
    destination: PathBuf,
    selection: Selection,
    preserve_hierarchy: bool,
}

pub(crate) struct MainView {
    page: Page,
    settings_open: bool,
    preferences: Preferences,
    key_store: Option<KeyStore>,
    keys: Vec<KeyEntry>,
    public_keys: Vec<PublicKeyEntry>,
    selected_key: usize,
    selected_public_key: usize,
    selected_recipients: HashSet<String>,
    archive_tx: mpsc::Sender<ArchiveCommand>,
    event_tx: async_channel::Sender<ServiceEvent>,
    archive_path: Option<PathBuf>,
    unlock_attempts: VecDeque<UnlockAttempt>,
    entries: Vec<EntryInfo>,
    loaded_directories: HashMap<EntryId, Vec<EntryInfo>>,
    directory_paths: HashMap<EntryId, String>,
    directory_parents: HashMap<EntryId, EntryId>,
    expanded_directories: HashSet<EntryId>,
    tree_state: Entity<TreeState>,
    table_state: Entity<TableState<ArchiveTableDelegate>>,
    create_table_state: Entity<TableState<CreateTableDelegate>>,
    ui_events: async_channel::Sender<UiEvent>,
    current_parent: EntryId,
    current_path: String,
    history: Vec<(EntryId, String)>,
    checked: HashSet<EntryId>,
    preserve_hierarchy: bool,
    clipboard_staging: Option<tempfile::TempDir>,
    clipboard_task: Option<ClipboardTask>,
    create_inputs: Vec<PathBuf>,
    password_mode: bool,
    active_task: Option<ActiveTask>,
    pending_extract: Option<PendingExtract>,
    password_required: bool,
    create_password_visible: bool,
    archive_password_visible: bool,
    status: String,
    decrypt_output: Entity<InputState>,
    create_output: Entity<InputState>,
    password: Entity<InputState>,
    password_confirm: Entity<InputState>,
    archive_password: Entity<InputState>,
    _archive_password_subscription: gpui::Subscription,
    key_name: Entity<InputState>,
    last_layout: Option<(Pixels, Pixels)>,
}

impl MainView {
    fn new(initial_path: Option<PathBuf>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let decrypt_output = cx.new(|cx| InputState::new(window, cx).placeholder("选择解压目录"));
        let create_output =
            cx.new(|cx| InputState::new(window, cx).placeholder("输出 .engage 文件的绝对路径"));
        let password = cx.new(|cx| InputState::new(window, cx).masked(true));
        let password_confirm = cx.new(|cx| InputState::new(window, cx).masked(true));
        let archive_password = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("此归档的密码")
                .masked(true)
        });
        let archive_password_subscription =
            cx.subscribe(&archive_password, |_, _, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    cx.notify();
                }
            });
        let key_name = cx.new(|cx| InputState::new(window, cx).placeholder("密钥显示名称"));

        let (event_tx, event_rx) = async_channel::bounded(128);
        let (ui_tx, ui_rx) = async_channel::unbounded();
        let archive_tx = service::spawn_archive_service(event_tx.clone());
        let key_store = KeyStore::for_current_user().ok();
        let keys = scan_keys(key_store.as_ref());
        let public_keys = scan_public_keys(key_store.as_ref());
        let selected_recipients = first_valid_recipient(&keys, &public_keys)
            .into_iter()
            .collect();
        let tree_state = cx.new(|cx| TreeState::new(cx));
        let rem_size = window.rem_size();
        let table_state = cx.new(|cx| {
            TableState::new(
                ArchiveTableDelegate::new(ui_tx.clone(), rem_size),
                window,
                cx,
            )
        });
        let create_table_state = cx.new(|cx| {
            TableState::new(
                CreateTableDelegate::new(ui_tx.clone(), rem_size),
                window,
                cx,
            )
        });
        let preferences = Preferences::load();

        cx.spawn_in(window, async move |view, window| {
            while let Ok(event) = event_rx.recv().await {
                if view
                    .update_in(window, |this, window, cx| {
                        this.handle_service_event(event, window, cx);
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();

        cx.spawn(async move |view, cx| {
            while let Ok(event) = ui_rx.recv().await {
                if view
                    .update(cx, |this, cx| {
                        this.handle_ui_event(event, cx);
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();

        let mut this = Self {
            page: Page::Home,
            settings_open: false,
            preferences,
            key_store,
            keys,
            public_keys,
            selected_key: 0,
            selected_public_key: 0,
            selected_recipients,
            archive_tx,
            event_tx,
            archive_path: None,
            unlock_attempts: VecDeque::new(),
            entries: Vec::new(),
            loaded_directories: HashMap::new(),
            directory_paths: HashMap::from([(0, String::new())]),
            directory_parents: HashMap::new(),
            expanded_directories: HashSet::from([0]),
            tree_state,
            table_state,
            create_table_state,
            ui_events: ui_tx,
            current_parent: 0,
            current_path: String::new(),
            history: Vec::new(),
            checked: HashSet::new(),
            preserve_hierarchy: true,
            clipboard_staging: None,
            clipboard_task: None,
            create_inputs: Vec::new(),
            password_mode: false,
            active_task: None,
            pending_extract: None,
            password_required: false,
            create_password_visible: false,
            archive_password_visible: false,
            status: "就绪".into(),
            decrypt_output,
            create_output,
            password,
            password_confirm,
            archive_password,
            _archive_password_subscription: archive_password_subscription,
            key_name,
            last_layout: None,
        };
        this.apply_theme(window, cx);
        if let Some(path) = initial_path.filter(|path| is_engage(path)) {
            this.open_archive(path, window, cx);
        }
        this
    }

    fn apply_theme(&self, window: &mut Window, cx: &mut App) {
        match self.preferences.theme {
            ThemePreference::System => Theme::sync_system_appearance(Some(window), cx),
            ThemePreference::Light => Theme::change(ThemeMode::Light, Some(window), cx),
            ThemePreference::Dark => Theme::change(ThemeMode::Dark, Some(window), cx),
        }
    }

    fn open_archive(&mut self, path: PathBuf, window: &mut Window, cx: &mut Context<Self>) {
        let path = absolute_path(path);
        self.archive_path = Some(path.clone());
        self.unlock_attempts.clear();
        self.page = Page::Decrypt;
        self.password_required = false;
        self.archive_password_visible = false;
        self.archive_password.update(cx, |state, cx| {
            state.set_value("", window, cx);
            state.set_masked(true, window, cx);
        });
        self.entries.clear();
        self.loaded_directories.clear();
        self.directory_paths.clear();
        self.directory_paths.insert(0, String::new());
        self.directory_parents.clear();
        self.expanded_directories.clear();
        self.expanded_directories.insert(0);
        self.checked.clear();
        self.history.clear();
        self.current_parent = 0;
        self.current_path.clear();
        self.status = "正在尝试当前用户的私钥…".into();
        let output = windows_display_path(&path.with_extension(""));
        self.decrypt_output.update(cx, |state, cx| {
            state.set_value(output, window, cx);
        });
        let keys = self
            .keys
            .iter()
            .filter(|entry| matches!(entry.state, KeyState::Valid { .. }))
            .cloned()
            .collect();
        if let Some(store) = self.key_store.clone() {
            if self
                .archive_tx
                .send(ArchiveCommand::OpenWithKeys { path, store, keys })
                .is_ok()
            {
                self.unlock_attempts.push_back(UnlockAttempt::AutomaticKeys);
            }
        } else {
            self.password_required = true;
            self.status = "密钥目录不可用，请输入密码".into();
        }
    }

    fn add_inputs(&mut self, paths: Vec<PathBuf>, window: &mut Window, cx: &mut Context<Self>) {
        for path in paths {
            let path = absolute_path(path);
            if !self.create_inputs.contains(&path) {
                self.create_inputs.push(path);
            }
        }
        if let Some(default) = default_output_path(&self.create_inputs) {
            self.create_output.update(cx, |state, cx| {
                state.set_value(windows_display_path(&default), window, cx);
            });
        }
        self.sync_create_table(cx);
        self.page = Page::Create;
        self.status = format!("已添加 {} 项", self.create_inputs.len());
    }

    fn handle_drop(&mut self, paths: &ExternalPaths, window: &mut Window, cx: &mut Context<Self>) {
        if self.clipboard_task.is_some() {
            self.status = "正在准备复制内容，请稍候".into();
            return;
        }
        let paths = paths.paths().to_vec();
        if paths.len() == 1 && is_engage(&paths[0]) {
            self.open_archive(paths[0].clone(), window, cx);
        } else if !paths.is_empty() {
            self.add_inputs(paths, window, cx);
        }
    }

    fn handle_service_event(&mut self, event: ServiceEvent, window: &mut Window, cx: &mut App) {
        match event {
            ServiceEvent::ArchiveOpened(entries) => {
                self.unlock_attempts.pop_front();
                self.current_parent = 0;
                self.current_path.clear();
                self.entries = entries.clone();
                self.loaded_directories.insert(0, entries);
                self.index_directory_paths(0);
                self.sync_archive_views(cx);
                self.password_required = false;
                self.status = "归档已打开，可勾选部分内容解压".into();
            }
            ServiceEvent::PasswordRequired(reason) => {
                match self.unlock_attempts.pop_front() {
                    Some(UnlockAttempt::RetriedKeys) => window
                        .push_notification(Notification::error("重新检查后仍未找到可用的私钥"), cx),
                    Some(UnlockAttempt::Password) => {
                        window.push_notification(Notification::error("密码错误，请重试"), cx);
                    }
                    Some(UnlockAttempt::AutomaticKeys) | None => {}
                }
                self.password_required = true;
                self.status = format!("本地私钥无法解密，请输入归档密码：{reason}");
            }
            ServiceEvent::Listed {
                parent,
                path,
                entries,
            } => {
                self.current_parent = parent;
                self.current_path = path.clone();
                self.entries = entries.clone();
                self.directory_paths.insert(parent, path);
                self.loaded_directories.insert(parent, entries);
                self.index_directory_paths(parent);
                self.sync_archive_views(cx);
                self.status = "目录已载入".into();
            }
            ServiceEvent::Conflicts {
                destination,
                selection,
                preserve_hierarchy,
                conflicts,
            } => {
                if conflicts.iter().any(|c| c.kind == ConflictKind::Blocked) {
                    self.status = "目标中存在无法覆盖的项目，请更换输出目录".into();
                } else if conflicts.is_empty() {
                    self.begin_extract(destination, selection, preserve_hierarchy, false);
                } else {
                    self.pending_extract = Some(PendingExtract {
                        destination,
                        selection,
                        preserve_hierarchy,
                    });
                    self.status = format!("目标中有 {} 项冲突", conflicts.len());
                }
            }
            ServiceEvent::Progress { kind, progress } => {
                if let Some(task) = self.active_task.as_mut()
                    && task.kind == kind
                    && !task.cancellation.is_cancelled()
                {
                    task.progress = Some(progress);
                }
            }
            ServiceEvent::Finished { kind, result } => {
                if self
                    .active_task
                    .as_ref()
                    .is_some_and(|task| task.kind == kind)
                {
                    self.active_task = None;
                }
                self.status = match result {
                    Ok(()) if kind == TaskKind::Create => "加密归档已生成".into(),
                    Ok(()) => "解压完成".into(),
                    Err(error) if error.contains("cancelled") => "任务已取消".into(),
                    Err(error) => format!("任务失败：{error}"),
                };
            }
            ServiceEvent::ClipboardReady(result) => {
                self.clipboard_task = None;
                if result.is_err() {
                    self.clipboard_staging = None;
                }
                self.status = match result {
                    Ok(count) => format!("已复制 {count} 项，可在资源管理器中粘贴"),
                    Err(error) if error.contains("cancelled") => "复制已取消".into(),
                    Err(error) => format!("复制失败：{error}"),
                };
            }
            ServiceEvent::ClipboardProgress(progress) => {
                if let Some(task) = self.clipboard_task.as_mut()
                    && !task.cancellation.is_cancelled()
                {
                    task.progress = Some(progress);
                }
            }
            ServiceEvent::Error(error) => self.status = format!("操作失败：{error}"),
        }
    }

    fn handle_ui_event(&mut self, event: UiEvent, cx: &mut App) {
        if self.clipboard_task.is_some() {
            return;
        }
        match event {
            UiEvent::ToggleEntry(id) => {
                if !self.checked.insert(id) {
                    self.checked.remove(&id);
                }
                self.sync_table(cx);
            }
            UiEvent::NavigateDirectory(id) => self.navigate_directory(id, cx),
            UiEvent::NavigateParent => self.navigate_parent(cx),
            UiEvent::SetPreserveHierarchy(value) => self.preserve_hierarchy = value,
            UiEvent::RemoveInput(index) => {
                if index < self.create_inputs.len() {
                    self.create_inputs.remove(index);
                    self.sync_create_table(cx);
                }
            }
            UiEvent::ToggleAllVisible => {
                let all_selected = !self.entries.is_empty()
                    && self
                        .entries
                        .iter()
                        .all(|entry| self.checked.contains(&entry.id));
                if all_selected {
                    for entry in &self.entries {
                        self.checked.remove(&entry.id);
                    }
                } else {
                    self.checked
                        .extend(self.entries.iter().map(|entry| entry.id));
                }
                self.sync_table(cx);
            }
            UiEvent::ToggleRecipient(recipient) => {
                if !self.selected_recipients.insert(recipient.clone()) {
                    self.selected_recipients.remove(&recipient);
                }
            }
        }
    }

    fn copy_archive_selection(&mut self, cx: &mut App) {
        if self.clipboard_task.is_some() {
            self.status = "正在准备复制内容，请稍候".into();
            return;
        }
        let ids = if self.checked.is_empty() {
            let Some(row) = self.table_state.read(cx).selected_row() else {
                self.status = "请先选择要复制的文件或文件夹".into();
                return;
            };
            let Some(entry) = row.checked_sub(1).and_then(|index| self.entries.get(index)) else {
                self.status = "不能复制上一级目录项".into();
                return;
            };
            vec![entry.id]
        } else {
            self.checked.iter().copied().collect::<Vec<_>>()
        };

        let mut names = HashMap::new();
        for entries in self.loaded_directories.values() {
            for entry in entries {
                names.insert(entry.id, entry.name.clone());
            }
        }
        let selected_names = ids
            .iter()
            .map(|id| names.get(id).cloned())
            .collect::<Option<Vec<_>>>();
        let Some(selected_names) = selected_names else {
            self.status = "无法定位部分选中项目".into();
            return;
        };
        let unique_names = selected_names.iter().collect::<HashSet<_>>();
        if unique_names.len() != selected_names.len() {
            self.status = "选中项目包含同名项，无法复制到同一个临时目录".into();
            return;
        }

        let staging = match tempfile::Builder::new().prefix("engage-copy-").tempdir() {
            Ok(staging) => staging,
            Err(error) => {
                self.status = format!("创建复制临时目录失败：{error}");
                return;
            }
        };
        let destination = staging.path().to_path_buf();
        let clipboard_paths = selected_names
            .iter()
            .map(|name| destination.join(name))
            .collect();
        self.clipboard_staging = Some(staging);
        let cancellation = CancellationToken::new();
        self.clipboard_task = Some(ClipboardTask {
            cancellation: cancellation.clone(),
            progress: None,
        });
        if self
            .archive_tx
            .send(ArchiveCommand::CopyToClipboard {
                destination,
                selection: Selection::EntryIds(ids),
                clipboard_paths,
                cancellation,
            })
            .is_err()
        {
            self.clipboard_staging = None;
            self.clipboard_task = None;
            self.status = "归档服务已停止".into();
            return;
        }
        self.status = "正在准备复制内容…".into();
    }

    fn navigate_directory(&mut self, id: EntryId, cx: &mut App) {
        self.remember_tree_expansion(id, cx);
        let Some(path) = self.directory_paths.get(&id).cloned() else {
            return;
        };
        if self.current_parent != id {
            self.history
                .push((self.current_parent, self.current_path.clone()));
        }
        self.current_parent = id;
        self.current_path = path.clone();
        if let Some(entries) = self.loaded_directories.get(&id).cloned() {
            self.entries = entries;
            self.sync_table(cx);
            self.status = "目录已载入".into();
        } else {
            self.entries.clear();
            self.sync_table(cx);
            self.status = "正在载入目录…".into();
            let _ = self
                .archive_tx
                .send(ArchiveCommand::List { parent: id, path });
        }
    }

    fn navigate_parent(&mut self, cx: &mut App) {
        let Some(parent) = self.directory_parents.get(&self.current_parent).copied() else {
            self.status = "已经位于归档根目录".into();
            return;
        };
        self.navigate_directory(parent, cx);
    }

    fn remember_tree_expansion(&mut self, id: EntryId, cx: &App) {
        let Some(entry) = self.tree_state.read(cx).selected_entry() else {
            return;
        };
        let item = entry.item();
        let selected_id = item
            .id
            .strip_prefix("directory:")
            .and_then(|value| value.parse::<EntryId>().ok());
        if selected_id != Some(id) {
            return;
        }
        if item.is_expanded() {
            self.expanded_directories.insert(id);
        } else {
            self.expanded_directories.remove(&id);
        }
    }

    fn index_directory_paths(&mut self, parent: EntryId) {
        let parent_path = self
            .directory_paths
            .get(&parent)
            .cloned()
            .unwrap_or_default();
        if let Some(entries) = self.loaded_directories.get(&parent) {
            for entry in entries {
                if entry.kind == EntryKind::Directory {
                    self.directory_paths
                        .insert(entry.id, join_archive_path(&parent_path, &entry.name));
                    self.directory_parents.insert(entry.id, parent);
                }
            }
        }
    }

    fn sync_archive_views(&self, cx: &mut App) {
        self.sync_table(cx);
        let items = vec![self.directory_tree_item(0, "归档根目录")];
        self.tree_state
            .update(cx, |state, cx| state.set_items(items, cx));
    }

    fn sync_table(&self, cx: &mut App) {
        self.table_state.update(cx, |state, cx| {
            let delegate = state.delegate_mut();
            delegate.entries = self.entries.clone();
            delegate.checked.clone_from(&self.checked);
            delegate.current_path.clone_from(&self.current_path);
            state.refresh(cx);
        });
    }

    fn sync_create_table(&self, cx: &mut App) {
        self.create_table_state.update(cx, |state, cx| {
            state.delegate_mut().paths.clone_from(&self.create_inputs);
            state.refresh(cx);
        });
    }

    fn directory_tree_item(&self, id: EntryId, label: &str) -> TreeItem {
        let mut item = TreeItem::new(format!("directory:{id}"), label.to_owned());
        if let Some(entries) = self.loaded_directories.get(&id) {
            let children = entries
                .iter()
                .filter(|entry| entry.kind == EntryKind::Directory)
                .map(|entry| self.directory_tree_item(entry.id, &entry.name))
                .collect::<Vec<_>>();
            item = item
                .children(children)
                .expanded(self.expanded_directories.contains(&id));
        } else {
            item = item
                .child(TreeItem::new(format!("loading:{id}"), "正在载入…").disabled(true))
                .expanded(self.expanded_directories.contains(&id));
        }
        item
    }

    fn begin_extract(
        &mut self,
        destination: PathBuf,
        selection: Selection,
        preserve_hierarchy: bool,
        overwrite: bool,
    ) {
        if self.active_task.is_some() {
            self.status = "当前窗口已有任务；可另开一个 engage 窗口".into();
            return;
        }
        let cancellation = CancellationToken::new();
        self.active_task = Some(ActiveTask {
            kind: TaskKind::Extract,
            progress: None,
            cancellation: cancellation.clone(),
        });
        let _ = self.archive_tx.send(ArchiveCommand::Extract {
            destination,
            selection,
            overwrite,
            preserve_hierarchy,
            cancellation,
        });
    }

    fn start_create(&mut self, cx: &mut App) {
        if self.active_task.is_some() || self.create_inputs.is_empty() {
            self.status = if self.create_inputs.is_empty() {
                "请先添加文件或文件夹".into()
            } else {
                "当前窗口已有任务；可另开一个 engage 窗口".into()
            };
            return;
        }
        let destination = PathBuf::from(self.create_output.read(cx).value().as_ref());
        if destination.as_os_str().is_empty() {
            self.status = "请设置输出文件".into();
            return;
        }
        let credential = if self.password_mode {
            let password = self.password.read(cx).value().to_string();
            if password.is_empty() || password != self.password_confirm.read(cx).value().as_ref() {
                self.status = "密码为空或两次输入不一致".into();
                return;
            }
            EncryptCredential::Passphrase(SecretString::from(password))
        } else {
            if self.selected_recipients.is_empty() {
                self.status = "请至少选择一个加密接收者".into();
                return;
            }
            let recipients = match self
                .selected_recipients
                .iter()
                .map(|recipient| engage::HybridRecipient::parse(recipient))
                .collect::<engage::Result<Vec<_>>>()
            {
                Ok(recipients) => recipients,
                Err(error) => {
                    self.status = format!("读取公钥失败：{error}");
                    return;
                }
            };
            EncryptCredential::PostQuantumRecipients(recipients)
        };
        let cancellation = CancellationToken::new();
        self.active_task = Some(ActiveTask {
            kind: TaskKind::Create,
            progress: None,
            cancellation: cancellation.clone(),
        });
        service::spawn_create(
            CreateRequest {
                inputs: self.create_inputs.clone(),
                destination: destination.clone(),
                credential,
                overwrite: destination.exists(),
                cancellation,
            },
            self.event_tx.clone(),
        );
        self.status = "正在创建归档…".into();
    }

    fn select_paths(
        &mut self,
        directories: bool,
        multiple: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: !directories,
            directories,
            multiple,
            prompt: Some(if directories {
                "选择文件夹".into()
            } else {
                "选择文件".into()
            }),
        });
        cx.spawn_in(window, async move |view, window| {
            if let Ok(Ok(Some(paths))) = receiver.await {
                let _ = view.update_in(window, |this, window, cx| {
                    if !directories && !multiple && paths.len() == 1 && is_engage(&paths[0]) {
                        this.open_archive(paths[0].clone(), window, cx);
                    } else {
                        this.add_inputs(paths, window, cx);
                    }
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn select_archive(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let directory = self
            .archive_path
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let dialog = rfd::AsyncFileDialog::new()
            .set_title("打开 Engage 归档")
            .set_directory(directory)
            .add_filter("Engage 归档 (*.engage)", &["engage"]);
        self.status = "正在打开归档选择器…".into();
        cx.notify();
        cx.spawn_in(window, async move |view, window| {
            let selected = dialog
                .pick_file()
                .await
                .map(|file| file.path().to_path_buf());
            if let Some(path) = selected {
                let _ = view.update_in(window, |this, window, cx| {
                    if is_engage(&path) {
                        this.open_archive(path, window, cx);
                    } else {
                        this.status = "只能打开扩展名为 .engage 的归档".into();
                    }
                    cx.notify();
                });
            } else {
                let _ = view.update_in(window, |this, _, cx| {
                    this.status = "已取消打开归档".into();
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn select_decrypt_output(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("选择解压目标文件夹".into()),
        });
        cx.spawn_in(window, async move |view, window| {
            if let Ok(Ok(Some(paths))) = receiver.await
                && let Some(path) = paths.into_iter().next()
            {
                let _ = view.update_in(window, |this, window, cx| {
                    this.decrypt_output.update(cx, |state, cx| {
                        state.set_value(windows_display_path(&path), window, cx);
                    });
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn select_create_output(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let current = PathBuf::from(self.create_output.read(cx).value().as_ref());
        let directory = current
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let suggested_name = current
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("archive.engage")
            .to_owned();
        let receiver = cx.prompt_for_new_path(&directory, Some(&suggested_name));
        cx.spawn_in(window, async move |view, window| {
            if let Ok(Ok(Some(mut path))) = receiver.await {
                if !is_engage(&path) {
                    path.set_extension("engage");
                }
                let _ = view.update_in(window, |this, window, cx| {
                    this.create_output.update(cx, |state, cx| {
                        state.set_value(windows_display_path(&path), window, cx);
                    });
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn generate_key(&mut self, _window: &mut Window, cx: &mut App) {
        let name = self.key_name.read(cx).value().to_string();
        let Some(store) = self.key_store.as_ref() else {
            self.status = "密钥目录不可用".into();
            return;
        };
        match store.generate(&name) {
            Ok(_) => {
                self.keys = scan_keys(self.key_store.as_ref());
                self.selected_key = self.keys.len().saturating_sub(1);
                self.refresh_recipient_selection();
                self.status = format!("已生成私钥 {name}");
            }
            Err(error) => self.status = format!("生成私钥失败：{error}"),
        }
    }

    fn delete_selected_key(&mut self, _window: &mut Window, _cx: &mut App) {
        let Some(store) = self.key_store.as_ref() else {
            return;
        };
        let Some(entry) = self.keys.get(self.selected_key).cloned() else {
            return;
        };
        match store.delete(&entry) {
            Ok(()) => {
                self.keys = scan_keys(self.key_store.as_ref());
                self.selected_key = self.selected_key.min(self.keys.len().saturating_sub(1));
                self.refresh_recipient_selection();
                self.status = format!("已删除私钥 {}", entry.name);
            }
            Err(error) => self.status = format!("删除私钥失败：{error}"),
        }
    }

    fn export_selected_public_key(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(store) = self.key_store.clone() else {
            self.status = "密钥目录不可用".into();
            return;
        };
        let Some(entry) = self.keys.get(self.selected_key).cloned() else {
            self.status = "请先选择一个私钥".into();
            return;
        };
        let suggested_name = format!("{}.agepub", entry.name);
        let receiver = cx.prompt_for_new_path(store.root(), Some(&suggested_name));
        cx.spawn_in(window, async move |view, window| {
            if let Ok(Ok(Some(mut destination))) = receiver.await {
                if destination.extension().is_none() {
                    destination.set_extension("agepub");
                }
                let result = store.export_public(&entry, &destination);
                let _ = view.update_in(window, |this, _, cx| {
                    this.status = match result {
                        Ok(()) => format!("已导出公钥到 {}", windows_display_path(&destination)),
                        Err(error) => format!("导出公钥失败：{error}"),
                    };
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn import_public_keys(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(store) = self.key_store.clone() else {
            self.status = "密钥目录不可用".into();
            return;
        };
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: Some("导入 PQ 公钥".into()),
        });
        cx.spawn_in(window, async move |view, window| {
            if let Ok(Ok(Some(paths))) = receiver.await {
                let total = paths.len();
                let mut imported = 0usize;
                let mut failures = Vec::new();
                for path in paths {
                    match store.import_public(&path) {
                        Ok(_) => imported += 1,
                        Err(error) => failures.push(format!("{}：{error}", path.display())),
                    }
                }
                let _ = view.update_in(window, |this, _, cx| {
                    this.public_keys = scan_public_keys(this.key_store.as_ref());
                    this.selected_public_key = this
                        .selected_public_key
                        .min(this.public_keys.len().saturating_sub(1));
                    this.refresh_recipient_selection();
                    this.status = if failures.is_empty() {
                        format!("已导入 {imported} 个公钥")
                    } else {
                        format!("已导入 {imported}/{total} 个公钥；{}", failures.join("；"))
                    };
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn delete_selected_public_key(&mut self) {
        let Some(store) = self.key_store.as_ref() else {
            return;
        };
        let Some(entry) = self.public_keys.get(self.selected_public_key).cloned() else {
            return;
        };
        match store.delete_public(&entry) {
            Ok(()) => {
                self.public_keys = scan_public_keys(self.key_store.as_ref());
                self.selected_public_key = self
                    .selected_public_key
                    .min(self.public_keys.len().saturating_sub(1));
                self.refresh_recipient_selection();
                self.status = format!("已删除公钥 {}", entry.name);
            }
            Err(error) => self.status = format!("删除公钥失败：{error}"),
        }
    }

    fn open_key_directory(&mut self) {
        let Some(store) = self.key_store.as_ref() else {
            self.status = "密钥目录不可用".into();
            return;
        };
        match std::process::Command::new("explorer.exe")
            .arg(store.root())
            .spawn()
        {
            Ok(_) => self.status = "已打开密钥目录".into(),
            Err(error) => self.status = format!("打开密钥目录失败：{error}"),
        }
    }

    fn retry_open_with_keys(&mut self) {
        let Some(path) = self.archive_path.clone() else {
            self.status = "没有正在打开的归档".into();
            return;
        };
        let Some(store) = self.key_store.clone() else {
            self.status = "密钥目录不可用".into();
            return;
        };

        self.keys = scan_keys(Some(&store));
        self.refresh_recipient_selection();
        let keys = self
            .keys
            .iter()
            .filter(|entry| matches!(entry.state, KeyState::Valid { .. }))
            .cloned()
            .collect::<Vec<_>>();
        let key_count = keys.len();
        if self
            .archive_tx
            .send(ArchiveCommand::OpenWithKeys { path, store, keys })
            .is_ok()
        {
            self.unlock_attempts.push_back(UnlockAttempt::RetriedKeys);
        }
        self.status = format!("正在重新检查 {key_count} 个本地私钥…");
    }

    fn refresh_recipient_selection(&mut self) {
        let available = recipient_choices(&self.keys, &self.public_keys)
            .into_iter()
            .map(|(_, recipient)| recipient)
            .collect::<HashSet<_>>();
        self.selected_recipients
            .retain(|recipient| available.contains(recipient));
        if self.selected_recipients.is_empty()
            && let Some(recipient) = available.into_iter().next()
        {
            self.selected_recipients.insert(recipient);
        }
    }

    fn toggle_create_password_visibility(&mut self, window: &mut Window, cx: &mut App) {
        self.create_password_visible = !self.create_password_visible;
        let masked = !self.create_password_visible;
        for input in [&self.password, &self.password_confirm] {
            input.update(cx, |state, cx| state.set_masked(masked, window, cx));
        }
    }

    fn toggle_archive_password_visibility(&mut self, window: &mut Window, cx: &mut App) {
        self.archive_password_visible = !self.archive_password_visible;
        self.archive_password.update(cx, |state, cx| {
            state.set_masked(!self.archive_password_visible, window, cx)
        });
    }

    fn set_theme(&mut self, preference: ThemePreference, window: &mut Window, cx: &mut App) {
        self.preferences.theme = preference;
        self.apply_theme(window, cx);
        if let Err(error) = self.preferences.save() {
            self.status = format!("保存设置失败：{error}");
        }
    }

    fn title_bar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let page = self.page;
        TitleBar::new().child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .w_full()
                .when(page != Page::Home, |this| {
                    this.child(
                        Button::new("back")
                            .icon(IconName::ArrowLeft)
                            .ghost()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.page = Page::Home;
                                cx.notify();
                            })),
                    )
                })
                .child(
                    div()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child("engage"),
                )
                .child(
                    div()
                        .text_color(cx.theme().muted_foreground)
                        .child(match page {
                            Page::Home => "安全归档",
                            Page::Decrypt => "解密",
                            Page::Create => "加密",
                        }),
                )
                .child(div().flex_1())
                .child(
                    Button::new("settings")
                        .icon(IconName::Settings)
                        .ghost()
                        .tooltip("设置与私钥")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.settings_open = !this.settings_open;
                            cx.notify();
                        })),
                ),
        )
    }

    fn render_task_progress(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let progress = self
            .active_task
            .as_ref()
            .and_then(|task| task.progress.as_ref());
        let value = progress.and_then(progress_percent);
        div()
            .px_5()
            .py_3()
            .border_b_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().background)
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .child(progress.map_or_else(|| "正在准备…".into(), progress_label)),
                    )
                    .child(div().flex_1())
                    .when_some(value, |this, value| this.child(format!("{value:.0}%")))
                    .when(value.is_none(), |this| {
                        this.child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(Spinner::new())
                                .when_some(progress, |this, progress| {
                                    this.child(progress_work_label(progress))
                                }),
                        )
                    }),
            )
            .when_some(value, |this, value| {
                this.child(Progress::new().value(value).h_2())
            })
            .when(value.is_none(), |this| {
                this.child(Skeleton::new().h_2().rounded_full())
            })
    }

    fn render_home(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex_1()
            .flex()
            .flex_col()
            .justify_center()
            .items_center()
            .gap_8()
            .p_8()
            .child(
                div()
                    .text_3xl()
                    .font_weight(gpui::FontWeight::BOLD)
                    .child("Engage"),
            )
            .child(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child("可随机访问的 PQ 加密归档"),
            )
            .child(
                div()
                    .w_full()
                    .max_w(rems(44.))
                    .flex()
                    .flex_wrap()
                    .justify_center()
                    .gap_5()
                    .children([
                        self.home_card(
                            "open-card",
                            IconName::FolderOpen,
                            "打开归档",
                            "浏览并只解压需要的文件",
                            cx.listener(|this, _, window, cx| this.select_archive(window, cx)),
                            cx,
                        ),
                        self.home_card(
                            "create-card",
                            IconName::Inbox,
                            "创建归档",
                            "添加多个文件或文件夹",
                            cx.listener(|this, _, _, cx| {
                                this.page = Page::Create;
                                cx.notify();
                            }),
                            cx,
                        ),
                    ]),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("拖入一个 .engage 文件以打开；拖入其他内容以创建归档"),
            )
    }

    fn home_card(
        &self,
        id: &'static str,
        icon: IconName,
        title: &'static str,
        description: &'static str,
        on_click: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        div()
            .id(id)
            .flex_1()
            .min_w(rems(16.))
            .max_w(rems(20.625))
            .min_h(rems(13.125))
            .p_7()
            .flex()
            .flex_col()
            .justify_between()
            .rounded_xl()
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().background)
            .shadow_sm()
            .cursor_pointer()
            .hover(|style| style.border_color(cx.theme().primary).shadow_md())
            .on_click(on_click)
            .child(Icon::new(icon).size_8().text_color(cx.theme().primary))
            .child(
                div()
                    .text_2xl()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(title),
            )
            .child(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child(description),
            )
    }

    fn render_create(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div().flex_1().overflow_hidden().p_6().child(
            div()
                .max_w(rems(57.5))
                .mx_auto()
                .h_full()
                .flex()
                .flex_col()
                .gap_5()
                .child(
                    div()
                        .text_2xl()
                        .font_weight(gpui::FontWeight::BOLD)
                        .child("创建加密归档"),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .child(
                            Button::new("add-files")
                                .icon(IconName::Plus)
                                .label("添加文件")
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.select_paths(false, true, window, cx)
                                })),
                        )
                        .child(
                            Button::new("add-folders")
                                .icon(IconName::Folder)
                                .label("添加文件夹")
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.select_paths(true, true, window, cx)
                                })),
                        )
                        .child(Button::new("clear-inputs").label("清空").ghost().on_click(
                            cx.listener(|this, _, _, cx| {
                                this.create_inputs.clear();
                                this.sync_create_table(cx);
                                cx.notify();
                            }),
                        )),
                )
                .child(
                    div()
                        .flex_1()
                        .min_h(rems(10.))
                        .when(self.create_inputs.is_empty(), |this| {
                            this.flex()
                                .items_center()
                                .justify_center()
                                .rounded_lg()
                                .border_1()
                                .border_color(cx.theme().border)
                                .text_color(cx.theme().muted_foreground)
                                .child("拖放文件或文件夹到这里")
                        })
                        .when(!self.create_inputs.is_empty(), |this| {
                            this.child(Table::new(&self.create_table_state).stripe(true))
                        }),
                )
                .child(
                    RadioGroup::horizontal("credential-mode")
                        .selected_index(Some(usize::from(self.password_mode)))
                        .children(["PQ 私钥", "密码"])
                        .on_click(cx.listener(|this, index: &usize, _, cx| {
                            this.password_mode = *index == 1;
                            cx.notify();
                        })),
                )
                .when(!self.password_mode, |this| {
                    this.child(self.render_key_choices(cx))
                })
                .when(self.password_mode, |this| {
                    this.child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div().flex().flex_col().gap_2().child("密码").child(
                                    accessible_input(&self.password, cx).w_full().suffix(
                                        Button::new("show-create-password")
                                            .icon(if self.create_password_visible {
                                                IconName::EyeOff
                                            } else {
                                                IconName::Eye
                                            })
                                            .ghost()
                                            .compact()
                                            .tooltip(if self.create_password_visible {
                                                "隐藏密码"
                                            } else {
                                                "显示密码"
                                            })
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.toggle_create_password_visibility(window, cx);
                                                cx.notify();
                                            })),
                                    ),
                                ),
                            )
                            .child(
                                div().flex().flex_col().gap_2().child("确认密码").child(
                                    accessible_input(&self.password_confirm, cx)
                                        .w_full()
                                        .suffix(
                                            Button::new("show-create-password-confirm")
                                                .icon(if self.create_password_visible {
                                                    IconName::EyeOff
                                                } else {
                                                    IconName::Eye
                                                })
                                                .ghost()
                                                .compact()
                                                .on_click(cx.listener(|this, _, window, cx| {
                                                    this.toggle_create_password_visibility(
                                                        window, cx,
                                                    );
                                                    cx.notify();
                                                })),
                                        ),
                                ),
                            ),
                    )
                })
                .child(
                    div().flex().flex_col().gap_2().child("输出文件").child(
                        accessible_input(&self.create_output, cx).w_full().suffix(
                            Button::new("browse-create-output")
                                .icon(IconName::FolderOpen)
                                .label("选择位置")
                                .ghost()
                                .compact()
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.select_create_output(window, cx);
                                })),
                        ),
                    ),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .justify_end()
                        .gap_3()
                        .when(self.active_task.is_some(), |this| {
                            this.child(
                                Button::new("cancel-create")
                                    .label("取消任务")
                                    .danger()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        if let Some(task) = &mut this.active_task {
                                            task.cancellation.cancel();
                                            task.progress = None;
                                            this.status = "正在取消任务…".into();
                                            cx.notify();
                                        }
                                    })),
                            )
                        })
                        .child(
                            Button::new("start-create")
                                .label("开始加密")
                                .primary()
                                .disabled(self.active_task.is_some())
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.start_create(cx);
                                    cx.notify();
                                })),
                        ),
                ),
        )
    }

    fn render_key_choices(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let choices = recipient_choices(&self.keys, &self.public_keys);
        let selected = self.selected_recipients.clone();
        let events = self.ui_events.clone();
        let selected_count = selected.len();
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child("加密接收者")
            .when(choices.is_empty(), |this| {
                this.text_color(cx.theme().muted_foreground)
                    .child("没有可用公钥，请在右上角设置中生成或导入")
            })
            .when(!choices.is_empty(), |this| {
                this.child(
                    Popover::new("recipient-select")
                        .anchor(Corner::TopRight)
                        .trigger(
                            Button::new("recipient-select-label")
                                .label(if selected_count == 0 {
                                    "选择 PQ 公钥".to_owned()
                                } else {
                                    format!("已选择 {selected_count} 个接收者")
                                })
                                .dropdown_caret(true)
                                .outline()
                                .border_1()
                                .border_color(cx.theme().muted_foreground.opacity(0.65))
                                .bg(cx.theme().background)
                                .w_full(),
                        )
                        .content(move |_, window, _cx| {
                            let preferred = rems(28.).to_pixels(window.rem_size());
                            let available = window.viewport_size().width
                                - rems(4.).to_pixels(window.rem_size());
                            let width = if available < preferred {
                                available
                            } else {
                                preferred
                            };
                            div()
                                .w(width)
                                .max_h(rems(22.5))
                                .overflow_y_scrollbar()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .children(choices.iter().enumerate().map(
                                    |(index, (label, recipient))| {
                                        let item_events = events.clone();
                                        let toggled_recipient = recipient.clone();
                                        Checkbox::new(("recipient-choice", index))
                                            .label(label.clone())
                                            .checked(selected.contains(recipient))
                                            .w_full()
                                            .px_2()
                                            .py_2()
                                            .on_click(move |_, _, _| {
                                                let _ =
                                                    item_events.try_send(UiEvent::ToggleRecipient(
                                                        toggled_recipient.clone(),
                                                    ));
                                            })
                                    },
                                ))
                        })
                        .w_full(),
                )
            })
    }

    fn render_decrypt(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let events = self.ui_events.clone();
        let directory_tree = tree(&self.tree_state, move |ix, entry, selected, _, _| {
            let item = entry.item();
            let item_id = item.id.to_string();
            let label = item.label.clone();
            let depth = entry.depth();
            let icon = if entry.is_expanded() {
                IconName::FolderOpen
            } else {
                IconName::Folder
            };
            let events = events.clone();
            ListItem::new(ix)
                .selected(selected)
                .pl(rems(0.75 + depth as f32 * 1.125))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(Icon::new(icon))
                        .child(div().truncate().child(label)),
                )
                .on_click(move |_, _, _| {
                    if let Some(id) = item_id
                        .strip_prefix("directory:")
                        .and_then(|value| value.parse::<EntryId>().ok())
                    {
                        let _ = events.try_send(UiEvent::NavigateDirectory(id));
                    }
                })
        });
        let hierarchy_events = self.ui_events.clone();
        div()
            .on_action(cx.listener(|this, _: &CopyArchiveSelection, _, cx| {
                this.copy_archive_selection(cx);
                cx.notify();
            }))
            .flex_1()
            .overflow_hidden()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .child(
                        Button::new("directory-back")
                            .icon(IconName::ArrowLeft)
                            .ghost()
                            .disabled(self.history.is_empty())
                            .on_click(cx.listener(|this, _, _, _| {
                                if let Some((parent, path)) = this.history.pop() {
                                    let _ =
                                        this.archive_tx.send(ArchiveCommand::List { parent, path });
                                }
                            })),
                    )
                    .child(
                        div()
                            .text_lg()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(if self.current_path.is_empty() {
                                "/".to_owned()
                            } else {
                                self.current_path.clone()
                            }),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!("{} 项", self.entries.len())),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .overflow_hidden()
                    .child(
                        div()
                            .w(relative(0.25))
                            .min_w(rems(11.))
                            .max_w(rems(16.))
                            .p_4()
                            .border_r_1()
                            .border_color(cx.theme().border)
                            .bg(cx.theme().sidebar)
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .px_3()
                                    .py_2()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("目录"),
                            )
                            .child(div().flex_1().min_h_0().child(directory_tree)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(Table::new(&self.table_state).stripe(true)),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        Checkbox::new("preserve-extraction-hierarchy")
                            .label("保留目录层级")
                            .checked(self.preserve_hierarchy)
                            .on_click(move |checked, _, _| {
                                let _ = hierarchy_events
                                    .try_send(UiEvent::SetPreserveHierarchy(*checked));
                            }),
                    )
                    .child("目标文件夹")
                    .child(
                        accessible_input(&self.decrypt_output, cx).w_full().suffix(
                            Button::new("browse-decrypt-output")
                                .icon(IconName::FolderOpen)
                                .label("选择文件夹")
                                .ghost()
                                .compact()
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.select_decrypt_output(window, cx);
                                })),
                        ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .justify_end()
                            .gap_2()
                            .when(self.active_task.is_some(), |this| {
                                this.child(
                                    Button::new("cancel-extract")
                                        .label("取消")
                                        .danger()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            if let Some(task) = &mut this.active_task {
                                                task.cancellation.cancel();
                                                task.progress = None;
                                                this.status = "正在取消任务…".into();
                                                cx.notify();
                                            }
                                        })),
                                )
                            })
                            .child(
                                Button::new("extract-selected")
                                    .label(format!("解压选中（{}）", self.checked.len()))
                                    .primary()
                                    .disabled(self.checked.is_empty() || self.active_task.is_some())
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let destination = PathBuf::from(
                                            this.decrypt_output.read(cx).value().as_ref(),
                                        );
                                        let selection = Selection::EntryIds(
                                            this.checked.iter().copied().collect(),
                                        );
                                        let _ = this.archive_tx.send(ArchiveCommand::PlanExtract {
                                            destination,
                                            selection,
                                            preserve_hierarchy: this.preserve_hierarchy,
                                        });
                                        this.status = "正在检查目标冲突…".into();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("extract-all")
                                    .label("全部解压")
                                    .disabled(self.active_task.is_some())
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let destination = PathBuf::from(
                                            this.decrypt_output.read(cx).value().as_ref(),
                                        );
                                        let _ = this.archive_tx.send(ArchiveCommand::PlanExtract {
                                            destination,
                                            selection: Selection::All,
                                            preserve_hierarchy: this.preserve_hierarchy,
                                        });
                                        this.status = "正在检查目标冲突…".into();
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
    }

    fn render_settings(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let private_key_list =
            div()
                .flex()
                .flex_col()
                .gap_2()
                .children(self.keys.iter().enumerate().map(|(index, key)| {
                    let label = if matches!(key.state, KeyState::Valid { .. }) {
                        key.name.clone()
                    } else {
                        format!("{}（无效）", key.name)
                    };
                    Button::new(("settings-key", index))
                        .icon(IconName::Asterisk)
                        .label(label)
                        .selected(index == self.selected_key)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.selected_key = index;
                            cx.notify();
                        }))
                }));
        let public_key_list =
            div()
                .flex()
                .flex_col()
                .gap_2()
                .children(self.public_keys.iter().enumerate().map(|(index, key)| {
                    let label = if matches!(key.state, KeyState::Valid { .. }) {
                        key.name.clone()
                    } else {
                        format!("{}（无效）", key.name)
                    };
                    Button::new(("settings-public-key", index))
                        .icon(IconName::Asterisk)
                        .label(label)
                        .selected(index == self.selected_public_key)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.selected_public_key = index;
                            cx.notify();
                        }))
                }));
        let private_section = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "私钥目录\n{}",
                                self.key_store.as_ref().map_or_else(
                                    || "目录不可用".into(),
                                    |store| windows_display_path(store.root())
                                )
                            )),
                    )
                    .child(
                        Button::new("open-key-directory")
                            .icon(IconName::FolderOpen)
                            .label("打开目录")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_key_directory();
                                cx.notify();
                            })),
                    ),
            )
            .child(private_key_list)
            .child(accessible_input(&self.key_name, cx).w_full())
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("export-public-key")
                            .label("导出公钥")
                            .disabled(self.keys.is_empty())
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.export_selected_public_key(window, cx);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("delete-key")
                            .label("删除选中")
                            .danger()
                            .disabled(self.keys.is_empty())
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.delete_selected_key(window, cx);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("generate-key")
                            .label("生成私钥")
                            .primary()
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.generate_key(window, cx);
                                cx.notify();
                            })),
                    ),
            );
        let public_section = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(format!(
                        "已导入公钥 · {}",
                        self.key_store.as_ref().map_or_else(
                            || "目录不可用".into(),
                            |store| windows_display_path(&store.public_root())
                        )
                    )),
            )
            .child(public_key_list)
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("delete-public-key")
                            .label("删除公钥")
                            .danger()
                            .disabled(self.public_keys.is_empty())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.delete_selected_public_key();
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("import-public-key")
                            .label("导入公钥")
                            .primary()
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.import_public_keys(window, cx);
                                cx.notify();
                            })),
                    ),
            );
        let panel = div()
            .id("settings-panel")
            .w_full()
            .max_w(rems(26.25))
            .h_full()
            .overflow_y_scrollbar()
            .p_6()
            .border_l_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().popover)
            .shadow_xl()
            .flex()
            .flex_col()
            .gap_5()
            .child(
                div()
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .text_xl()
                            .font_weight(gpui::FontWeight::BOLD)
                            .child("设置"),
                    )
                    .child(div().flex_1())
                    .child(
                        Button::new("close-settings")
                            .icon(IconName::Close)
                            .ghost()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.settings_open = false;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("外观"),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_2()
                            .child(self.theme_button(
                                "theme-system",
                                "跟随系统",
                                ThemePreference::System,
                                cx,
                            ))
                            .child(self.theme_button(
                                "theme-light",
                                "浅色",
                                ThemePreference::Light,
                                cx,
                            ))
                            .child(self.theme_button(
                                "theme-dark",
                                "深色",
                                ThemePreference::Dark,
                                cx,
                            )),
                    ),
            )
            .child(div().h_px().my_2().bg(cx.theme().border))
            .child(private_section)
            .child(div().h_px().my_2().bg(cx.theme().border))
            .child(public_section);

        div()
            .absolute()
            .inset_0()
            .pt(px(34.))
            .flex()
            .justify_end()
            .bg(gpui::black().opacity(0.45))
            .child(panel)
    }

    fn theme_button(
        &self,
        id: &'static str,
        label: &'static str,
        value: ThemePreference,
        cx: &mut Context<Self>,
    ) -> Button {
        Button::new(id)
            .label(label)
            .selected(self.preferences.theme == value)
            .on_click(cx.listener(move |this, _, window, cx| {
                this.set_theme(value, window, cx);
                cx.notify();
            }))
    }

    fn render_overlays(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .absolute()
            .inset_0()
            .when(self.password_required, |this| {
                this.child(
                    self.modal_card(
                        "需要密码",
                        "请将私钥放入密钥文件夹后重新检查，或输入归档密码。",
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .child(
                                accessible_input(&self.archive_password, cx)
                                    .w_full()
                                    .suffix(
                                        Button::new("show-archive-password")
                                            .icon(if self.archive_password_visible {
                                                IconName::EyeOff
                                            } else {
                                                IconName::Eye
                                            })
                                            .ghost()
                                            .compact()
                                            .tooltip(if self.archive_password_visible {
                                                "隐藏密码"
                                            } else {
                                                "显示密码"
                                            })
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.toggle_archive_password_visibility(window, cx);
                                                cx.notify();
                                            })),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .justify_end()
                                    .gap_2()
                                    .child(Button::new("password-cancel").label("取消").on_click(
                                        cx.listener(|this, _, window, cx| {
                                            this.password_required = false;
                                            this.page = Page::Home;
                                            this.status = "已取消打开归档".into();
                                            this.archive_password.update(cx, |state, cx| {
                                                state.set_value("", window, cx);
                                            });
                                            cx.notify();
                                        }),
                                    ))
                                    .child(
                                        Button::new("open-key-directory")
                                            .label("打开密钥文件夹")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.open_key_directory();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        Button::new("retry-open-with-keys")
                                            .label("重新检查")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.retry_open_with_keys();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        Button::new("password-submit")
                                            .label("确定")
                                            .primary()
                                            .disabled(
                                                self.archive_password.read(cx).value().is_empty(),
                                            )
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let password = this
                                                    .archive_password
                                                    .read(cx)
                                                    .value()
                                                    .to_string();
                                                if password.is_empty() {
                                                    return;
                                                }
                                                if let Some(path) = this.archive_path.clone() {
                                                    if this
                                                        .archive_tx
                                                        .send(ArchiveCommand::OpenWithPassword {
                                                            path,
                                                            password: SecretString::from(password),
                                                        })
                                                        .is_ok()
                                                    {
                                                        this.unlock_attempts
                                                            .push_back(UnlockAttempt::Password);
                                                    }
                                                    this.status = "正在验证密码…".into();
                                                    cx.notify();
                                                }
                                            })),
                                    ),
                            ),
                        cx,
                    ),
                )
            })
            .when(self.pending_extract.is_some(), |this| {
                this.child(
                    self.modal_card(
                        "覆盖冲突",
                        "目标中已有同名文件。是否替换普通文件并复用目录？",
                        div()
                            .flex()
                            .justify_end()
                            .gap_2()
                            .child(Button::new("conflict-cancel").label("取消").on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.pending_extract = None;
                                    cx.notify();
                                }),
                            ))
                            .child(
                                Button::new("conflict-replace")
                                    .label("替换并继续")
                                    .danger()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        if let Some(pending) = this.pending_extract.take() {
                                            this.begin_extract(
                                                pending.destination,
                                                pending.selection,
                                                pending.preserve_hierarchy,
                                                true,
                                            );
                                        }
                                        cx.notify();
                                    })),
                            ),
                        cx,
                    ),
                )
            })
    }

    fn modal_card(
        &self,
        title: &'static str,
        description: &'static str,
        content: impl IntoElement,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .absolute()
            .inset_0()
            .bg(gpui::black().opacity(0.45))
            .flex()
            .items_center()
            .justify_center()
            .p_4()
            .child(
                div()
                    .w_full()
                    .max_w(rems(28.75))
                    .p_6()
                    .rounded_xl()
                    .bg(cx.theme().popover)
                    .border_1()
                    .border_color(cx.theme().border)
                    .shadow_xl()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(
                        div()
                            .text_xl()
                            .font_weight(gpui::FontWeight::BOLD)
                            .child(title),
                    )
                    .child(
                        div()
                            .text_color(cx.theme().muted_foreground)
                            .child(description),
                    )
                    .child(content),
            )
    }

    fn render_clipboard_overlay(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let task = self
            .clipboard_task
            .as_ref()
            .expect("clipboard overlay requires an active task");
        let cancelled = task.cancellation.is_cancelled();
        let progress = task.progress.as_ref();
        let value = progress.and_then(progress_percent).unwrap_or(0.);
        let label = if cancelled {
            "正在取消复制…".to_owned()
        } else {
            progress.map_or_else(|| "正在准备复制内容…".to_owned(), progress_label)
        };

        div()
            .id("clipboard-copy-lock")
            .absolute()
            .inset_0()
            .flex()
            .items_center()
            .justify_center()
            .p_4()
            .bg(gpui::black().opacity(0.45))
            .on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .on_mouse_down(MouseButton::Right, |_, _, cx| {
                cx.stop_propagation();
            })
            .child(
                div()
                    .w_full()
                    .max_w(rems(28.))
                    .p_6()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .bg(cx.theme().popover)
                    .shadow_lg()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .when(!cancelled, |this| this.child(Spinner::new()))
                            .child(div().flex_1().child(label))
                            .child(format!("{value:.0}%")),
                    )
                    .child(Progress::new().value(value).h_2())
                    .child(
                        div().flex().justify_end().child(
                            Button::new("cancel-clipboard-copy")
                                .label(if cancelled { "正在取消" } else { "取消" })
                                .danger()
                                .disabled(cancelled)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    if let Some(task) = &this.clipboard_task {
                                        task.cancellation.cancel();
                                        this.status = "正在取消复制…".into();
                                        cx.notify();
                                    }
                                })),
                        ),
                    ),
            )
    }
}

impl Render for MainView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let viewport_width = window.viewport_size().width;
        let rem_size = window.rem_size();
        let notification_layer = Root::render_notification_layer(window, cx);
        if self.last_layout != Some((viewport_width, rem_size)) {
            self.last_layout = Some((viewport_width, rem_size));
            self.table_state.update(cx, |state, cx| {
                state
                    .delegate_mut()
                    .resize_columns(viewport_width, rem_size);
                state.refresh(cx);
            });
            self.create_table_state.update(cx, |state, cx| {
                state
                    .delegate_mut()
                    .resize_columns(viewport_width, rem_size);
                state.refresh(cx);
            });
        }
        div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(self.title_bar(cx))
            .when(
                self.active_task
                    .as_ref()
                    .is_some_and(|task| !task.cancellation.is_cancelled()),
                |this| this.child(self.render_task_progress(cx)),
            )
            .child(match self.page {
                Page::Home => self.render_home(cx).into_any_element(),
                Page::Decrypt => self.render_decrypt(cx).into_any_element(),
                Page::Create => self.render_create(cx).into_any_element(),
            })
            .child(
                div()
                    .h(px(34.))
                    .px_4()
                    .flex()
                    .items_center()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .truncate()
                    .child(self.status.clone()),
            )
            .when(self.settings_open, |this| {
                this.child(self.render_settings(cx))
            })
            .when(
                self.password_required || self.pending_extract.is_some(),
                |this| this.child(self.render_overlays(cx)),
            )
            .when(self.clipboard_task.is_some(), |this| {
                this.child(self.render_clipboard_overlay(cx))
            })
            .when_some(notification_layer, |this, layer| this.child(layer))
            .on_drop(cx.listener(|this, paths: &ExternalPaths, window, cx| {
                this.handle_drop(paths, window, cx);
                cx.notify();
            }))
    }
}

pub(crate) fn run(initial_path: Option<PathBuf>) {
    Application::new()
        .with_assets(Assets)
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
            gpui_component::set_locale("zh-CN");
            cx.bind_keys([KeyBinding::new(
                "ctrl-c",
                CopyArchiveSelection,
                Some("Table"),
            )]);
            let bounds = Bounds::centered(None, size(px(1120.), px(760.)), cx);
            let initial_path = initial_path.clone();
            cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    titlebar: Some(TitleBar::title_bar_options()),
                    ..Default::default()
                },
                move |window, cx| {
                    let view = cx.new(|cx| MainView::new(initial_path, window, cx));
                    cx.new(|cx| Root::new(view, window, cx))
                },
            )
            .expect("failed to open engage window");
            cx.activate(true);
        });
}

fn accessible_input(state: &Entity<InputState>, cx: &App) -> Input {
    Input::new(state)
        .bordered(true)
        .border_1()
        .border_color(cx.theme().muted_foreground.opacity(0.65))
}

fn scan_keys(store: Option<&KeyStore>) -> Vec<KeyEntry> {
    store
        .and_then(|store| store.scan().ok())
        .unwrap_or_default()
}

fn scan_public_keys(store: Option<&KeyStore>) -> Vec<PublicKeyEntry> {
    store
        .and_then(|store| store.scan_public().ok())
        .unwrap_or_default()
}

fn recipient_choices(keys: &[KeyEntry], public_keys: &[PublicKeyEntry]) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut choices = Vec::new();
    for (kind, name, state) in keys
        .iter()
        .map(|key| ("本地私钥", &key.name, &key.state))
        .chain(
            public_keys
                .iter()
                .map(|key| ("导入公钥", &key.name, &key.state)),
        )
    {
        if let KeyState::Valid { recipient } = state
            && seen.insert(recipient.clone())
        {
            choices.push((format!("{kind} · {name}"), recipient.clone()));
        }
    }
    choices
}

fn first_valid_recipient(keys: &[KeyEntry], public_keys: &[PublicKeyEntry]) -> Option<String> {
    recipient_choices(keys, public_keys)
        .into_iter()
        .next()
        .map(|(_, recipient)| recipient)
}

fn is_engage(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("engage"))
}

fn default_output_path(inputs: &[PathBuf]) -> Option<PathBuf> {
    let first = inputs.first()?;
    let basename = first.file_name()?.to_string_lossy();
    Some(
        first
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!("{basename}.engage")),
    )
}

fn absolute_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir().map_or(path.clone(), |directory| directory.join(path))
    }
}

pub(crate) fn windows_display_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = value.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        value.into_owned()
    }
}

fn join_archive_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.into()
    } else {
        format!("{parent}/{name}")
    }
}

fn progress_label(progress: &OperationProgress) -> String {
    let stage = match progress.stage {
        OperationStage::Scanning => "扫描",
        OperationStage::Archiving
            if progress.entries_total.is_none() && progress.bytes_total.is_none() =>
        {
            "扫描并打包"
        }
        OperationStage::Archiving => "打包",
        OperationStage::BuildingIndex => "构建索引",
        OperationStage::WritingIndex => "写入索引",
        OperationStage::ResolvingSelection => "解析选择",
        OperationStage::Extracting => "解压",
        OperationStage::ApplyingMetadata => "恢复元数据",
        OperationStage::Finalizing => "收尾",
        OperationStage::Complete => "完成",
    };
    progress
        .current_path
        .as_ref()
        .and_then(|path| path.file_name())
        .map_or_else(
            || stage.into(),
            |name| format!("{stage} · {}", name.to_string_lossy()),
        )
}

fn progress_percent(progress: &OperationProgress) -> Option<f32> {
    if progress.stage == OperationStage::Complete {
        return Some(100.);
    }
    if let Some(total) = progress.bytes_total.filter(|total| *total > 0) {
        return Some((progress.bytes_done as f32 * 100. / total as f32).clamp(0., 100.));
    }
    if let Some(total) = progress.entries_total.filter(|total| *total > 0) {
        return Some((progress.entries_done as f32 * 100. / total as f32).clamp(0., 100.));
    }
    None
}

fn progress_work_label(progress: &OperationProgress) -> String {
    if progress.entries_done == 0 && progress.bytes_done == 0 {
        return "正在准备…".into();
    }
    format!(
        "已处理 {} 项 · {}",
        progress.entries_done,
        format_progress_bytes(progress.bytes_done)
    )
}

fn format_progress_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024. && unit < UNITS.len() - 1 {
        value /= 1024.;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
