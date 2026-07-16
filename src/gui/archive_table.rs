use std::{collections::HashSet, path::PathBuf};

use chrono::{DateTime, Utc};
use engage::{EntryId, EntryInfo, EntryKind};
use gpui::{
    App, Context, InteractiveElement as _, IntoElement, ParentElement as _, Stateful,
    StatefulInteractiveElement as _, Styled as _, Window, div, prelude::FluentBuilder as _, rems,
};
use gpui_component::{
    ActiveTheme as _, Disableable as _, Icon, IconName, Sizable as _,
    button::{Button, ButtonVariants as _},
    checkbox::Checkbox,
    h_flex,
    table::{Column, TableDelegate, TableState},
};

use super::{UiEvent, windows_display_path};

pub(crate) struct ArchiveTableDelegate {
    columns: Vec<Column>,
    pub entries: Vec<EntryInfo>,
    pub checked: HashSet<EntryId>,
    pub current_path: String,
    events: async_channel::Sender<UiEvent>,
}

impl ArchiveTableDelegate {
    pub fn new(events: async_channel::Sender<UiEvent>, rem_size: gpui::Pixels) -> Self {
        Self {
            columns: vec![
                Column::new("checked", "")
                    .width(rems(3.).to_pixels(rem_size))
                    .resizable(false),
                Column::new("name", "名称").width(rems(26.25).to_pixels(rem_size)),
                Column::new("details", "详情").width(rems(16.25).to_pixels(rem_size)),
            ],
            entries: Vec::new(),
            checked: HashSet::new(),
            current_path: String::new(),
            events,
        }
    }

    pub fn resize_columns(&mut self, viewport_width: gpui::Pixels, rem_size: gpui::Pixels) {
        let min_sidebar = rems(11.).to_pixels(rem_size);
        let max_sidebar = rems(16.).to_pixels(rem_size);
        let proposed_sidebar = viewport_width * 0.25;
        let sidebar = if proposed_sidebar < min_sidebar {
            min_sidebar
        } else if proposed_sidebar > max_sidebar {
            max_sidebar
        } else {
            proposed_sidebar
        };
        let proposed_available = viewport_width - sidebar - rems(4.).to_pixels(rem_size);
        let minimum_available = rems(22.).to_pixels(rem_size);
        let available = if proposed_available < minimum_available {
            minimum_available
        } else {
            proposed_available
        };
        let selector = rems(3.).to_pixels(rem_size);
        let content = available - selector;
        self.columns[0].width = selector;
        self.columns[1].width = content * 0.62;
        self.columns[2].width = content * 0.38;
    }
}

impl TableDelegate for ArchiveTableDelegate {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.entries.len() + 1
    }

    fn column(&self, col_ix: usize, _: &App) -> &Column {
        &self.columns[col_ix]
    }

    fn render_th(
        &mut self,
        col_ix: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        if col_ix != 0 {
            return div()
                .size_full()
                .child(self.columns[col_ix].name.clone())
                .into_any_element();
        }

        let selected = self
            .entries
            .iter()
            .filter(|entry| self.checked.contains(&entry.id))
            .count();
        let all = !self.entries.is_empty() && selected == self.entries.len();
        let partial = selected > 0 && !all;
        let events = self.events.clone();
        h_flex()
            .size_full()
            .justify_center()
            .child(if partial {
                div()
                    .id("archive-check-partial")
                    .size_4()
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded_sm()
                    .bg(cx.theme().primary)
                    .border_1()
                    .border_color(cx.theme().muted_foreground.opacity(0.7))
                    .cursor_pointer()
                    .child(
                        Icon::new(IconName::Dash)
                            .small()
                            .text_color(cx.theme().primary_foreground),
                    )
                    .on_click(move |_, _, _| {
                        let _ = events.try_send(UiEvent::ToggleAllVisible);
                    })
                    .into_any_element()
            } else {
                Checkbox::new("archive-check-all")
                    .checked(all)
                    .disabled(self.entries.is_empty())
                    .border_1()
                    .border_color(cx.theme().muted_foreground.opacity(0.7))
                    .rounded_sm()
                    .on_click(move |_, _, _| {
                        let _ = events.try_send(UiEvent::ToggleAllVisible);
                    })
                    .into_any_element()
            })
            .into_any_element()
    }

    fn render_tr(
        &mut self,
        row_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> Stateful<gpui::Div> {
        div().id(("archive-row", row_ix))
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        if row_ix == 0 {
            let at_root = self.current_path.is_empty();
            let events = self.events.clone();
            return match col_ix {
                0 => div().size_full().into_any_element(),
                1 => h_flex()
                    .id("archive-parent-row")
                    .size_full()
                    .gap_2()
                    .cursor_pointer()
                    .when(at_root, |this| this.text_color(cx.theme().muted_foreground))
                    .child(Icon::new(IconName::FolderOpen))
                    .child("..")
                    .on_click(move |event, _, _| {
                        if event.click_count() >= 2 {
                            let _ = events.try_send(UiEvent::NavigateParent);
                        }
                    })
                    .into_any_element(),
                _ => h_flex()
                    .size_full()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(if at_root {
                        "归档根目录"
                    } else {
                        "上一级"
                    })
                    .into_any_element(),
            };
        }

        let entry = self.entries[row_ix - 1].clone();
        match col_ix {
            0 => {
                let events = self.events.clone();
                h_flex()
                    .size_full()
                    .justify_center()
                    .child(
                        Checkbox::new(("archive-check", entry.id as usize))
                            .checked(self.checked.contains(&entry.id))
                            .border_1()
                            .border_color(cx.theme().muted_foreground.opacity(0.7))
                            .rounded_sm()
                            .on_click(move |_, _, _| {
                                let _ = events.try_send(UiEvent::ToggleEntry(entry.id));
                            }),
                    )
                    .into_any_element()
            }
            1 => {
                let events = self.events.clone();
                let is_directory = entry.kind == EntryKind::Directory;
                let entry_id = entry.id;
                h_flex()
                    .id(("archive-name", entry.id as usize))
                    .size_full()
                    .gap_2()
                    .overflow_hidden()
                    .cursor_pointer()
                    .child(Icon::new(if is_directory {
                        IconName::Folder
                    } else {
                        IconName::File
                    }))
                    .child(div().truncate().child(entry.name))
                    .on_click(move |event, _, _| {
                        if is_directory && event.click_count() >= 2 {
                            let _ = events.try_send(UiEvent::NavigateDirectory(entry_id));
                        }
                    })
                    .into_any_element()
            }
            _ => h_flex()
                .size_full()
                .justify_between()
                .text_sm()
                .child(match entry.kind {
                    EntryKind::Directory => "文件夹".to_owned(),
                    EntryKind::File => format_bytes(entry.size),
                    EntryKind::Symlink => "符号链接".to_owned(),
                })
                .child(format_time(entry.mtime))
                .into_any_element(),
        }
    }
}

pub(crate) struct CreateTableDelegate {
    columns: Vec<Column>,
    pub paths: Vec<PathBuf>,
    events: async_channel::Sender<UiEvent>,
}

impl CreateTableDelegate {
    pub fn new(events: async_channel::Sender<UiEvent>, rem_size: gpui::Pixels) -> Self {
        Self {
            columns: vec![
                Column::new("remove", "")
                    .width(rems(3.).to_pixels(rem_size))
                    .resizable(false),
                Column::new("name", "名称").width(rems(17.5).to_pixels(rem_size)),
                Column::new("location", "位置").width(rems(30.).to_pixels(rem_size)),
            ],
            paths: Vec::new(),
            events,
        }
    }

    pub fn resize_columns(&mut self, viewport_width: gpui::Pixels, rem_size: gpui::Pixels) {
        let maximum = rems(57.5).to_pixels(rem_size);
        let proposed_width = if viewport_width < maximum {
            viewport_width
        } else {
            maximum
        } - rems(3.).to_pixels(rem_size);
        let minimum_width = rems(24.).to_pixels(rem_size);
        let content_width = if proposed_width < minimum_width {
            minimum_width
        } else {
            proposed_width
        };
        let remove = rems(3.).to_pixels(rem_size);
        let content = content_width - remove;
        self.columns[0].width = remove;
        self.columns[1].width = content * 0.36;
        self.columns[2].width = content * 0.64;
    }
}

impl TableDelegate for CreateTableDelegate {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.paths.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> &Column {
        &self.columns[col_ix]
    }

    fn render_tr(
        &mut self,
        row_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> Stateful<gpui::Div> {
        div().id(("create-row", row_ix))
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let path = self.paths[row_ix].clone();
        match col_ix {
            0 => {
                let events = self.events.clone();
                h_flex()
                    .size_full()
                    .justify_center()
                    .child(
                        Button::new(("remove-create-input", row_ix))
                            .icon(IconName::Close)
                            .ghost()
                            .compact()
                            .on_click(move |_, _, _| {
                                let _ = events.try_send(UiEvent::RemoveInput(row_ix));
                            }),
                    )
                    .into_any_element()
            }
            1 => h_flex()
                .size_full()
                .gap_2()
                .child(Icon::new(if path.is_dir() {
                    IconName::Folder
                } else {
                    IconName::File
                }))
                .child(div().truncate().child(path.file_name().map_or_else(
                    || windows_display_path(&path),
                    |name| name.to_string_lossy().into_owned(),
                )))
                .into_any_element(),
            _ => div()
                .truncate()
                .child(
                    path.parent()
                        .map_or_else(|| windows_display_path(&path), windows_display_path),
                )
                .into_any_element(),
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024. && unit + 1 < UNITS.len() {
        value /= 1024.;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_time(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|value| value.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "—".to_owned())
}
