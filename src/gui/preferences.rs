use std::{fs, io::Write, path::PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ThemePreference {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Preferences {
    pub theme: ThemePreference,
}

impl Preferences {
    pub fn load() -> Self {
        let Some(path) = preferences_path() else {
            return Self::default();
        };
        fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> engage::Result<()> {
        let path =
            preferences_path().ok_or_else(|| eros::error!("cannot determine current user home"))?;
        let parent = path
            .parent()
            .ok_or_else(|| eros::error!("invalid preferences path"))?;
        fs::create_dir_all(parent)?;
        let mut temp = NamedTempFile::new_in(parent)?;
        temp.write_all(&serde_json::to_vec_pretty(self)?)?;
        temp.as_file_mut().sync_all()?;
        temp.persist(path).map_err(|error| error.error)?;
        Ok(())
    }
}

fn preferences_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".engage").join("preferences.json"))
}
