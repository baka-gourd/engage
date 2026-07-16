use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use age::secrecy::ExposeSecret;
use tempfile::NamedTempFile;

use crate::{HybridIdentity, HybridRecipient, Result, error::message, generate_pq_keypair};

const KEY_EXTENSION: &str = "agekey";
const PUBLIC_KEY_EXTENSION: &str = "agepub";

#[derive(Debug, Clone)]
pub enum KeyState {
    Valid { recipient: String },
    Invalid { reason: String },
}

#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub name: String,
    pub path: PathBuf,
    pub state: KeyState,
}

#[derive(Debug, Clone)]
pub struct PublicKeyEntry {
    pub name: String,
    pub path: PathBuf,
    pub state: KeyState,
}

#[derive(Debug, Clone)]
pub struct KeyStore {
    root: PathBuf,
}

impl KeyStore {
    pub fn for_current_user() -> Result<Self> {
        let home = dirs::home_dir().ok_or_else(|| message("cannot determine current user home"))?;
        Self::new(home.join(".engage"))
    }

    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        fs::create_dir_all(root.join("public"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn public_root(&self) -> PathBuf {
        self.root.join("public")
    }

    pub fn scan(&self) -> Result<Vec<KeyEntry>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file()
                || !path
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case(KEY_EXTENSION))
            {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_owned();
            let state = match Self::read_identity(&path).and_then(|identity| identity.to_public()) {
                Ok(recipient) => KeyState::Valid {
                    recipient: recipient.to_string(),
                },
                Err(error) => KeyState::Invalid {
                    reason: error.to_string(),
                },
            };
            entries.push(KeyEntry { name, path, state });
        }
        entries.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(entries)
    }

    pub fn generate(&self, name: &str) -> Result<KeyEntry> {
        validate_key_name(name)?;
        let destination = self.root.join(format!("{name}.{KEY_EXTENSION}"));
        if destination.exists() {
            return Err(message(format!("key already exists: {name}")));
        }
        let (recipient, identity) = generate_pq_keypair()?;
        let mut temp = NamedTempFile::new_in(&self.root)?;
        writeln!(temp, "# public key: {recipient}")?;
        writeln!(temp, "{}", identity.to_secret_string().expose_secret())?;
        temp.as_file_mut().sync_all()?;
        temp.persist_noclobber(&destination)
            .map_err(|error| error.error)?;
        Ok(KeyEntry {
            name: name.to_owned(),
            path: destination,
            state: KeyState::Valid {
                recipient: recipient.to_string(),
            },
        })
    }

    pub fn scan_public(&self) -> Result<Vec<PublicKeyEntry>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(self.public_root())? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file()
                || !path
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case(PUBLIC_KEY_EXTENSION))
            {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_owned();
            let state = match Self::read_recipient(&path) {
                Ok(recipient) => KeyState::Valid {
                    recipient: recipient.to_string(),
                },
                Err(error) => KeyState::Invalid {
                    reason: error.to_string(),
                },
            };
            entries.push(PublicKeyEntry { name, path, state });
        }
        entries.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(entries)
    }

    pub fn export_public(&self, entry: &KeyEntry, destination: &Path) -> Result<()> {
        let recipient = self.load_recipient(entry)?;
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let mut temp = NamedTempFile::new_in(parent)?;
        writeln!(temp, "# engage PQ public key: {}", entry.name)?;
        writeln!(temp, "{recipient}")?;
        temp.as_file_mut().sync_all()?;
        temp.persist(destination).map_err(|error| error.error)?;
        Ok(())
    }

    pub fn import_public(&self, source: &Path) -> Result<PublicKeyEntry> {
        let recipient = Self::read_recipient(source)?;
        let name = source
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| message("public key file has no valid basename"))?;
        validate_key_name(name)?;
        let root = self.public_root();
        let destination = root.join(format!("{name}.{PUBLIC_KEY_EXTENSION}"));
        if destination.exists() {
            return Err(message(format!("public key already exists: {name}")));
        }
        let mut temp = NamedTempFile::new_in(&root)?;
        writeln!(temp, "# imported from: {}", source.display())?;
        writeln!(temp, "{recipient}")?;
        temp.as_file_mut().sync_all()?;
        temp.persist_noclobber(&destination)
            .map_err(|error| error.error)?;
        Ok(PublicKeyEntry {
            name: name.to_owned(),
            path: destination,
            state: KeyState::Valid {
                recipient: recipient.to_string(),
            },
        })
    }

    pub fn delete(&self, entry: &KeyEntry) -> Result<()> {
        if entry.path.parent() != Some(self.root.as_path())
            || !entry
                .path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case(KEY_EXTENSION))
        {
            return Err(message("refusing to delete a key outside the key store"));
        }
        fs::remove_file(&entry.path)?;
        Ok(())
    }

    pub fn delete_public(&self, entry: &PublicKeyEntry) -> Result<()> {
        if entry.path.parent() != Some(self.public_root().as_path())
            || !entry
                .path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case(PUBLIC_KEY_EXTENSION))
        {
            return Err(message(
                "refusing to delete a public key outside the public key store",
            ));
        }
        fs::remove_file(&entry.path)?;
        Ok(())
    }

    pub fn load_identity(&self, entry: &KeyEntry) -> Result<HybridIdentity> {
        if !matches!(entry.state, KeyState::Valid { .. }) {
            return Err(message(format!("key is invalid: {}", entry.name)));
        }
        Self::read_identity(&entry.path)
    }

    pub fn load_recipient(&self, entry: &KeyEntry) -> Result<HybridRecipient> {
        self.load_identity(entry)?.to_public()
    }

    pub fn load_public_recipient(&self, entry: &PublicKeyEntry) -> Result<HybridRecipient> {
        if !matches!(entry.state, KeyState::Valid { .. }) {
            return Err(message(format!("public key is invalid: {}", entry.name)));
        }
        Self::read_recipient(&entry.path)
    }

    fn read_identity(path: &Path) -> Result<HybridIdentity> {
        let text = fs::read_to_string(path)?;
        let secret = text
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("AGE-SECRET-KEY-PQ-"))
            .ok_or_else(|| message("file has no PQ identity"))?;
        HybridIdentity::parse(secret)
    }

    fn read_recipient(path: &Path) -> Result<HybridRecipient> {
        let text = fs::read_to_string(path)?;
        let recipient = text
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("age1pq"))
            .ok_or_else(|| message("file has no PQ public key"))?;
        HybridRecipient::parse(recipient)
    }
}

fn validate_key_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed != name
        || matches!(name, "." | "..")
        || name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'])
        || name.ends_with([' ', '.'])
        || name.len() > 120
    {
        return Err(message("invalid key name"));
    }
    let base = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    let reserved = matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'));
    if reserved {
        return Err(message("key name is reserved by Windows"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_scan_load_and_delete() {
        let temp = tempfile::tempdir().unwrap();
        let store = KeyStore::new(temp.path()).unwrap();
        let generated = store.generate("primary").unwrap();
        assert!(generated.path.ends_with("primary.agekey"));
        let entries = store.scan().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].state, KeyState::Valid { .. }));
        store.load_recipient(&entries[0]).unwrap();
        store.delete(&entries[0]).unwrap();
        assert!(store.scan().unwrap().is_empty());
    }

    #[test]
    fn invalid_key_is_visible_and_reserved_names_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let store = KeyStore::new(temp.path()).unwrap();
        fs::write(temp.path().join("broken.agekey"), "not a key").unwrap();
        let entries = store.scan().unwrap();
        assert!(matches!(entries[0].state, KeyState::Invalid { .. }));
        assert!(store.generate("CON").is_err());
        assert!(store.generate("../escape").is_err());
    }

    #[test]
    fn delete_rejects_outside_paths() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let store = KeyStore::new(temp.path()).unwrap();
        let entry = KeyEntry {
            name: "outside".into(),
            path: outside.path().join("outside.agekey"),
            state: KeyState::Invalid {
                reason: "test".into(),
            },
        };
        fs::File::create(&entry.path).unwrap();
        assert!(store.delete(&entry).is_err());
        assert!(entry.path.exists());
    }

    #[test]
    fn exported_public_key_can_be_imported_and_loaded() {
        let private_root = tempfile::tempdir().unwrap();
        let import_root = tempfile::tempdir().unwrap();
        let export_root = tempfile::tempdir().unwrap();
        let private_store = KeyStore::new(private_root.path()).unwrap();
        let import_store = KeyStore::new(import_root.path()).unwrap();
        let private = private_store.generate("primary").unwrap();
        let expected = private_store.load_recipient(&private).unwrap().to_string();
        let exported = export_root.path().join("shared.agepub");

        private_store.export_public(&private, &exported).unwrap();
        let imported = import_store.import_public(&exported).unwrap();

        assert_eq!(imported.name, "shared");
        assert!(imported.path.ends_with("public/shared.agepub"));
        assert_eq!(
            import_store
                .load_public_recipient(&imported)
                .unwrap()
                .to_string(),
            expected
        );
        assert_eq!(import_store.scan_public().unwrap().len(), 1);
        import_store.delete_public(&imported).unwrap();
        assert!(import_store.scan_public().unwrap().is_empty());
    }
}
