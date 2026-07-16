use std::{
    fs::{self, OpenOptions},
    io::Write,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::ExitCode,
};

use age::secrecy::{ExposeSecret, SecretString};
use clap::{Args, Parser, Subcommand};
use engage::{
    Archive, CreateOptions, DecryptCredential, EncryptCredential, EntryId, EntryKind,
    ExtractOptions, HybridIdentity, HybridRecipient, OverwritePolicy, Selection, create_archive,
    generate_pq_keypair,
};

#[derive(Parser)]
#[command(version, about = "Seekable encrypted archives")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen(Keygen),
    Create(Create),
    List(List),
    Extract(Extract),
}

#[derive(Args)]
struct Keygen {
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Args)]
struct Create {
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
    #[arg(short, long)]
    output: PathBuf,
    #[arg(
        long,
        value_name = "AGE1PQ_RECIPIENT",
        action = clap::ArgAction::Append,
        conflicts_with = "passphrase",
        help = "PQ recipient; repeat this option to encrypt for multiple recipients"
    )]
    recipient: Vec<String>,
    #[arg(long, conflicts_with = "recipient")]
    passphrase: bool,
    #[arg(
        long,
        value_name = "N",
        help = "Maximum compression workers; defaults to min(5, available CPUs minus one)"
    )]
    threads: Option<NonZeroUsize>,
}

#[derive(Args)]
struct Unlock {
    #[arg(long, conflicts_with = "passphrase")]
    identity: Option<PathBuf>,
    #[arg(long, conflicts_with = "identity")]
    passphrase: bool,
}

#[derive(Args)]
struct List {
    archive: PathBuf,
    #[command(flatten)]
    unlock: Unlock,
    #[arg(long)]
    path: Option<String>,
    #[arg(short, long)]
    recursive: bool,
}

#[derive(Args)]
struct Extract {
    archive: PathBuf,
    #[arg(short, long)]
    output: PathBuf,
    #[command(flatten)]
    unlock: Unlock,
    #[arg(long, conflicts_with = "paths")]
    all: bool,
    #[arg(long = "path", value_name = "ARCHIVE_PATH")]
    paths: Vec<String>,
    #[arg(long)]
    overwrite: bool,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("engage: {error:#?}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> engage::Result<()> {
    match cli.command {
        Command::Keygen(args) => keygen(args),
        Command::Create(args) => create(args),
        Command::List(args) => list(args),
        Command::Extract(args) => extract(args),
    }
}

fn keygen(args: Keygen) -> engage::Result<()> {
    let (recipient, identity) = generate_pq_keypair()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    writeln!(file, "# public key: {recipient}")?;
    writeln!(file, "{}", identity.to_secret_string().expose_secret())?;
    file.sync_all()?;
    eprintln!("Public key: {recipient}");
    Ok(())
}

fn create(args: Create) -> engage::Result<()> {
    let credential = if !args.recipient.is_empty() {
        EncryptCredential::PostQuantumRecipients(
            args.recipient
                .iter()
                .map(|recipient| HybridRecipient::parse(recipient))
                .collect::<engage::Result<Vec<_>>>()?,
        )
    } else if args.passphrase {
        let first = rpassword::prompt_password("Passphrase: ")?;
        let second = rpassword::prompt_password("Confirm passphrase: ")?;
        if first != second {
            eros::bail!("passphrases do not match");
        }
        EncryptCredential::Passphrase(SecretString::from(first))
    } else {
        eros::bail!("specify either --recipient or --passphrase");
    };
    create_archive(
        args.inputs,
        args.output,
        &credential,
        CreateOptions {
            compression_threads: args.threads.map(NonZeroUsize::get),
            ..CreateOptions::default()
        },
    )
}

fn unlock(args: Unlock) -> engage::Result<DecryptCredential> {
    if let Some(path) = args.identity {
        let text = fs::read_to_string(path)?;
        let identity = text
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("AGE-SECRET-KEY-PQ-"))
            .ok_or_else(|| eros::error!("identity file has no PQ identity"))?;
        Ok(DecryptCredential::PostQuantum(HybridIdentity::parse(
            identity,
        )?))
    } else if args.passphrase {
        Ok(DecryptCredential::Passphrase(SecretString::from(
            rpassword::prompt_password("Passphrase: ")?,
        )))
    } else {
        Err(eros::error!("specify either --identity or --passphrase"))
    }
}

fn list(args: List) -> engage::Result<()> {
    let credential = unlock(args.unlock)?;
    let mut archive = Archive::open(args.archive, credential, 32 * 1024 * 1024)?;
    let (parent, prefix) = if let Some(path) = args.path {
        let entry = archive
            .lookup(&path)?
            .ok_or_else(|| eros::error!("archive entry not found: {path}"))?;
        if entry.kind != EntryKind::Directory {
            println!("{}\t{}\t{}", kind_name(entry.kind), entry.size, path);
            return Ok(());
        }
        (entry.id, PathBuf::from(path))
    } else {
        (0, PathBuf::new())
    };
    print_children(&mut archive, parent, &prefix, args.recursive)
}

fn print_children(
    archive: &mut Archive,
    parent: EntryId,
    prefix: &Path,
    recursive: bool,
) -> engage::Result<()> {
    let mut cursor = None;
    loop {
        let page = archive.list_children(parent, cursor, 1024)?;
        for entry in page.entries {
            let path = prefix.join(&entry.name);
            println!(
                "{}\t{}\t{}",
                kind_name(entry.kind),
                entry.size,
                path.to_string_lossy().replace('\\', "/")
            );
            if recursive && entry.kind == EntryKind::Directory {
                print_children(archive, entry.id, &path, true)?;
            }
        }
        cursor = page.next;
        if cursor.is_none() {
            return Ok(());
        }
    }
}

fn extract(args: Extract) -> engage::Result<()> {
    if !args.all && args.paths.is_empty() {
        eros::bail!("specify --all or at least one --path");
    }
    let credential = unlock(args.unlock)?;
    let mut archive = Archive::open(args.archive, credential, 32 * 1024 * 1024)?;
    archive.extract(
        args.output,
        if args.all {
            Selection::All
        } else {
            Selection::Paths(args.paths)
        },
        ExtractOptions {
            overwrite: if args.overwrite {
                OverwritePolicy::ReplaceFiles
            } else {
                OverwritePolicy::Refuse
            },
            preserve_hierarchy: true,
        },
    )
}

fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Directory => "dir",
        EntryKind::Symlink => "link",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_accepts_repeated_recipients() {
        let cli = Cli::try_parse_from([
            "engage-cli",
            "create",
            "--output",
            "archive.engage",
            "--recipient",
            "age1pq-first",
            "--recipient",
            "age1pq-second",
            "input.txt",
        ])
        .unwrap();

        let Command::Create(create) = cli.command else {
            panic!("expected create command");
        };
        assert_eq!(create.recipient, ["age1pq-first", "age1pq-second"]);
    }

    #[test]
    fn recipients_conflict_with_passphrase() {
        let result = Cli::try_parse_from([
            "engage-cli",
            "create",
            "--output",
            "archive.engage",
            "--recipient",
            "age1pq-recipient",
            "--passphrase",
            "input.txt",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn create_accepts_positive_compression_thread_count() {
        let cli = Cli::try_parse_from([
            "engage-cli",
            "create",
            "--output",
            "archive.engage",
            "--passphrase",
            "--threads",
            "4",
            "input.txt",
        ])
        .unwrap();
        let Command::Create(create) = cli.command else {
            panic!("expected create command");
        };
        assert_eq!(create.threads.map(NonZeroUsize::get), Some(4));
    }

    #[test]
    fn create_rejects_zero_compression_threads() {
        let result = Cli::try_parse_from([
            "engage-cli",
            "create",
            "--output",
            "archive.engage",
            "--passphrase",
            "--threads",
            "0",
            "input.txt",
        ]);
        assert!(result.is_err());
    }
}
