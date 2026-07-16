use std::fs;

use age::secrecy::SecretString;
use engage::{
    Archive, CancellationToken, ConflictKind, CreateOptions, DecryptCredential, EncryptCredential,
    ExtractOptions, OperationProgress, OperationStage, Selection, create_archive,
    create_archive_controlled, create_archive_with_progress, generate_pq_keypair,
};

const PASSWORD: &str = "correct horse battery staple";

fn encrypt_credential() -> EncryptCredential {
    EncryptCredential::Passphrase(SecretString::from(PASSWORD))
}

fn decrypt_credential() -> DecryptCredential {
    DecryptCredential::Passphrase(SecretString::from(PASSWORD))
}

#[test]
fn creation_pipelines_scanning_and_switches_to_determinate_archiving_progress() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("progress-input");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("first.txt"), b"first").unwrap();
    fs::write(input.join("second.txt"), b"second payload").unwrap();
    let archive_path = temp.path().join("progress.engage");
    let cancellation = CancellationToken::new();
    let mut snapshots = Vec::<OperationProgress>::new();

    create_archive_with_progress(
        vec![input],
        &archive_path,
        &encrypt_credential(),
        CreateOptions::default(),
        false,
        &cancellation,
        &mut |progress| snapshots.push(progress),
    )
    .unwrap();

    let stages = snapshots
        .iter()
        .map(|item| item.stage)
        .fold(Vec::new(), |mut stages, stage| {
            if stages.last() != Some(&stage) {
                stages.push(stage);
            }
            stages
        });
    assert_eq!(
        stages,
        vec![
            OperationStage::Scanning,
            OperationStage::Archiving,
            OperationStage::BuildingIndex,
            OperationStage::WritingIndex,
            OperationStage::Finalizing,
            OperationStage::Complete,
        ]
    );
    let archiving = snapshots
        .iter()
        .find(|item| item.stage == OperationStage::Archiving)
        .unwrap();
    assert_eq!(archiving.entries_total, None);
    assert_eq!(archiving.bytes_total, None);
    let determinate_archiving = snapshots
        .iter()
        .find(|item| {
            item.stage == OperationStage::Archiving
                && item.entries_total == Some(3)
                && item.bytes_total == Some(19)
        })
        .expect("scanner totals should make archiving determinate");
    assert!(determinate_archiving.entries_done < 3 || determinate_archiving.bytes_done < 19);

    let index_progress = snapshots
        .iter()
        .filter(|item| item.stage == OperationStage::BuildingIndex)
        .collect::<Vec<_>>();
    assert_eq!(index_progress.first().unwrap().entries_total, Some(6));
    assert_eq!(index_progress.last().unwrap().entries_done, 6);

    let complete = snapshots.last().unwrap();
    assert_eq!(complete.stage, OperationStage::Complete);
    assert_eq!(complete.entries_done, 3);
    assert_eq!(complete.bytes_done, 19);
    assert_eq!(complete.entries_total, Some(3));
    assert_eq!(complete.bytes_total, Some(19));
}

#[test]
fn archive_encrypted_for_multiple_pq_recipients_opens_with_either_identity() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("shared.txt");
    fs::write(&input, b"shared with two recipients").unwrap();
    let archive_path = temp.path().join("shared.engage");
    let (first_recipient, first_identity) = generate_pq_keypair().unwrap();
    let (second_recipient, second_identity) = generate_pq_keypair().unwrap();

    create_archive(
        vec![input],
        &archive_path,
        &EncryptCredential::PostQuantumRecipients(vec![first_recipient, second_recipient]),
        CreateOptions::default(),
    )
    .unwrap();

    for identity in [first_identity, second_identity] {
        let mut archive = Archive::open(
            &archive_path,
            DecryptCredential::PostQuantum(identity),
            64 * 1024,
        )
        .unwrap();
        assert_eq!(archive.list_children(0, None, 10).unwrap().entries.len(), 1);
    }
}

#[test]
fn multiple_inputs_and_partial_extraction_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let inputs = temp.path().join("inputs");
    fs::create_dir_all(inputs.join("tree/nested")).unwrap();
    fs::write(inputs.join("tree/nested/selected.txt"), b"selected payload").unwrap();
    fs::write(inputs.join("tree/nested/other.txt"), b"must stay archived").unwrap();
    fs::write(inputs.join("single.bin"), (0..=255).collect::<Vec<_>>()).unwrap();

    let archive_path = temp.path().join("sample.engage");
    create_archive(
        vec![inputs.join("tree"), inputs.join("single.bin")],
        &archive_path,
        &encrypt_credential(),
        CreateOptions {
            sort_memory_bytes: 128 * 1024,
            // Force metadata to span many skippable frames.
            metadata_segment_bytes: 128,
            compression_threads: None,
        },
    )
    .unwrap();

    let mut archive = Archive::open(&archive_path, decrypt_credential(), 64 * 1024).unwrap();
    let selected = archive.lookup("tree/nested/selected.txt").unwrap().unwrap();
    assert_eq!(selected.size, 16);

    let output = temp.path().join("partial");
    archive
        .extract(
            &output,
            Selection::Paths(vec!["tree/nested/selected.txt".into()]),
            ExtractOptions::default(),
        )
        .unwrap();
    assert_eq!(
        fs::read(output.join("tree/nested/selected.txt")).unwrap(),
        b"selected payload"
    );
    assert!(!output.join("tree/nested/other.txt").exists());
    assert!(!output.join("single.bin").exists());

    // Refuse overwrite is the default and is checked before extracting data.
    assert!(
        archive
            .extract(
                &output,
                Selection::Paths(vec!["tree/nested/selected.txt".into()]),
                ExtractOptions::default(),
            )
            .is_err()
    );
}

#[test]
fn multi_frame_archive_created_with_parallel_compression_round_trips() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("parallel.bin");
    let contents = (0..5 * 1024 * 1024 + 137)
        .map(|index| ((index * 17 + index / 97) % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(&input, &contents).unwrap();
    let archive_path = temp.path().join("parallel.engage");

    create_archive(
        vec![input],
        &archive_path,
        &encrypt_credential(),
        CreateOptions {
            compression_threads: Some(4),
            ..CreateOptions::default()
        },
    )
    .unwrap();

    let mut archive = Archive::open(&archive_path, decrypt_credential(), 64 * 1024).unwrap();
    let output = temp.path().join("parallel-output");
    archive
        .extract(&output, Selection::All, ExtractOptions::default())
        .unwrap();
    assert_eq!(fs::read(output.join("parallel.bin")).unwrap(), contents);
}

#[test]
fn zero_compression_threads_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input.txt");
    fs::write(&input, b"input").unwrap();
    let archive_path = temp.path().join("invalid.engage");
    let error = create_archive(
        vec![input],
        &archive_path,
        &encrypt_credential(),
        CreateOptions {
            compression_threads: Some(0),
            ..CreateOptions::default()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("at least one"));
    assert!(!archive_path.exists());
}

#[test]
fn a_listed_entry_id_can_be_extracted() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("only.txt");
    fs::write(&input, b"entry by id").unwrap();
    let archive_path = temp.path().join("id.engage");
    create_archive(
        vec![input],
        &archive_path,
        &encrypt_credential(),
        CreateOptions::default(),
    )
    .unwrap();

    let mut archive = Archive::open(&archive_path, decrypt_credential(), 64 * 1024).unwrap();
    let page = archive.list_children(0, None, 1).unwrap();
    let id = page.entries[0].id;
    let output = temp.path().join("by-id");
    archive
        .extract(
            &output,
            Selection::EntryIds(vec![id]),
            ExtractOptions::default(),
        )
        .unwrap();
    assert_eq!(fs::read(output.join("only.txt")).unwrap(), b"entry by id");
}

#[test]
fn selected_directory_can_be_extracted_without_archive_ancestors() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input");
    fs::create_dir_all(input.join("tree/nested")).unwrap();
    fs::write(input.join("tree/nested/file.txt"), b"direct output").unwrap();
    let archive_path = temp.path().join("direct.engage");
    create_archive(
        vec![input.join("tree")],
        &archive_path,
        &encrypt_credential(),
        CreateOptions::default(),
    )
    .unwrap();

    let mut archive = Archive::open(&archive_path, decrypt_credential(), 64 * 1024).unwrap();
    let root = archive.list_children(0, None, 16).unwrap();
    let tree_id = root
        .entries
        .iter()
        .find(|entry| entry.name == "tree")
        .unwrap()
        .id;
    let tree = archive.list_children(tree_id, None, 16).unwrap();
    let nested_id = tree
        .entries
        .iter()
        .find(|entry| entry.name == "nested")
        .unwrap()
        .id;
    let output = temp.path().join("direct-output");
    let options = ExtractOptions {
        preserve_hierarchy: false,
        ..ExtractOptions::default()
    };

    assert!(
        archive
            .plan_extraction_with_options(&output, Selection::EntryIds(vec![nested_id]), &options,)
            .unwrap()
            .is_empty()
    );
    archive
        .extract(&output, Selection::EntryIds(vec![nested_id]), options)
        .unwrap();

    assert_eq!(
        fs::read(output.join("nested/file.txt")).unwrap(),
        b"direct output"
    );
    assert!(!output.join("tree").exists());
}

#[test]
fn cancelled_creation_does_not_publish_an_archive() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("cancel.txt");
    fs::write(&input, b"do not publish").unwrap();
    let archive_path = temp.path().join("cancelled.engage");
    let cancellation = CancellationToken::new();
    cancellation.cancel();

    let error = create_archive_controlled(
        vec![input],
        &archive_path,
        &encrypt_credential(),
        CreateOptions::default(),
        false,
        &cancellation,
    )
    .unwrap_err();

    assert!(error.to_string().contains("operation cancelled"));
    assert!(!archive_path.exists());
}

#[test]
fn cancellation_after_staging_removes_temporary_archive() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("cancel-after-staging.txt");
    fs::write(&input, vec![0x5a; 1024 * 1024]).unwrap();
    let archive_path = temp.path().join("cancel-after-staging.engage");
    let cancellation = CancellationToken::new();
    let cancel_from_progress = cancellation.clone();
    let mut reporter = move |progress: engage::OperationProgress| {
        if progress.stage == engage::OperationStage::Archiving {
            cancel_from_progress.cancel();
        }
    };

    let error = engage::create_archive_with_progress(
        vec![input.clone()],
        &archive_path,
        &encrypt_credential(),
        CreateOptions::default(),
        false,
        &cancellation,
        &mut reporter,
    )
    .unwrap_err();

    assert!(error.to_string().contains("operation cancelled"));
    assert!(!archive_path.exists());
    let remaining = fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(remaining, vec![input]);
}

#[test]
fn cancellation_with_parallel_frames_removes_temporary_archive() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("cancel-parallel.bin");
    fs::write(&input, vec![0x5a; 6 * 1024 * 1024]).unwrap();
    let archive_path = temp.path().join("cancel-parallel.engage");
    let cancellation = CancellationToken::new();
    let cancel_from_progress = cancellation.clone();
    let mut reporter = move |progress: engage::OperationProgress| {
        if progress.stage == engage::OperationStage::Archiving
            && progress.bytes_done >= 3 * 1024 * 1024
        {
            cancel_from_progress.cancel();
        }
    };

    let error = engage::create_archive_with_progress(
        vec![input.clone()],
        &archive_path,
        &encrypt_credential(),
        CreateOptions {
            compression_threads: Some(4),
            ..CreateOptions::default()
        },
        false,
        &cancellation,
        &mut reporter,
    )
    .unwrap_err();

    assert!(error.to_string().contains("operation cancelled"));
    assert!(!archive_path.exists());
    let remaining = fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(remaining, vec![input]);
}

#[test]
fn extraction_conflicts_are_reported_before_writing() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("existing.txt");
    fs::write(&input, b"archived").unwrap();
    let archive_path = temp.path().join("conflict.engage");
    create_archive(
        vec![input],
        &archive_path,
        &encrypt_credential(),
        CreateOptions::default(),
    )
    .unwrap();

    let mut archive = Archive::open(&archive_path, decrypt_credential(), 64 * 1024).unwrap();
    let output = temp.path().join("conflicts");
    fs::create_dir_all(&output).unwrap();
    fs::write(output.join("existing.txt"), b"keep until confirmed").unwrap();

    let conflicts = archive.plan_extraction(&output, Selection::All).unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].kind, ConflictKind::ReplaceableFile);
    assert_eq!(
        fs::read(output.join("existing.txt")).unwrap(),
        b"keep until confirmed"
    );
}

#[test]
fn output_inside_input_excludes_internal_and_previous_archives() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("keep.txt"), b"keep me").unwrap();
    let archive_path = input.join("inside.engage");

    create_archive(
        vec![input.clone()],
        &archive_path,
        &encrypt_credential(),
        CreateOptions::default(),
    )
    .unwrap();
    create_archive_controlled(
        vec![input.clone()],
        &archive_path,
        &encrypt_credential(),
        CreateOptions::default(),
        true,
        &CancellationToken::new(),
    )
    .unwrap();

    let mut archive = Archive::open(&archive_path, decrypt_credential(), 64 * 1024).unwrap();
    let root = archive.list_children(0, None, 16).unwrap();
    assert_eq!(root.entries.len(), 1);
    let children = archive.list_children(root.entries[0].id, None, 16).unwrap();
    assert_eq!(
        children
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["keep.txt"]
    );
}

#[test]
fn symlink_ancestor_cannot_create_directories_outside_output() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input");
    fs::create_dir_all(input.join("a/b")).unwrap();
    fs::write(input.join("a/b/file.txt"), b"contained").unwrap();
    let archive_path = temp.path().join("links.engage");
    create_archive(
        vec![input.join("a")],
        &archive_path,
        &encrypt_credential(),
        CreateOptions::default(),
    )
    .unwrap();

    let output = temp.path().join("output");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&output).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let link = output.join("a");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    #[cfg(windows)]
    if let Err(error) = std::os::windows::fs::symlink_dir(&outside, &link) {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return;
        }
        panic!("failed to create test symlink: {error}");
    }

    let mut archive = Archive::open(&archive_path, decrypt_credential(), 64 * 1024).unwrap();
    assert!(
        archive
            .extract(
                &output,
                Selection::Paths(vec!["a/b/file.txt".into()]),
                ExtractOptions::default(),
            )
            .is_err()
    );
    assert!(!outside.join("b").exists());
}
