# `.engage` container format (version 1)

All integers are little-endian. Paths in the archive are UTF-8, relative, and use `/` separators.

## Layout

```text
age(tar | seekable-zstd(level=9, frame=2 MiB, checksum))
metadata skippable frame 0
...
metadata skippable frame N
```

The body is one seekable age stream. The tar byte stream is compressed into independent seekable
zstd frames before it is encrypted. File records store the offset and length of their payload in the
uncompressed tar stream, so extraction seeks directly to the required zstd frames and age chunks.

Metadata is a fixed-page B-tree (64 KiB pages), compressed with seekable zstd and encrypted as a
second age stream. It is split over one or more zstd skippable frames. The logical ciphertext length
and segment lengths are 64-bit, so the metadata stream is not limited to 4 GiB even though each
individual skippable frame has a 32-bit payload length.

## Metadata skippable frame

Each physical frame is:

```text
u32 magic = 0x184D2A5D
u32 payload_size = ciphertext_segment_size + 48
u8  ciphertext_segment[ciphertext_segment_size]
u8  trailer[48]
```

Trailer fields:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `ENGMETA1` |
| 8 | 2 | version (`1`) |
| 10 | 2 | flags (`FIRST = 1`, `LAST = 2`) |
| 12 | 4 | zero-based segment index |
| 16 | 8 | ciphertext bytes in this segment |
| 24 | 8 | total logical metadata ciphertext bytes |
| 32 | 8 | encrypted body bytes |
| 40 | 4 | previous complete physical frame size, or zero |
| 44 | 4 | CRC-32 of trailer bytes 0..44 |

Readers start at EOF and follow trailers backward until `FIRST`, then expose all ciphertext segments
as one seekable logical stream. Every segment must agree on the body length and total ciphertext
length.

## Index pages

Page 0 is the superblock. Remaining pages form a B-tree ordered by `(parent_entry_id, name)`.
Leaf records contain entry ID, parent ID, kind, name, tar payload offset, size, timestamps,
permissions, BLAKE3 content hash, and optional symlink target. Each page has its own CRC-32.

Archive creation uses bounded-memory external sorting, so metadata size does not need to fit in RAM.
Readers decompress pages lazily and keep a bounded page cache.

## Credentials

An archive uses exactly one credential mode:

- age scrypt passphrase; or
- hybrid ML-KEM-768 + X25519 recipients encoded as `age1pq` and
  `AGE-SECRET-KEY-PQ-1`.

The hybrid recipient adapter is based on `Slurp9187/age-pq-workspace` commit
`966d530d33dec94f171634d78b6aa5c97eea89bc`. That implementation has not been independently
audited.
