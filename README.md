# Digital Forensics Toolkit

A small, dependency-light toolkit for learning digital forensics fundamentals: file integrity verification, filesystem timeline reconstruction, metadata extraction, and log analysis. Built in **C** (performance-critical file operations) and **Python** (metadata parsing and analysis).

> Built as a learning project to explore concepts used in real digital forensics and incident response work — file hashing / chain of custody, MAC-time analysis, EXIF/PDF metadata, and intrusion detection heuristics.

## Features

| Module | Language | What it does |
|---|---|---|
| `hasher` | C | Computes SHA-256 hashes of files (single file or recursive directory scan) for integrity verification / chain of custody |
| `timeline` | C | Builds a filesystem timeline (MAC times: Modified / Accessed / Changed) for every file in a directory tree |
| `metadata_extractor.py` | Python | Extracts EXIF data from images (including GPS coordinates if present) and metadata from PDFs (author, creation date, producer software, etc.) |
| `log_analyzer.py` | Python | Parses SSH auth logs and flags brute-force attempts, successful logins following failed attempts, root login attempts, and distributed scanning patterns |
| `forensics.py` | Python | Unified CLI that ties everything together, including a `full` sweep command |

The SHA-256 implementation is **self-contained** (`include/sha256.h`) — no external crypto library required, so the project builds with just `gcc`.

## Requirements

- GCC (or any C compiler)
- Python 3.8+
- `pip install -r requirements.txt` (Pillow + pypdf, only needed for the metadata module)

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/forensics-toolkit.git
cd forensics-toolkit

# Build the C components
cd src
make
cd ..

# Install Python dependencies
pip install -r requirements.txt
```

## Usage

All commands can be run through the unified CLI:

```bash
cd python

# Hash a file or directory (chain of custody)
python3 forensics.py hash /path/to/evidence hashes.csv

# Build a filesystem timeline
python3 forensics.py timeline /path/to/evidence timeline.csv

# Extract metadata from images/PDFs
python3 forensics.py metadata /path/to/evidence --output metadata.json

# Analyze an auth log for intrusion patterns
python3 forensics.py logs /var/log/auth.log --threshold 5 --output log_report.json

# Run a full sweep (hash + timeline + metadata) on a directory
python3 forensics.py full /path/to/evidence --outdir ./report
```

Or run the C binaries and Python scripts directly:

```bash
./src/hasher /path/to/evidence hashes.csv
./src/timeline /path/to/evidence timeline.csv
python3 python/metadata_extractor.py /path/to/evidence --output metadata.json
python3 python/log_analyzer.py /var/log/auth.log --threshold 5
```

### Example: detecting a brute-force attempt

```bash
python3 python/forensics.py logs /var/log/auth.log
```

```
3 finding(s). Report written to log_report.json
  [brute_force_suspected] 6 failed login attempts from 203.0.113.5 (threshold: 5)
  [possible_successful_brute_force] 203.0.113.5 had 6 failed attempts before a successful login - review this session
  [root_login_attempts] 6 login attempt(s) targeting the root account
```

## Project structure

```
forensics-toolkit/
├── include/
│   └── sha256.h          # Self-contained SHA-256 implementation
├── src/
│   ├── hasher.c           # File integrity hashing (recursive)
│   ├── timeline.c         # Filesystem MAC-time timeline builder
│   └── Makefile
├── python/
│   ├── metadata_extractor.py   # EXIF / PDF metadata extraction
│   ├── log_analyzer.py         # Auth log intrusion analysis
│   └── forensics.py            # Unified CLI
├── requirements.txt
├── LICENSE
└── README.md
```

## How it works

**Hashing (`hasher.c`)** — Reads each file in 8KB chunks and feeds it through a from-scratch SHA-256 implementation following the FIPS 180-4 spec. Output is a CSV of `filepath,hash,size` that can be diffed against a later run to detect tampering.

**Timeline (`timeline.c`)** — Walks a directory recursively using `stat()`/`lstat()` and records access, modification, and change (metadata change) timestamps for every file, sorted chronologically. This is the classic "MAC time" analysis technique used to reconstruct a sequence of events on a filesystem.

**Metadata extraction (`metadata_extractor.py`)** — Uses Pillow to read EXIF tags from images (camera model, timestamps, GPS coordinates) and pypdf to read PDF document properties (author, creator software, creation/modification dates). Flags any file with embedded GPS data.

**Log analysis (`log_analyzer.py`)** — Parses OpenSSH-style auth log lines with regex, groups failed/successful login events by source IP, and applies simple heuristics: repeated failures from one IP (brute force), a success following a burst of failures (compromised credential), root-targeted attempts, and failures spread across many distinct IPs (distributed scanning).

## Limitations & disclaimer

This is an educational project, not a production forensics tool. It doesn't handle disk images, deleted file recovery, memory forensics, or chain-of-custody legal requirements. Only use the log analyzer and hashing tools on logs and files you have legitimate access to (your own systems, lab environments, or with explicit authorization).

## Possible extensions

- Compare two hash CSVs to auto-detect added/removed/modified files
- Add support for Windows Event Log parsing
- Export timeline as an interactive HTML view
- Add file carving / signature-based file type detection (magic bytes)
- Support for more log formats (nginx, Apache, Windows Security log)

## License

MIT — see [LICENSE](LICENSE).
# forensics-toolkit
