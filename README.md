# Digital Forensics Toolkit

A simple tool for learning digital forensics, built with **C and Python**. It helps check file integrity, track file activity, extract metadata, and detect suspicious login attempts.

## Features

| Module | Language | Description |
|---|---|---|
| `hasher` | C | Creates SHA-256 hashes to check file integrity. |
| `timeline` | C | Tracks when files were modified, accessed, or changed. |
| `metadata_extractor.py` | Python | Extracts image and PDF metadata, including dates and GPS data. |
| `log_analyzer.py` | Python | Analyzes SSH logs to detect suspicious login activity. |
| `forensics.py` | Python | Combines all tools into one command-line interface. |

The SHA-256 hashing code is built into the project, so no external cryptography library is needed.

## Requirements

- GCC or another C compiler
- Python 3.8+
- Pillow and pypdf for metadata extraction

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/forensics-toolkit.git
cd forensics-toolkit

cd src
make
cd ..

pip install -r requirements.txt
```

## Usage

```bash
# Hash files
python3 forensics.py hash /path/to/evidence hashes.csv

# Create a file timeline
python3 forensics.py timeline /path/to/evidence timeline.csv

# Extract metadata
python3 forensics.py metadata /path/to/evidence --output metadata.json

# Analyze SSH logs
python3 forensics.py logs /var/log/auth.log --threshold 5

# Run all main checks
python3 forensics.py full /path/to/evidence --outdir ./report
```

## How It Works

- **Hashing:** Generates file hashes to help identify changes or tampering.
- **Timeline:** Records file timestamps to help reconstruct activity.
- **Metadata:** Extracts information stored in images and PDFs.
- **Log analysis:** Flags repeated failed logins, suspicious successful logins, root login attempts, and possible distributed attacks.

## Limitations

This is an educational project, not a professional forensic solution. It does not support disk recovery, deleted files, memory analysis, or legally compliant evidence handling.

Only analyze files and logs you have permission to access.

## Future Improvements

- Compare hashes to detect file changes.
- Support Windows security logs.
- Create interactive timelines.
- Detect file types using file signatures.
- Support web server logs.
*Done by Michael hell ye*
## License

MIT License.
