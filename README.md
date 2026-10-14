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


MIT License.
