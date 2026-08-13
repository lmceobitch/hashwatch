#!/bin/bash
set -e

TARGET="/home/michael/Sublime.txt/forensics-toolkit"
mkdir -p "$TARGET"/include "$TARGET"/src "$TARGET"/python
cd "$TARGET"

cat > 'include/sha256.h' << 'SHA256_H_EOF'
/*
 * sha256.h - Minimal, self-contained SHA-256 implementation
 *
 * Public domain style implementation, adapted for this toolkit so the
 * project has zero external dependencies (no libssl-dev required).
 * Based on the standard FIPS 180-4 SHA-256 specification.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <string.h>

#define SHA256_BLOCK_SIZE 32

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX_LOCAL;

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SHA256_ROTR(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define SHA256_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_EP1(x) (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SIG0(x) (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX_LOCAL *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    for (; i < 64; ++i)
        m[i] = SHA256_SIG1(m[i-2]) + m[i-7] + SHA256_SIG0(m[i-15]) + m[i-16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + sha256_k[i] + m[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX_LOCAL *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX_LOCAL *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX_LOCAL *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            hash[i + (j * 4)] = (uint8_t)(ctx->state[j] >> (24 - i * 8));
        }
    }
}

#endif /* SHA256_H */
SHA256_H_EOF

cat > 'src/hasher.c' << 'HASHER_C_EOF'
/*
 * hasher.c - File integrity hasher for digital forensics toolkit
 *
 * Computes SHA-256 hashes of files to establish a "chain of custody"
 * baseline. Can hash a single file or recursively hash every file in
 * a directory, outputting results in a simple CSV format:
 *
 *      filepath,sha256_hash,size_bytes
 *
 * This CSV can later be compared against a fresh run to detect any
 * file that was added, removed, or modified.
 *
 * Usage:
 *   ./hasher <file_or_directory> [output.csv]
 *
 * Build:
 *   gcc -O2 -Wall -o hasher hasher.c
 *
 * Uses a self-contained SHA-256 implementation (include/sha256.h) so
 * the project has no external dependencies like libssl-dev.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../include/sha256.h"

#define PATH_MAX_LEN 4096
#define READ_BUF_SIZE 8192

/* Computes the SHA-256 hash of a file and writes it as a hex string
 * into out_hex (must be at least 65 bytes). Returns 0 on success. */
static int hash_file(const char *filepath, char *out_hex, long *out_size) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        return -1;
    }

    SHA256_CTX_LOCAL ctx;
    sha256_init(&ctx);

    unsigned char buf[READ_BUF_SIZE];
    size_t bytes_read;
    long total_size = 0;

    while ((bytes_read = fread(buf, 1, READ_BUF_SIZE, fp)) > 0) {
        sha256_update(&ctx, buf, bytes_read);
        total_size += (long)bytes_read;
    }

    unsigned char digest[SHA256_BLOCK_SIZE];
    sha256_final(&ctx, digest);
    fclose(fp);

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        sprintf(out_hex + (i * 2), "%02x", digest[i]);
    }
    out_hex[64] = '\0';

    *out_size = total_size;
    return 0;
}

/* Recursively walks a directory, hashing every regular file found.
 * Writes one CSV line per file to the output stream. */
static void walk_directory(const char *dirpath, FILE *out) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "Warning: could not open directory %s\n", dirpath);
        return;
    }

    struct dirent *entry;
    char full_path[PATH_MAX_LEN];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            walk_directory(full_path, out);
        } else if (S_ISREG(st.st_mode)) {
            char hex_hash[65];
            long size;
            if (hash_file(full_path, hex_hash, &size) == 0) {
                fprintf(out, "%s,%s,%ld\n", full_path, hex_hash, size);
                printf("Hashed: %s\n", full_path);
            } else {
                fprintf(stderr, "Warning: could not read %s\n", full_path);
            }
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file_or_directory> [output.csv]\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    const char *output_path = (argc >= 3) ? argv[2] : "hashes.csv";

    FILE *out = fopen(output_path, "w");
    if (!out) {
        fprintf(stderr, "Error: could not open output file %s\n", output_path);
        return 1;
    }

    fprintf(out, "filepath,sha256_hash,size_bytes\n");

    struct stat st;
    if (stat(target, &st) != 0) {
        fprintf(stderr, "Error: cannot access %s\n", target);
        fclose(out);
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        walk_directory(target, out);
    } else if (S_ISREG(st.st_mode)) {
        char hex_hash[65];
        long size;
        if (hash_file(target, hex_hash, &size) == 0) {
            fprintf(out, "%s,%s,%ld\n", target, hex_hash, size);
            printf("Hashed: %s\n", target);
        } else {
            fprintf(stderr, "Error: could not read %s\n", target);
        }
    }

    fclose(out);
    printf("\nDone. Results written to %s\n", output_path);
    return 0;
}
HASHER_C_EOF

cat > 'src/timeline.c' << 'TIMELINE_C_EOF'
/*
 * timeline.c - Filesystem timeline builder for digital forensics toolkit
 *
 * Recursively scans a directory and records, for every file:
 *   - path
 *   - size in bytes
 *   - last access time (atime)
 *   - last modification time (mtime)
 *   - last status change time (ctime) - metadata change, not "creation"
 *     on Linux (Linux ext4 has no portable creation time via stat())
 *
 * Output is a CSV sorted by modification time, which is the classic
 * "MAC time" (Modified/Accessed/Changed) timeline used in forensics
 * to reconstruct what happened on a system and when.
 *
 * Usage:
 *   ./timeline <directory> [output.csv]
 *
 * Build:
 *   gcc -O2 -Wall -o timeline timeline.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

#define PATH_MAX_LEN 4096
#define MAX_ENTRIES 100000

typedef struct {
    char path[PATH_MAX_LEN];
    long size;
    time_t atime;
    time_t mtime;
    time_t ctime;
} FileRecord;

static FileRecord *records;
static int record_count = 0;

static void format_time(time_t t, char *buf, size_t buflen) {
    struct tm *tm_info = localtime(&t);
    strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", tm_info);
}

static int compare_by_mtime(const void *a, const void *b) {
    const FileRecord *fa = (const FileRecord *)a;
    const FileRecord *fb = (const FileRecord *)b;
    if (fa->mtime < fb->mtime) return -1;
    if (fa->mtime > fb->mtime) return 1;
    return 0;
}

static void walk_directory(const char *dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "Warning: could not open directory %s\n", dirpath);
        return;
    }

    struct dirent *entry;
    char full_path[PATH_MAX_LEN];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);

        struct stat st;
        if (lstat(full_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            walk_directory(full_path);
        } else if (S_ISREG(st.st_mode)) {
            if (record_count >= MAX_ENTRIES) {
                fprintf(stderr, "Warning: max entries reached, skipping remaining files\n");
                continue;
            }
            FileRecord *rec = &records[record_count++];
            strncpy(rec->path, full_path, PATH_MAX_LEN - 1);
            rec->path[PATH_MAX_LEN - 1] = '\0';
            rec->size = (long)st.st_size;
            rec->atime = st.st_atime;
            rec->mtime = st.st_mtime;
            rec->ctime = st.st_ctime;
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory> [output.csv]\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    const char *output_path = (argc >= 3) ? argv[2] : "timeline.csv";

    records = malloc(sizeof(FileRecord) * MAX_ENTRIES);
    if (!records) {
        fprintf(stderr, "Error: memory allocation failed\n");
        return 1;
    }

    struct stat st;
    if (stat(target, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: %s is not a valid directory\n", target);
        free(records);
        return 1;
    }

    printf("Scanning %s ...\n", target);
    walk_directory(target);
    printf("Found %d files. Sorting by modification time...\n", record_count);

    qsort(records, record_count, sizeof(FileRecord), compare_by_mtime);

    FILE *out = fopen(output_path, "w");
    if (!out) {
        fprintf(stderr, "Error: could not open output file %s\n", output_path);
        free(records);
        return 1;
    }

    fprintf(out, "path,size_bytes,accessed,modified,changed\n");

    char abuf[32], mbuf[32], cbuf[32];
    for (int i = 0; i < record_count; i++) {
        format_time(records[i].atime, abuf, sizeof(abuf));
        format_time(records[i].mtime, mbuf, sizeof(mbuf));
        format_time(records[i].ctime, cbuf, sizeof(cbuf));
        fprintf(out, "\"%s\",%ld,%s,%s,%s\n",
                records[i].path, records[i].size, abuf, mbuf, cbuf);
    }

    fclose(out);
    free(records);

    printf("Done. Timeline written to %s\n", output_path);
    return 0;
}
TIMELINE_C_EOF

cat > 'src/Makefile' << 'MAKEFILE_EOF'
CC = gcc
CFLAGS = -O2 -Wall -Wextra

all: hasher timeline

hasher: hasher.c ../include/sha256.h
	$(CC) $(CFLAGS) -o hasher hasher.c

timeline: timeline.c
	$(CC) $(CFLAGS) -o timeline timeline.c

clean:
	rm -f hasher timeline

.PHONY: all clean
MAKEFILE_EOF

cat > 'python/metadata_extractor.py' << 'METADATA_PY_EOF'
"""
metadata_extractor.py - Metadata extraction for digital forensics toolkit

Extracts embedded metadata from common file types:
  - Images (JPEG, PNG, TIFF, etc.) via EXIF data - can reveal camera
    model, GPS coordinates, timestamps, software used to edit, etc.
  - PDF documents - author, creation/modification dates, producer
    software, and other embedded document properties.

This kind of metadata is a classic first step in digital forensics:
it can place a device at a location, reveal what software created or
touched a file, and expose timestamps that don't match the file's
filesystem timestamps (a common red flag).

Usage:
    python3 metadata_extractor.py <file_or_directory> [--output report.json]

Dependencies (install with pip):
    pip install Pillow pypdf
"""

import argparse
import json
import os
import sys
from datetime import datetime

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    Image = None

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp"}
PDF_EXTENSIONS = {".pdf"}


def _convert_gps(value):
    """Converts EXIF GPS coordinate tuples into decimal degrees."""
    try:
        d, m, s = value
        return float(d) + float(m) / 60.0 + float(s) / 3600.0
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def extract_image_metadata(filepath):
    """Extracts EXIF metadata from an image file. Returns a dict."""
    if Image is None:
        return {"error": "Pillow not installed. Run: pip install Pillow"}

    result = {"file": filepath, "type": "image"}
    try:
        img = Image.open(filepath)
        result["format"] = img.format
        result["dimensions"] = f"{img.width}x{img.height}"

        exif_data = img.getexif()
        if not exif_data:
            result["exif"] = None
            return result

        exif = {}
        gps_info = {}

        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if tag_name == "GPSInfo":
                for gps_id, gps_value in value.items():
                    gps_tag_name = GPSTAGS.get(gps_id, gps_id)
                    gps_info[gps_tag_name] = str(gps_value)
            else:
                exif[str(tag_name)] = str(value)

        result["exif"] = exif

        if gps_info:
            result["gps"] = gps_info
            lat = gps_info.get("GPSLatitude")
            lon = gps_info.get("GPSLongitude")
            if lat and lon:
                result["gps_note"] = (
                    "GPS coordinates present - image may reveal capture location"
                )

    except Exception as e:
        result["error"] = str(e)

    return result


def extract_pdf_metadata(filepath):
    """Extracts document metadata from a PDF file. Returns a dict."""
    if PdfReader is None:
        return {"error": "pypdf not installed. Run: pip install pypdf"}

    result = {"file": filepath, "type": "pdf"}
    try:
        reader = PdfReader(filepath)
        result["num_pages"] = len(reader.pages)

        meta = reader.metadata
        if meta:
            result["metadata"] = {
                "author": meta.author,
                "creator": meta.creator,
                "producer": meta.producer,
                "subject": meta.subject,
                "title": meta.title,
                "creation_date": str(meta.creation_date) if meta.creation_date else None,
                "modification_date": str(meta.modification_date) if meta.modification_date else None,
            }
        else:
            result["metadata"] = None

    except Exception as e:
        result["error"] = str(e)

    return result


def process_file(filepath):
    """Dispatches a single file to the correct extractor based on extension."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext in IMAGE_EXTENSIONS:
        return extract_image_metadata(filepath)
    elif ext in PDF_EXTENSIONS:
        return extract_pdf_metadata(filepath)
    return None


def process_target(target):
    """Processes a single file or recursively walks a directory."""
    results = []

    if os.path.isfile(target):
        r = process_file(target)
        if r:
            results.append(r)
    elif os.path.isdir(target):
        for root, _dirs, files in os.walk(target):
            for name in files:
                full_path = os.path.join(root, name)
                r = process_file(full_path)
                if r:
                    results.append(r)
    else:
        print(f"Error: {target} is not a valid file or directory", file=sys.stderr)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Extract metadata from images (EXIF) and PDFs for forensic analysis."
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument(
        "--output", "-o", default="metadata_report.json",
        help="Output JSON report path (default: metadata_report.json)"
    )
    args = parser.parse_args()

    print(f"Scanning {args.target} for extractable metadata...")
    results = process_target(args.target)

    report = {
        "generated_at": datetime.now().isoformat(),
        "target": args.target,
        "files_processed": len(results),
        "results": results,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"Processed {len(results)} file(s). Report written to {args.output}")

    # Flag anything with GPS data as it's worth a human's attention
    gps_hits = [r for r in results if r.get("gps")]
    if gps_hits:
        print(f"\n⚠ {len(gps_hits)} file(s) contain embedded GPS coordinates:")
        for hit in gps_hits:
            print(f"  - {hit['file']}")


if __name__ == "__main__":
    main()
METADATA_PY_EOF

cat > 'python/log_analyzer.py' << 'LOGANALYZER_PY_EOF'
"""
log_analyzer.py - Log analysis for digital forensics toolkit

Parses system authentication logs (Linux auth.log / secure style) and
flags patterns commonly associated with intrusion attempts:
  - Repeated failed login attempts (possible brute force)
  - Successful login immediately following a burst of failures
    (possible successful brute force / credential stuffing)
  - Logins from an unusually high number of distinct source IPs
  - Root login attempts

This is a static, offline analyzer meant for learning log-analysis
techniques and for after-the-fact review of logs you already have
legitimate access to (your own machine, a lab VM, a CTF, etc.).

Usage:
    python3 log_analyzer.py <logfile> [--threshold 5] [--output report.json]

Example log line formats supported (OpenSSH style):
    Aug 12 03:14:15 myhost sshd[1234]: Failed password for root from 203.0.113.5 port 51515 ssh2
    Aug 12 03:14:20 myhost sshd[1234]: Accepted password for mike from 198.51.100.7 port 51516 ssh2
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

FAILED_PATTERN = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
TIMESTAMP_PATTERN = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def parse_log(filepath):
    """Reads a log file and extracts failed/accepted login events."""
    failed_events = []
    accepted_events = []

    with open(filepath, "r", errors="ignore") as f:
        for line_num, line in enumerate(f, start=1):
            ts_match = TIMESTAMP_PATTERN.match(line)
            timestamp = ts_match.group(1) if ts_match else None

            failed_match = FAILED_PATTERN.search(line)
            if failed_match:
                failed_events.append({
                    "line": line_num,
                    "timestamp": timestamp,
                    "user": failed_match.group("user"),
                    "ip": failed_match.group("ip"),
                })
                continue

            accepted_match = ACCEPTED_PATTERN.search(line)
            if accepted_match:
                accepted_events.append({
                    "line": line_num,
                    "timestamp": timestamp,
                    "user": accepted_match.group("user"),
                    "ip": accepted_match.group("ip"),
                })

    return failed_events, accepted_events


def analyze(failed_events, accepted_events, threshold=5):
    """Applies simple heuristics to flag suspicious patterns."""
    findings = []

    # 1. Repeated failures per source IP (possible brute force)
    failures_by_ip = defaultdict(list)
    for ev in failed_events:
        failures_by_ip[ev["ip"]].append(ev)

    for ip, events in failures_by_ip.items():
        if len(events) >= threshold:
            findings.append({
                "type": "brute_force_suspected",
                "ip": ip,
                "failed_attempts": len(events),
                "users_tried": sorted(set(e["user"] for e in events)),
                "detail": f"{len(events)} failed login attempts from {ip} "
                          f"(threshold: {threshold})"
            })

    # 2. Successful login from an IP that also had failures (possible
    #    successful brute force / credential stuffing)
    accepted_by_ip = defaultdict(list)
    for ev in accepted_events:
        accepted_by_ip[ev["ip"]].append(ev)

    for ip in accepted_by_ip:
        if ip in failures_by_ip and len(failures_by_ip[ip]) >= 3:
            findings.append({
                "type": "possible_successful_brute_force",
                "ip": ip,
                "failed_attempts_before_success": len(failures_by_ip[ip]),
                "detail": f"{ip} had {len(failures_by_ip[ip])} failed attempts "
                          f"before a successful login - review this session"
            })

    # 3. Root login attempts (failed or accepted)
    root_attempts = [e for e in failed_events + accepted_events if e["user"] == "root"]
    if root_attempts:
        findings.append({
            "type": "root_login_attempts",
            "count": len(root_attempts),
            "ips": sorted(set(e["ip"] for e in root_attempts)),
            "detail": f"{len(root_attempts)} login attempt(s) targeting the root account"
        })

    # 4. Wide-net scanning: many distinct IPs each trying a small number of times
    if len(failures_by_ip) >= 10:
        findings.append({
            "type": "distributed_scanning_suspected",
            "distinct_ips": len(failures_by_ip),
            "detail": f"Failed logins from {len(failures_by_ip)} distinct IPs - "
                      f"may indicate a distributed scan or botnet"
        })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Analyze auth logs for signs of brute-force or intrusion attempts."
    )
    parser.add_argument("logfile", help="Path to the log file (e.g. auth.log)")
    parser.add_argument(
        "--threshold", "-t", type=int, default=5,
        help="Minimum failed attempts from one IP to flag as suspicious (default: 5)"
    )
    parser.add_argument(
        "--output", "-o", default="log_report.json",
        help="Output JSON report path (default: log_report.json)"
    )
    args = parser.parse_args()

    print(f"Parsing {args.logfile} ...")
    try:
        failed_events, accepted_events = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"Error: file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(failed_events)} failed login events, "
          f"{len(accepted_events)} accepted login events.")

    findings = analyze(failed_events, accepted_events, threshold=args.threshold)

    report = {
        "generated_at": datetime.now().isoformat(),
        "source_log": args.logfile,
        "total_failed_events": len(failed_events),
        "total_accepted_events": len(accepted_events),
        "threshold_used": args.threshold,
        "findings": findings,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{len(findings)} finding(s). Report written to {args.output}")
    for f_ in findings:
        print(f"  [{f_['type']}] {f_['detail']}")


if __name__ == "__main__":
    main()
LOGANALYZER_PY_EOF

cat > 'python/forensics.py' << 'FORENSICS_PY_EOF'
"""
forensics.py - Main CLI for the Digital Forensics Toolkit

Ties together the C components (hasher, timeline) and the Python
components (metadata_extractor, log_analyzer) into a single command.

Usage:
    python3 forensics.py hash <file_or_dir> [output.csv]
    python3 forensics.py timeline <dir> [output.csv]
    python3 forensics.py metadata <file_or_dir> [--output report.json]
    python3 forensics.py logs <logfile> [--threshold 5] [--output report.json]
    python3 forensics.py full <target_dir> [--outdir ./report]

The C binaries (hasher, timeline) must be compiled first:
    cd ../src && make
"""

import argparse
import os
import subprocess
import sys

import metadata_extractor
import log_analyzer

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(SCRIPT_DIR, "..", "src")


def run_c_binary(name, args):
    """Runs a compiled C binary from the src/ directory."""
    binary_path = os.path.join(BIN_DIR, name)
    if not os.path.exists(binary_path):
        print(f"Error: {name} not found at {binary_path}. "
              f"Build it first with 'make' in the src/ directory.", file=sys.stderr)
        sys.exit(1)

    result = subprocess.run([binary_path] + args)
    sys.exit(result.returncode)


def cmd_hash(args):
    run_c_binary("hasher", [args.target, args.output])


def cmd_timeline(args):
    run_c_binary("timeline", [args.target, args.output])


def cmd_metadata(args):
    results = metadata_extractor.process_target(args.target)
    import json
    from datetime import datetime
    report = {
        "generated_at": datetime.now().isoformat(),
        "target": args.target,
        "files_processed": len(results),
        "results": results,
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Processed {len(results)} file(s). Report written to {args.output}")


def cmd_logs(args):
    failed_events, accepted_events = log_analyzer.parse_log(args.logfile)
    findings = log_analyzer.analyze(failed_events, accepted_events, threshold=args.threshold)
    import json
    from datetime import datetime
    report = {
        "generated_at": datetime.now().isoformat(),
        "source_log": args.logfile,
        "total_failed_events": len(failed_events),
        "total_accepted_events": len(accepted_events),
        "findings": findings,
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"{len(findings)} finding(s). Report written to {args.output}")


def cmd_full(args):
    """Runs every module against a target directory and collects output
    into a single report folder - a full sweep."""
    os.makedirs(args.outdir, exist_ok=True)

    print("=== Step 1/3: Hashing files (chain of custody) ===")
    run_c_binary_noexit("hasher", [args.target, os.path.join(args.outdir, "hashes.csv")])

    print("\n=== Step 2/3: Building filesystem timeline ===")
    run_c_binary_noexit("timeline", [args.target, os.path.join(args.outdir, "timeline.csv")])

    print("\n=== Step 3/3: Extracting embedded metadata ===")
    results = metadata_extractor.process_target(args.target)
    import json
    from datetime import datetime
    report = {
        "generated_at": datetime.now().isoformat(),
        "target": args.target,
        "files_processed": len(results),
        "results": results,
    }
    with open(os.path.join(args.outdir, "metadata.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Metadata report: {len(results)} file(s) processed.")

    print(f"\nAll done. Full report written to: {args.outdir}/")


def run_c_binary_noexit(name, args):
    """Like run_c_binary but doesn't exit the whole process - used by 'full'."""
    binary_path = os.path.join(BIN_DIR, name)
    if not os.path.exists(binary_path):
        print(f"Error: {name} not found at {binary_path}. Build with 'make' in src/.",
              file=sys.stderr)
        return
    subprocess.run([binary_path] + args)


def main():
    parser = argparse.ArgumentParser(
        prog="forensics",
        description="Digital Forensics Toolkit - hashing, timeline, metadata, and log analysis"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_hash = subparsers.add_parser("hash", help="Hash files for integrity verification (C)")
    p_hash.add_argument("target", help="File or directory to hash")
    p_hash.add_argument("output", nargs="?", default="hashes.csv", help="Output CSV path")
    p_hash.set_defaults(func=cmd_hash)

    p_timeline = subparsers.add_parser("timeline", help="Build a filesystem MAC-time timeline (C)")
    p_timeline.add_argument("target", help="Directory to scan")
    p_timeline.add_argument("output", nargs="?", default="timeline.csv", help="Output CSV path")
    p_timeline.set_defaults(func=cmd_timeline)

    p_meta = subparsers.add_parser("metadata", help="Extract EXIF/PDF metadata (Python)")
    p_meta.add_argument("target", help="File or directory to scan")
    p_meta.add_argument("--output", "-o", default="metadata_report.json")
    p_meta.set_defaults(func=cmd_metadata)

    p_logs = subparsers.add_parser("logs", help="Analyze auth logs for intrusion patterns (Python)")
    p_logs.add_argument("logfile", help="Path to the log file")
    p_logs.add_argument("--threshold", "-t", type=int, default=5)
    p_logs.add_argument("--output", "-o", default="log_report.json")
    p_logs.set_defaults(func=cmd_logs)

    p_full = subparsers.add_parser("full", help="Run hash + timeline + metadata as one sweep")
    p_full.add_argument("target", help="Directory to analyze")
    p_full.add_argument("--outdir", default="./forensics_report", help="Output directory")
    p_full.set_defaults(func=cmd_full)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
FORENSICS_PY_EOF

cat > 'requirements.txt' << 'REQUIREMENTS_EOF'
Pillow>=10.0.0
pypdf>=4.0.0
REQUIREMENTS_EOF

cat > '.gitignore' << 'GITIGNORE_EOF'
# Compiled C binaries
src/hasher
src/timeline
*.o

# Python
__pycache__/
*.pyc
.venv/
venv/

# Generated reports (these are output, not source)
*.csv
*.json
forensics_report/
report/

# OS
.DS_Store
GITIGNORE_EOF

cat > 'LICENSE' << 'LICENSE_EOF'
MIT License

Copyright (c) 2026 Michael

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
LICENSE_EOF

cat > 'README.md' << 'README_EOF'
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
README_EOF

chmod +x src/Makefile 2>/dev/null || true
echo ""
echo "Toate fisierele au fost create in: $TARGET"
echo ""
echo "Urmatorii pasi:"
echo "  cd \"$TARGET\"/src && make"
echo "  cd .. && pip install -r requirements.txt"
echo "  git init && git add -A && git commit -m \"Initial commit\""
