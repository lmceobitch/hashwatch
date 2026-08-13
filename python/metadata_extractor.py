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
