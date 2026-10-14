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
    TAGS = {}
    GPSTAGS = {}

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp"}
PDF_EXTENSIONS = {".pdf"}


def _convert_gps(value):
    try:
        d, m, s = value
        return float(d) + float(m) / 60.0 + float(s) / 3600.0
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def extract_image_metadata(filepath):
    if Image is None:
        return {"error": "Pillow not installed. Run: pip install Pillow"}

    result = {"file": filepath, "type": "image"}

    try:
        with Image.open(filepath) as img:
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

    except Exception as error:
        result["error"] = str(error)

    return result


def extract_pdf_metadata(filepath):
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
                "modification_date": str(meta.modification_date) if meta.modification_date else None
            }
        else:
            result["metadata"] = None

    except Exception as error:
        result["error"] = str(error)

    return result


def process_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()

    if ext in IMAGE_EXTENSIONS:
        return extract_image_metadata(filepath)
    elif ext in PDF_EXTENSIONS:
        return extract_pdf_metadata(filepath)

    return None


def process_target(target):
    results = []

    if os.path.isfile(target):
        result = process_file(target)
        if result:
            results.append(result)

    elif os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            for name in files:
                filepath = os.path.join(root, name)
                result = process_file(filepath)

                if result:
                    results.append(result)

    else:
        print(
            f"Error: {target} is not a valid file or directory",
            file=sys.stderr
        )

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Extract metadata from images and PDF files"
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument(
        "--output", "-o",
        default="metadata_report.json",
        help="Output JSON report path"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.target) and not os.path.isdir(args.target):
        print(f"Error: {args.target} is not a valid file or directory", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {args.target}...")
    results = process_target(args.target)

    report = {
        "generated_at": datetime.now().isoformat(),
        "target": args.target,
        "files_processed": len(results),
        "results": results
    }

    try:
        with open(args.output, "w") as file:
            json.dump(report, file, indent=2, default=str)
    except OSError as error:
        print(f"Error writing report: {error}", file=sys.stderr)
        sys.exit(1)

    print(f"Processed {len(results)} file(s). Report saved to {args.output}")

    gps_hits = [result for result in results if result.get("gps")]

    if gps_hits:
        print(f"\n{len(gps_hits)} file(s) contain GPS data:")

        for hit in gps_hits:
            print(f"  - {hit['file']}")


if __name__ == "__main__":
    main()
