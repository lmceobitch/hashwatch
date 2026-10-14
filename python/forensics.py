import argparse
import os
import subprocess
import sys

import metadata_extractor
import log_analyzer

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(SCRIPT_DIR, "..", "src")


def run_c_binary(name, args):
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
