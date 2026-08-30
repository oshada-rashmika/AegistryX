#!/usr/bin/env python3
import argparse
import json
import os
import sys

# ansi color constants
RED = "\033[91m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

# default prohibited spdx license identifiers
DEFAULT_BANNED_LICENSES = {
    "gpl-3.0",
    "gpl-3.0-only",
    "gpl-3.0-or-later",
    "agpl-3.0",
    "agpl-3.0-only",
    "agpl-3.0-or-later",
    "lgpl-3.0",
}


def parse_args():
    # setup cli arguments
    parser = argparse.ArgumentParser(
        description="Verify license compliance from an SPDX JSON SBOM."
    )
    parser.add_argument(
        "--file",
        "--sbom",
        "-f",
        "-s",
        dest="file",
        default="./sbom.spdx.json",
        help="path to spdx json file (default: ./sbom.spdx.json)",
    )
    parser.add_argument(
        "--prohibited",
        "-p",
        default=None,
        help="comma-separated list of forbidden licenses",
    )
    parser.add_argument(
        "positional_path",
        nargs="?",
        default=None,
        help="optional positional sbom file path",
    )
    return parser.parse_args()


def get_banned_licenses(prohibited_arg):
    # build set of lowercase banned license keys
    if not prohibited_arg:
        return DEFAULT_BANNED_LICENSES
    return {
        item.strip().lower()
        for item in prohibited_arg.split(",")
        if item.strip()
    }


def is_banned(license_str, banned_set):
    # check exact match or expression tokens
    clean_str = license_str.strip()
    if not clean_str or clean_str in ("NOASSERTION", "NONE"):
        return False

    if clean_str.lower() in banned_set:
        return True

    # split compound expressions (and, or, with, brackets)
    tokens = (
        clean_str.replace("(", " ")
        .replace(")", " ")
        .replace(",", " ")
        .replace("/", " ")
        .split()
    )
    for token in tokens:
        if token.lower() in banned_set:
            return True

    return False


def check_licenses(sbom_path, banned_set):
    # check file existence
    if not os.path.isfile(sbom_path):
        print(f"{RED}{BOLD}[ERROR]{RESET} SBOM file not found: {sbom_path}", file=sys.stderr)
        sys.exit(1)

    # load and parse json
    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as err:
        print(f"{RED}{BOLD}[ERROR]{RESET} Failed to parse JSON in {sbom_path}: {err}", file=sys.stderr)
        sys.exit(1)

    packages = data.get("packages", [])
    total_packages = len(packages)
    violations = []

    # iterate through all detected packages
    for pkg in packages:
        name = pkg.get("name") or pkg.get("SPDXID", "unknown")
        version = pkg.get("versionInfo") or pkg.get("version", "unknown")

        candidates = []
        for field in ("licenseDeclared", "licenseConcluded"):
            val = pkg.get(field)
            if isinstance(val, str) and val not in ("NOASSERTION", "NONE", ""):
                candidates.append(val)

        info_from_files = pkg.get("licenseInfoFromFiles")
        if isinstance(info_from_files, list):
            for val in info_from_files:
                if isinstance(val, str) and val not in ("NOASSERTION", "NONE", ""):
                    candidates.append(val)

        # check candidate license strings
        for license_val in candidates:
            if is_banned(license_val, banned_set):
                violations.append((name, version, license_val))
                break

    # display scan summary
    print(f"[*] Total packages scanned: {total_packages}")

    if violations:
        print(f"\n{RED}{BOLD}[VIOLATION SUMMARY]{RESET} Found {len(violations)} non-compliant package(s):")
        for name, version, lic in violations:
            print(f"{RED}{BOLD}[VIOLATION]{RESET} Package {name} ({version}) uses banned license: {lic}")
        return False

    print(f"{GREEN}{BOLD}[SUCCESS]{RESET} All package licenses are compliant.")
    return True


def main():
    # enable vt100 processing on windows terminal if supported
    if os.name == "nt":
        os.system("")

    args = parse_args()
    target_file = args.positional_path or args.file
    banned_licenses = get_banned_licenses(args.prohibited)

    compliant = check_licenses(target_file, banned_licenses)
    if not compliant:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
