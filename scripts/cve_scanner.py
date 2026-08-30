#!/usr/bin/env python3
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

# ansi color constants
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def parse_args():
    # setup cli arguments
    parser = argparse.ArgumentParser(
        description="Scan SPDX SBOM packages for CVEs via OSV.dev API."
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
        "positional_path",
        nargs="?",
        default=None,
        help="optional positional sbom file path",
    )
    return parser.parse_args()


def query_osv(package_name, package_version, timeout=10):
    # query osv api endpoint
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({
        "package": {"name": package_name},
        "version": package_version,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                body = response.read().decode("utf-8")
                return json.loads(body)
    except urllib.error.HTTPError as e:
        # non-200 api responses
        print(f"{YELLOW}[WARN]{RESET} OSV API returned status {e.code} for {package_name}@{package_version}", file=sys.stderr)
    except urllib.error.URLError as e:
        # connection or dns errors
        print(f"{YELLOW}[WARN]{RESET} Connection error querying OSV for {package_name}: {e.reason}", file=sys.stderr)
    except Exception as e:
        # general timeout or parsing errors
        print(f"{YELLOW}[WARN]{RESET} Error checking {package_name} against OSV: {e}", file=sys.stderr)

    return {}


def scan_sbom(sbom_path):
    # check file existence
    if not os.path.isfile(sbom_path):
        print(f"{RED}{BOLD}[ERROR]{RESET} SBOM file not found: {sbom_path}", file=sys.stderr)
        sys.exit(1)

    # load and parse spdx json
    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as err:
        print(f"{RED}{BOLD}[ERROR]{RESET} Failed to parse JSON in {sbom_path}: {err}", file=sys.stderr)
        sys.exit(1)

    packages = data.get("packages", [])
    total_packages = len(packages)
    print(f"[*] Scanning {total_packages} packages against OSV.dev...")

    total_vulns = 0

    # iterate through all packages
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("versionInfo") or pkg.get("version")

        # skip empty or unversioned packages
        if not name or not version or version in ("NOASSERTION", "NONE"):
            continue

        result = query_osv(name, version)
        vulns = result.get("vulns", [])

        if vulns:
            total_vulns += len(vulns)

            # extract cve aliases and advisory ids
            cve_ids = []
            for v in vulns:
                aliases = v.get("aliases", [])
                vid = v.get("id")
                if aliases:
                    cve_ids.extend(aliases)
                elif vid:
                    cve_ids.append(vid)

            cve_list_str = ", ".join(dict.fromkeys(cve_ids)) or "Unknown"
            print(f"{RED}{BOLD}[CVE FOUND]{RESET} {name} {version} is vulnerable! CVEs: {cve_list_str}")

    print("-" * 60)
    print(f"[*] Total packages checked: {total_packages}")
    print(f"[*] Total vulnerabilities detected: {total_vulns}")

    if total_vulns > 0:
        print(f"{RED}{BOLD}[FAILED]{RESET} Vulnerability scan failed with {total_vulns} active CVE(s).")
        return False

    print(f"{GREEN}{BOLD}[SUCCESS]{RESET} No active CVEs found.")
    return True


def main():
    # enable vt100 terminal escape sequences on windows
    if os.name == "nt":
        os.system("")

    args = parse_args()
    target_file = args.positional_path or args.file

    compliant = scan_sbom(target_file)
    if not compliant:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
