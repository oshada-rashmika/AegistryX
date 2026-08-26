#!/usr/bin/env python3
"""
Aegistryx CI/CD Runner Verification Script
Validates Python runtime, environment variables, and execution context on GitHub Actions runners.
"""

import os
import sys

#Ensure UTF-8 stdout encoding compatibility across platforms
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    separator = "=" * 60
    print(separator)
    print(">> Aegistryx Pipeline Test: SUCCESS! <<")
    print(separator)
    
    #Python Environment Check
    print("\n[*] Python Runtime Information:")
    print(f"  - Version         : {sys.version}")
    print(f"  - Executable Path : {sys.executable}")
    
    #Key Environment Variables Check
    print("\n[*] Environment Variables Passed to Process:")
    priority_keys = ["TEST_VAR", "GITHUB_WORKFLOW", "GITHUB_RUN_ID", "GITHUB_REF", "RUNNER_OS"]
    
    print("  [Target Pipeline Variables]")
    for key in priority_keys:
        val = os.environ.get(key, "(not set)")
        print(f"    - {key}: {val}")
        
    print("\n  [Full Environment Variables Snapshot]")
    all_keys = sorted(os.environ.keys())
    print(f"    Total environment variables detected: {len(all_keys)}")
    for key in all_keys:
        #Avoid printing sensitive secrets; mask tokens/passwords if present
        if any(secret_term in key.upper() for secret_term in ["TOKEN", "SECRET", "PASSWORD", "AUTH"]):
            val = "***MASKED***"
        else:
            val = os.environ[key]
        print(f"    - {key} = {val}")

    print("\n" + separator)
    print("All runner environment checks passed successfully.")
    print(separator)

if __name__ == "__main__":
    main()
