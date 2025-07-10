import argparse
import subprocess
import json
import os
import tempfile
from pathlib import Path
import json
import pandas as pd
from langchain_google_genai import ChatGoogleGenerativeAI
api_key = "" #ENTER Google API Key


import argparse, subprocess, json, sys
from pathlib import Path

def run_cmd(cmd, cwd=None):
    """Run list-form cmd, return (returncode, stdout, stderr)."""
    proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    return proc.returncode, proc.stdout, proc.stderr

def run_bandit(target):
    _, out, err = run_cmd([sys.executable, "-m", "bandit", "-r",
                           str(target), "-f", "json"])
    return out

def run_semgrep(target):
    cmd = [sys.executable, "-m", "semgrep", "--config", "auto",
           "--json", "--quiet", "--output", "-", str(target)]
    rc, out, err = run_cmd(cmd)
    return out

def run_pip_audit():
    rc, out, _ = run_cmd([sys.executable, "-m", "pip_audit", "--format", "json"])
    return out

def run_safety(requirements):
    rc, out, _ = run_cmd(["safety", "check", "-r", str(requirements), "--json"])
    return out

def run_detect_secrets(target):
    rc, out, _ = run_cmd(["detect-secrets", "scan", str(target), "--json"])
    # detect-secrets embeds JSON inside a wrapper dict
    return out

def run_gitleaks(target):
    rc, out, _ = run_cmd(["gitleaks", "detect", "--source", str(target),
                          "--report-format", "json"])
    return out

def run_trufflehog(target):
    rc, out, _ = run_cmd(["trufflehog", "filesystem", str(target), "--json"])
    # trufflehog may output multiple JSON objects; wrap in list
    return out


def run_flake8_security(target):
    rc, out, _ = run_cmd(["flake8", "--select=SEC", str(target)])
    return out

def run_pylint_security(target):
    rc, out, _ = run_cmd(["pylint", "--load-plugins", "pylint_plugin_security",
                          "--output-format=json", str(target)])
    return out

def run_mypy(target):
    report_dir = Path(".mypy_report")
    report_dir.mkdir(exist_ok=True)
    cmd = ["mypy", "--show-error-codes", "--ignore-missing-imports",
           "--json-report", str(report_dir), str(target)]
    run_cmd(cmd)
    # read the generated report
    report_file = report_dir / "index.json"
    return report_file.read_text() if report_file.exists() else {}

def run_scancode(target):
    # ensure scancode installed and license cleared
    out_file = "scancode-report.json"
    cmd = ["scancode", "--format", "json-pp", "--output", out_file, str(target)]
    run_cmd(cmd)
    return json.loads(Path(out_file).read_text()) if Path(out_file).exists() else {}

def run_cyclonedx(target):
    out_file = "bom.xml"
    cmd = ["cyclonedx-py", "--output", out_file]
    run_cmd(cmd, cwd=target)
    return Path(target / out_file).read_text() if Path(target / out_file).exists() else ""


def report_build(data):
    llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    google_api_key=api_key,
    temperature=1,
    )
    system_prompt = f"""You are a security expert. Given tool findings use them to create an indepth The report contains:
-Vulnerability Findings
-Authentication & Authorization Issues
-Input Validation & Output Encoding
-Cryptographic Practices
-Error Handling & Logging
-Secure Coding Practices
-Third-party Dependencies
-Remediation Recommendations..
The tool findings are as follows: {data}"""
    ans=llm.invoke(system_prompt)
    return ans.content


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="/Users/hem/Desktop/Python/git_projects/fitness-dashboard", help="Path to codebase")
    p.add_argument("--requirements", default="requirements.txt")
    p.add_argument("--output", default="security_report.md")
    args = p.parse_args()

    tgt = Path(args.target).resolve()
    data = {}

    print("Bandit…")        
    data["bandit"]=run_bandit(tgt)
    print("Semgrep…")
    data["semgrep"]=run_semgrep(tgt)
    print("pip-audit…")
    data["pip_audit"]=run_pip_audit()
    req = Path(args.requirements)
    if req.exists():
        data["safety"]=run_safety(req)
    data["detect_secrets"]=run_detect_secrets(tgt)
    print("Gitleaks…")
    data["gitleaks"]=run_gitleaks(tgt)
    print("TruffleHog…")
    data["trufflehog"]=run_trufflehog(tgt)
    print("Flake8‑SEC…")
    data["flake8_sec"]=run_flake8_security(tgt)
    print("Mypy…")
    data["mypy"]=run_mypy(tgt)
    print("Scancode…")
    data["scancode"]=run_scancode(tgt)
    print("CycloneDX…")
    data["cyclonedx"]= run_cyclonedx(tgt)

    report=report_build(data)
    with open("report.txt", "w") as out_f:
        out_f.write(report)

if __name__ == '__main__':
    main()
