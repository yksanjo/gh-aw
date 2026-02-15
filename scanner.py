#!/usr/bin/env python3
"""
gh-aw: GitHub Actions Workflow Security Scanner
Lightweight version focused specifically on GitHub Actions workflows
Usage: python3 scanner.py /path/to/workflows
"""

import os
import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Category(Enum):
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    UNSAFE_CODE_EXECUTION = "unsafe_code_execution"
    DATA_LEAKAGE = "data_leakage"
    SECRET_EXPOSURE = "secret_exposure"

@dataclass
class Finding:
    rule_id: str
    severity: Severity
    category: Category
    title: str
    description: str
    file_path: str
    recommendation: str = ""
    cwe_id: Optional[str] = None

def check_permissions(content: str, file_path: str) -> List[Finding]:
    findings = []
    
    if re.search(r'permissions:.*\s+contents:\s+write', content, re.DOTALL):
        findings.append(Finding(
            "PERM001", Severity.HIGH, Category.EXCESSIVE_PERMISSIONS,
            "Overly Permissive GitHub Token (contents:write)",
            "Workflow has write access to repository contents",
            file_path, "Use 'contents: read' unless write access is required", "CWE-862"))
    
    if re.search(r'permissions:.*\s+contents:\s+admin', content, re.DOTALL):
        findings.append(Finding(
            "PERM002", Severity.CRITICAL, Category.EXCESSIVE_PERMISSIONS,
            "Admin Permissions Granted",
            "Workflow has admin permissions",
            file_path, "Use minimum required permissions", "CWE-862"))
    
    if re.search(r'permissions:.*\s+secrets:\s+write', content, re.DOTALL):
        findings.append(Finding(
            "PERM003", Severity.CRITICAL, Category.EXCESSIVE_PERMISSIONS,
            "Secrets Write Access",
            "Workflow can write to secrets",
            file_path, "Use 'secrets: read' unless write is required", "CWE-862"))
    
    if 'pull_request_target' in content:
        findings.append(Finding(
            "PERM004", Severity.CRITICAL, Category.EXCESSIVE_PERMISSIONS,
            "Using pull_request_target Trigger",
            "Runs with base repo permissions - can be exploited",
            file_path, "Use 'pull_request' trigger or ensure trusted forks only", "CWE-94"))
    
    return findings

def check_unsafe_commands(content: str, file_path: str) -> List[Finding]:
    findings = []
    patterns = [
        (r'rm\s+-rf\s+/', "EXEC001", Severity.CRITICAL, "Recursive force delete"),
        (r'eval\s+\$', "EXEC002", Severity.CRITICAL, "Dynamic command evaluation"),
        (r'curl\s+.*\|\s*(sh|bash)', "EXEC009", Severity.CRITICAL, "Curl-pipe-sh"),
        (r'wget\s+.*\|\s*(sh|bash)', "EXEC010", Severity.CRITICAL, "Wget-pipe-sh"),
        (r'docker\s+run\s+--privileged', "EXEC015", Severity.CRITICAL, "Privileged Docker"),
    ]
    
    for pattern, rule_id, severity, desc in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(Finding(
                rule_id, severity, Category.UNSAFE_CODE_EXECUTION,
                f"Unsafe Command: {desc}",
                f"Found dangerous pattern: {desc}",
                file_path, "Review and use safer alternatives", "CWE-78"))
    
    return findings

def check_secrets(content: str, file_path: str) -> List[Finding]:
    findings = []
    patterns = [
        (r'ghp_[A-Za-z0-9]{36}', "SECR002", Severity.CRITICAL, "GitHub PAT"),
        (r'AKIA[0-9A-Z]{16}', "SECR006", Severity.CRITICAL, "AWS Access Key"),
        (r'sk-[A-Za-z0-9]{48,}', "SECR007", Severity.CRITICAL, "OpenAI API Key"),
        (r'xox[baprs]-[A-Za-z0-9\-_]+', "SECR010", Severity.CRITICAL, "Slack Token"),
    ]
    
    content_check = re.sub(r'\$\{\{\s*secrets\.\w+\s*\}\}', 'SECRET', content)
    
    for pattern, rule_id, severity, desc in patterns:
        if re.search(pattern, content_check):
            findings.append(Finding(
                rule_id, severity, Category.SECRET_EXPOSURE,
                f"Secret Exposure: {desc}",
                f"Potential hardcoded {desc}",
                file_path, "Use environment variables or secrets", "CWE-798"))
    
    return findings

def check_data_leakage(content: str, file_path: str) -> List[Finding]:
    findings = []
    
    if re.search(r'echo\s+.*\$\{\{.*secrets', content, re.IGNORECASE):
        findings.append(Finding(
            "DATA017", Severity.HIGH, Category.DATA_LEAKAGE,
            "Potential Secret Logging",
            "Workflow may be echoing secrets",
            file_path, "Use '::add-mask::' to mask secrets", "CWE-532"))
    
    if re.search(r'http://(?!localhost)', content):
        findings.append(Finding(
            "DATA018", Severity.HIGH, Category.DATA_LEAKAGE,
            "Unencrypted HTTP Connection",
            "Using unencrypted HTTP",
            file_path, "Use HTTPS instead", "CWE-295"))
    
    return findings

def scan_file(file_path: str) -> List[Finding]:
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return findings
    
    findings.extend(check_permissions(content, file_path))
    findings.extend(check_unsafe_commands(content, file_path))
    findings.extend(check_secrets(content, file_path))
    findings.extend(check_data_leakage(content, file_path))
    
    return findings

def main():
    parser = argparse.ArgumentParser(description='gh-aw: GitHub Actions Workflow Security Scanner')
    parser.add_argument('path', help='Path to workflow files or directory')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    args = parser.parse_args()
    
    all_findings = []
    patterns = ['*.yml', '*.yaml']
    
    path = Path(args.path)
    if path.is_file():
        files = [path]
    else:
        files = []
        for p in patterns:
            files.extend(path.rglob(p))
    
    for f in files:
        all_findings.extend(scan_file(str(f)))
    
    if args.json:
        print(json.dumps({
            'total_findings': len(all_findings),
            'findings': [{
                'rule_id': f.rule_id,
                'severity': f.severity.value,
                'category': f.category.value,
                'title': f.title,
                'file': f.file_path,
                'recommendation': f.recommendation
            } for f in all_findings]
        }, indent=2))
    else:
        print(f"\n🔍 gh-aw: GitHub Actions Security Scanner")
        print(f"   Files scanned: {len(files)}")
        print(f"   Findings: {len(all_findings)}\n")
        
        for i, f in enumerate(all_findings, 1):
            print(f"[{i}] {f.title}")
            print(f"    Severity: {f.severity.value}")
            print(f"    File: {f.file_path}")
            print(f"    Recommendation: {f.recommendation}\n")

if __name__ == '__main__':
    main()
