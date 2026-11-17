import os
import re
import subprocess
from pathlib import Path

def scan_supply_chain_stealer(target_dir):
    target_dir = Path(target_dir)
    """
    Scans for indicators of the recent GitHub CI secret stealer campaign.
    """
    findings = []
    
    # IOCs from the report
    SUSPICIOUS_BRANCHES = [r"wfx-docs", r"chore/[a-z0-9]{8}", r"ci-check-[0-9]{4}"]
    SUSPICIOUS_COMMIT_MSGS = [
        r"ci: refresh build cache",
        r"chore: add ci helper",
        r"chore: add dependency audit workflow",
        r"ci: restore",
        r"ci: cleanup"
    ]
    
    # Check Git History for suspicious branches and commits
    try:
        # Get all branches
        result = subprocess.run(["git", "-C", str(target_dir), "branch", "-a"], 
                                capture_output=True, text=True)
        branches = result.stdout.splitlines()
        
        for branch in branches:
            branch_name = branch.strip().replace("* ", "").replace("remotes/origin/", "")
            for pattern in SUSPICIOUS_BRANCHES:
                if re.search(pattern, branch_name):
                    findings.append({
                        "tool": "Supply-Chain-Stealer-Scanner",
                        "severity": "CRITICAL",
                        "title": "Suspicious Branch Detected (Potential CI Stealer)",
                        "description": f"Branch '{branch_name}' matches known malicious patterns used in recent GitHub account hijackings.",
                        "file": ".git/refs",
                        "recommendation": "Investigate this branch immediately. Check for unauthorized workflow changes."
                    })

        # Get recent commit messages
        result = subprocess.run(["git", "-C", str(target_dir), "log", "--oneline", "-n", "50"], 
                                capture_output=True, text=True)
        commits = result.stdout.splitlines()
        
        for commit in commits:
            for msg_pattern in SUSPICIOUS_COMMIT_MSGS:
                if re.search(msg_pattern, commit, re.IGNORECASE):
                    findings.append({
                        "tool": "Supply-Chain-Stealer-Scanner",
                        "severity": "HIGH",
                        "title": "Suspicious Commit Message Detected",
                        "description": f"Commit message matches patterns used by CI secret stealers: '{commit}'",
                        "file": ".git/logs",
                        "recommendation": "Review the files changed in this commit. Look for changes to .github/workflows/ or package.json postinstall hooks."
                    })
                    
    except Exception as e:
        pass # Git might not be available in shallow clones

    # Check for malicious files in workflows
    workflow_dir = target_dir / ".github" / "workflows"
    if workflow_dir.exists():
        for wf_file in workflow_dir.glob("*.yml"):
            try:
                content = wf_file.read_text()
                if "wfx-loot" in content or "194.150.166.244" in content or "18.143.168.96" in content:
                    findings.append({
                        "tool": "Supply-Chain-Stealer-Scanner",
                        "severity": "CRITICAL",
                        "title": "Malicious Workflow Content Detected",
                        "description": f"Workflow file {wf_file.name} contains indicators of compromise (IOCs) for the CI secret stealer.",
                        "file": str(wf_file),
                        "recommendation": "Remove this workflow immediately. Rotate all secrets accessible to this repository's CI environment."
                    })
            except:
                continue

    # Check package.json for malicious postinstall hooks
    pkg_json = target_dir / "package.json"
    if pkg_json.exists():
        try:
            import json
            with open(pkg_json, 'r') as f:
                data = json.load(f)
            scripts = data.get('scripts', {})
            if 'postinstall' in scripts:
                hook = scripts['postinstall']
                if '.ci-' in hook or 'sh' in hook:
                     findings.append({
                        "tool": "Supply-Chain-Stealer-Scanner",
                        "severity": "CRITICAL",
                        "title": "Suspicious Postinstall Hook",
                        "description": f"package.json contains a postinstall hook that may execute malicious scripts: {hook}",
                        "file": "package.json",
                        "recommendation": "Verify the integrity of this hook. Attackers use this to run stealers on developer machines during npm install."
                    })
        except:
             pass

    # --- NEW: Scan for GitHub Personal Access Tokens (ghp_) ---
    ghp_pattern = re.compile(r'ghp_[A-Za-z0-9]{36,}')
    
    for root, dirs, files in os.walk(target_dir):
        # Skip .git folder to avoid scanning history again (TruffleHog does that)
        if '.git' in root:
            continue
            
        for file in files:
            # Only check text-based files to avoid binary errors
            if file.endswith(('.py', '.js', '.ts', '.json', '.yml', '.yaml', '.env', '.md', '.txt', '.sh')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        matches = ghp_pattern.findall(content)
                        for match in matches:
                            findings.append({
                                "tool": "Supply-Chain-Stealer-Scanner",
                                "severity": "CRITICAL",
                                "title": "Hardcoded GitHub Token (ghp_)",
                                "description": f"Found a GitHub Personal Access Token in {file}",
                                "file": file_path,
                                "secret_preview": match[:10] + "...",
                                "recommendation": "Revoke this token immediately on GitHub and remove it from the code."
                            })
                except Exception:
                    continue # This 'continue' is now safely inside the 'for file' loop

    return findings
