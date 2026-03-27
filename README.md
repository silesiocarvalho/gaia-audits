# Gaia Audits 🕵🏽‍♂️

The gaia-audits is a Python-based security auditing utility designed to assess the configuration posture of a Check Point Gaia R82 Standalone deployment against the CIS Check Point Firewall Benchmark v1.1.0.

The tool automates the process of validating system configurations and produces a structured compliance report, helping security engineers quickly identify misconfigurations, gaps, and areas requiring manual review.

## Features
🔍 Automated audit of Gaia R82 configurations

📊 Structured compliance reporting (Pass / Fail / Manual Review)

📁 Easy-to-parse output formats (JSON)

⚙️ Modular checks aligned with CIS Benchmark controls

🚀 Lightweight and CLI-friendly

🧩 Extensible framework for adding new controls


## How It Works

The tool connects to a Gaia R82 system (locally or remotely), collects relevant configuration data, and evaluates it against predefined CIS controls.

Each control is categorized as:

PASS → Configuration meets CIS requirements
FAIL → Configuration does not meet requirements
MANUAL REVIEW → Requires human validation

# Installation
TBD

# Usage

```bash
SSH + Management API (full coverage)
python audit_tool.py -m 192.168.1.1 -u admin -p MyPass --level all

SSH-only (no API, L1 controls only)
python audit_tool.py -m 192.168.1.1 -u admin -p MyPass --no-api --level 1

API key authentication
python audit_tool.py -m 192.168.1.1 --api-key JpPA+eJ5gekQ... --level all
```

Custom output file
python audit_tool.py -m 192.168.1.1 -u admin -p MyPass -o my_audit.json

# Example Output
======================================================================

  ── Password Policy ──
  [1.1   ] ❌ FAIL  Ensure Minimum Password Length is set to 14 or higher
           Expected : ≥ 14
           Actual   : 6
           Fix      : set password-controls min-password-length 14
  [1.2   ] ✅ PASS  Ensure Disallow Palindromes is selected
  [1.3   ] ❌ FAIL  Ensure Password Complexity is set to 3
           Expected : ≥ 3
           Actual   : 2
           Fix      : set password-controls complexity 3


# Supported Benchmark
CIS Check Point Firewall Benchmark v1.1.0
Target: Gaia R82 Standalone deployments


# Roadmap

Support for distributed deployments
HTML report generation
Integration with CI/CD pipelines
API-based scanning
Auto-remediation suggestions


# Contributing

Contributions are welcome. Feel free to:

Submit issues
Open pull requests
Suggest new checks or improvements


# Disclaimer

This tool is intended for auditing and compliance purposes only. It does not modify system configurations. Always validate findings before applying changes in production environments.

License

MIT License

Author

Built for security practitioners and engineers who need fast, repeatable, and transparent compliance validation for Check Point Gaia systems.
