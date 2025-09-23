# Ox Security Findings Fetcher

This directory contains tools for fetching and analyzing all types of security findings from [Ox Security](https://app.ox.security/) using their GraphQL API.

## 🚀 Features

- **Comprehensive Security Data**: Fetch all security findings including SCA, SAST, Secrets, Infrastructure, and more
- **Flexible Filtering**: Filter by severity, application, issue type, and more
- **GraphQL API**: Uses the comprehensive getIssues query for complete coverage
- **Export Capabilities**: Export findings to JSON for further analysis
- **Summary Reports**: Get detailed summaries with breakdowns by severity, type, and application
- **Secure Configuration**: Store API credentials securely in YAML files

## 📋 Prerequisites

- Python 3.7+
- Ox Security API key
- Access to [Ox Security platform](https://app.ox.security/)

## 🛠️ Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Configure your Ox Security API credentials in `secret.yaml`:
```yaml
ox_security:
  api_key: "ox_your_api_key_here"
  api_url: "https://api.ox.security"
```

## 🔧 Usage

### Basic Usage

```bash
# Fetch all security findings
python fetch_findings.py

# Show summary only
python fetch_findings.py --summary-only

# Test API authentication
python fetch_findings.py --test-auth

# List available applications
python fetch_findings.py --list-applications
```

### Advanced Filtering

```bash
# Fetch only Critical and High severity findings
python fetch_findings.py --severities Critical High

# Fetch findings for specific applications
python fetch_findings.py --applications app1 app2

# Filter by issue type
python fetch_findings.py --type Secret
python fetch_findings.py --type SCA SAST
python fetch_findings.py --type Infrastructure
```

### Export and Analysis

```bash
# Export all findings to JSON
python fetch_findings.py --output security_findings.json

# Export filtered findings
python fetch_findings.py --severities Critical High --output critical_high.json
python fetch_findings.py --type Secret --output secrets.json

# Verbose logging
python fetch_findings.py --verbose
```

## 📊 Sample Output

```
============================================================
📊 OX SECURITY SECURITY ISSUES SUMMARY
============================================================
🔍 Total Findings: 156
🎯 Unique CVEs: 89
📱 Applications Scanned: 8
📋 Total Issues Processed: 156

🔍 By Issue Type:
   Secret: 45
   SCA: 34
   Infrastructure: 23
   SAST: 18

📊 By Finding Type:
   Secret: 45
   SCA: 34
   Infrastructure: 23
   SAST: 18

📈 By Severity:
   Critical: 12
   High: 34
   Medium: 78
   Low: 32

📱 By Application:
   backend-api: 45 findings (12 issues)
   frontend-web: 23 findings (8 issues)
   mobile-app: 18 findings (5 issues)

📦 Top Vulnerable Packages (SCA):
   lodash: 8 findings
   jackson-databind: 6 findings
   spring-core: 4 findings
============================================================
```

## 🔐 Authentication

The script supports multiple ways to provide your Ox Security API key:

1. **YAML Config File** (Recommended):
   ```yaml
   ox_security:
     api_key: "ox_your_api_key_here"
   ```

2. **Environment Variable**:
   ```bash
   export OX_SECURITY_API_KEY="ox_your_api_key_here"
   ```

3. **Command Line** (Not recommended for security):
   ```python
   fetcher = OxSecuritySCAFetcher(api_key="ox_your_api_key_here")
   ```

## 📚 API Reference

Based on [Ox Security GraphQL API Documentation](https://docs.ox.security/api-documentation/api-reference/api--issue/queries/get-issues), the script uses the comprehensive `getIssues` query to fetch all types of security findings:

- **SCA**: Software Composition Analysis vulnerabilities
- **SAST**: Static Application Security Testing findings  
- **Secrets**: Hardcoded secrets and credentials
- **Infrastructure**: Infrastructure as Code (IaC) issues
- **License**: Open source license compliance issues

## 🔍 Troubleshooting

### Authentication Issues
```bash
# Test your API key
python fetch_findings.py --test-auth

# Check verbose logs
python fetch_findings.py --verbose
```

### No Findings Returned
```bash
# List available applications
python fetch_findings.py --list-applications

# Try without filters
python fetch_findings.py
```

### Rate Limiting
The script includes reasonable timeouts and error handling. If you encounter rate limits, try:
- Reducing the `--limit` parameter
- Adding delays between requests (contact support for bulk data needs)

## 📁 File Structure

```
oxing/
├── fetch_findings.py       # Main findings fetcher script (GraphQL)
├── fetch_sca_findings.py   # Legacy REST API SCA fetcher
├── requirements.txt        # Python dependencies  
├── secret.yaml            # API credentials (gitignored)
├── README.md              # This documentation
└── .gitignore             # Git ignore rules
```

## 🤝 Integration with Other Tools

This Ox Security fetcher is designed to complement other security tools in the SDLC workspace:

- **Cycode**: Compare SCA findings between platforms
- **GitSec**: Cross-reference with Git security analysis
- **SAMM**: Incorporate findings into security maturity assessments

## 📈 Next Steps

1. **Run Initial Fetch**: Start with `--summary-only` to understand your data
2. **Filter by Type**: Use `--type Secret` or `--type Infrastructure` to focus on specific issue types
3. **Export Full Data**: Use `--output` to save complete findings
4. **Filter Critical Issues**: Focus on `--severities Critical High`
5. **Automate**: Integrate into CI/CD pipelines for continuous monitoring

## 🔗 Links

- [Ox Security Platform](https://app.ox.security/)
- [Ox Security GraphQL API Documentation](https://docs.ox.security/api-documentation/api-reference/api--issue/queries/get-issues)
- [SDLC Workspace Documentation](../README.md)
