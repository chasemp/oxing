#!/usr/bin/env python3
"""
Ox Security SCA Findings Fetcher

This script fetches all SCA (Software Composition Analysis) findings from the Ox Security platform
using their REST API. It provides comprehensive vulnerability data for open source dependencies.

Usage:
    python fetch_sca_findings.py [options]

Examples:
    # Fetch all SCA findings
    python fetch_sca_findings.py

    # Fetch only Critical and High severity findings
    python fetch_sca_findings.py --severities Critical High

    # Fetch findings for specific repositories
    python fetch_sca_findings.py --repositories repo1 repo2

    # Export to JSON file
    python fetch_sca_findings.py --output sca_findings.json

    # Show summary only
    python fetch_sca_findings.py --summary-only

Based on Ox Security API documentation:
https://docs.ox.security/api-documentation/working-with-ox-apis
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

import requests
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('ox_security_sca.log')
    ]
)
logger = logging.getLogger(__name__)


class OxSecuritySCAFetcher:
    """Fetches SCA findings from Ox Security API"""
    
    def __init__(self, api_key: str = None, api_url: str = None, config_file: str = None):
        """
        Initialize the Ox Security SCA fetcher
        
        Args:
            api_key: Ox Security API key
            api_url: Ox Security API base URL  
            config_file: Path to YAML config file with credentials
        """
        self.api_key = api_key
        self.api_url = api_url or "https://api.ox.security"
        
        # Load config if not provided directly
        if not self.api_key:
            config = self._load_config(config_file)
            self.api_key = config.get('api_key') or os.getenv('OX_SECURITY_API_KEY')
            if not self.api_url:
                self.api_url = config.get('api_url', self.api_url)
        
        if not self.api_key:
            raise ValueError("Ox Security API key must be provided via parameter, config file, or OX_SECURITY_API_KEY environment variable")
        
        self.session = None
        logger.info(f"Initialized Ox Security SCA fetcher with API URL: {self.api_url}")
    
    def _load_config(self, config_file: str = None) -> Dict[str, str]:
        """Load configuration from YAML file"""
        if not config_file:
            # Try default locations
            possible_files = [
                "secret.yaml",
                "secrets.yaml", 
                "config.yaml",
                "ox_security.yaml"
            ]
            
            for file_path in possible_files:
                if Path(file_path).exists():
                    config_file = file_path
                    break
        
        if not config_file or not Path(config_file).exists():
            logger.debug("No config file found, using environment variables")
            return {}
        
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                
            # Extract ox_security section
            ox_config = config.get('ox_security', {})
            logger.info(f"Loaded configuration from {config_file}")
            return ox_config
            
        except Exception as e:
            logger.warning(f"Failed to load config from {config_file}: {e}")
            return {}
    
    def setup_session(self):
        """Set up requests session with authentication"""
        self.session = requests.Session()
        
        # Ox Security uses API key authentication
        # Based on their docs, this is typically passed as a header
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'OxSecurity-SCA-Fetcher/1.0'
        })
        
        logger.info("Session configured with Ox Security API authentication")
    
    def test_authentication(self) -> bool:
        """Test if authentication is working"""
        if not self.session:
            self.setup_session()
        
        # Try a simple API call to test authentication
        test_endpoints = [
            '/api/v1/health',
            '/api/v1/user',
            '/api/v1/organizations',
            '/v1/health',
            '/v1/user',
            '/v1/organizations'
        ]
        
        for endpoint in test_endpoints:
            try:
                url = f"{self.api_url}{endpoint}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    logger.info(f"Authentication successful via {endpoint}")
                    return True
                elif response.status_code in [401, 403]:
                    logger.error(f"Authentication failed: {response.status_code}")
                    logger.debug(f"Response: {response.text}")
                    return False
                else:
                    logger.debug(f"Endpoint {endpoint}: {response.status_code}")
                    
            except Exception as e:
                logger.debug(f"Error testing {endpoint}: {e}")
                continue
        
        logger.warning("Could not verify authentication with standard endpoints")
        return False
    
    def discover_sca_endpoints(self) -> List[str]:
        """Discover available SCA-related endpoints"""
        if not self.session:
            self.setup_session()
        
        # Ox Security specific endpoints based on their documentation
        potential_endpoints = [
            # Primary Ox Security endpoint from documentation
            '/v1/issues',
            '/api/v1/issues',
            
            # Alternative issue endpoints
            '/v1/sca/issues',
            '/api/v1/sca/issues',
            '/v1/vulnerabilities',
            '/api/v1/vulnerabilities',
            
            # Legacy/alternative patterns
            '/api/v1/sca/findings',
            '/api/v1/sca/vulnerabilities',
            '/api/v1/findings',
            '/v1/findings',
            '/v1/sca/findings',
            
            # Common security platform patterns (fallback)
            '/api/v1/security/vulnerabilities',
            '/api/v2/issues',
            '/api/v2/vulnerabilities',
            '/v2/issues',
            '/v2/vulnerabilities'
        ]
        
        working_endpoints = []
        
        logger.info("Discovering SCA endpoints...")
        
        for endpoint in potential_endpoints:
            try:
                url = f"{self.api_url}{endpoint}"
                
                # Try with minimal parameters
                params = {'limit': 5}
                response = self.session.get(url, params=params, timeout=10)
                
                if response.status_code == 200:
                    logger.info(f"✅ Working endpoint: {endpoint}")
                    working_endpoints.append(endpoint)
                    
                    # Show sample data structure
                    try:
                        data = response.json()
                        if isinstance(data, dict):
                            if 'items' in data or 'data' in data or 'results' in data:
                                items_key = 'items' if 'items' in data else 'data' if 'data' in data else 'results'
                                items = data[items_key]
                                logger.info(f"   📊 Found {len(items)} {items_key}")
                                if items and isinstance(items[0], dict):
                                    sample_keys = list(items[0].keys())[:8]
                                    logger.info(f"   🔑 Sample keys: {sample_keys}")
                            else:
                                keys = list(data.keys())[:8]
                                logger.info(f"   🔑 Response keys: {keys}")
                        elif isinstance(data, list):
                            logger.info(f"   📊 Direct list with {len(data)} items")
                            if data and isinstance(data[0], dict):
                                sample_keys = list(data[0].keys())[:8]
                                logger.info(f"   🔑 Sample keys: {sample_keys}")
                    except Exception as parse_error:
                        logger.debug(f"   Parse error: {parse_error}")
                        logger.info(f"   📄 Response length: {len(response.text)} chars")
                
                elif response.status_code == 404:
                    continue  # Skip 404s silently
                elif response.status_code in [401, 403]:
                    logger.warning(f"🔐 Auth issue for {endpoint}: {response.status_code}")
                elif response.status_code == 400:
                    logger.debug(f"🔧 Bad request for {endpoint} (might need different params)")
                else:
                    logger.debug(f"❓ {endpoint}: HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                logger.debug(f"⏱️ Timeout: {endpoint}")
            except Exception as e:
                logger.debug(f"Error testing {endpoint}: {e}")
                continue
        
        logger.info(f"Found {len(working_endpoints)} working SCA endpoints")
        return working_endpoints
    
    def fetch_sca_findings(self, 
                          severities: List[str] = None,
                          repositories: List[str] = None,
                          limit: int = None,
                          status: str = None) -> Dict[str, Any]:
        """
        Fetch SCA findings from Ox Security
        
        Args:
            severities: List of severity levels to filter (Critical, High, Medium, Low)
            repositories: List of repository names to filter
            limit: Maximum number of findings to retrieve
            status: Status filter (open, closed, etc.)
            
        Returns:
            Dict containing findings data and metadata
        """
        if not self.session:
            self.setup_session()
        
        logger.info("Fetching SCA findings from Ox Security...")
        
        # Discover working endpoints first
        working_endpoints = self.discover_sca_endpoints()
        
        if not working_endpoints:
            logger.error("No working SCA endpoints found")
            return {
                'error': 'No accessible SCA endpoints found',
                'endpoints_tested': len(self.discover_sca_endpoints.__defaults__ or []),
                'authentication_status': self.test_authentication()
            }
        
        # Use the first working endpoint (most likely to be the main one)
        primary_endpoint = working_endpoints[0]
        logger.info(f"Using primary endpoint: {primary_endpoint}")
        
        # Build query parameters based on Ox Security API documentation
        params = {
            'type': 'SCA'  # Filter for SCA vulnerabilities specifically
        }
        
        if severities:
            # Ox Security might use different severity parameter names
            params['severity'] = severities if len(severities) > 1 else severities[0]
        
        if repositories:
            # Try different repository parameter names
            params['repository'] = repositories if len(repositories) > 1 else repositories[0]
        
        if status:
            params['status'] = status
        
        if limit:
            params['limit'] = limit
        else:
            params['limit'] = 1000  # Default high limit to get comprehensive data
        
        # Fetch findings
        try:
            url = f"{self.api_url}{primary_endpoint}"
            logger.info(f"Fetching from: {url}")
            logger.debug(f"Parameters: {params}")
            
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"Successfully fetched SCA findings")
            
            # Process and structure the response
            findings = self._process_findings_response(data)
            
            # Add metadata
            findings['metadata'] = {
                'timestamp': datetime.now().isoformat(),
                'endpoint': primary_endpoint,
                'parameters': params,
                'total_endpoints_discovered': len(working_endpoints),
                'available_endpoints': working_endpoints
            }
            
            return findings
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response body: {e.response.text}")
            
            return {
                'error': str(e),
                'endpoint': primary_endpoint,
                'parameters': params
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {
                'error': str(e),
                'endpoint': primary_endpoint
            }
    
    def _process_findings_response(self, data: Any) -> Dict[str, Any]:
        """Process the raw API response into structured findings data"""
        findings = {
            'findings': [],
            'summary': {
                'total_findings': 0,
                'by_severity': {},
                'by_repository': {},
                'by_package': {},
                'unique_cves': set()
            }
        }
        
        # Extract findings from Ox Security response structure
        items = []
        if isinstance(data, dict):
            # Ox Security API returns issues in an 'issues' key
            if 'issues' in data:
                issues = data['issues']
                # Extract SCA vulnerabilities from each issue
                for issue in issues:
                    sca_vulns = issue.get('scaVulnerabilities', [])
                    for vuln in sca_vulns:
                        # Add issue context to vulnerability
                        vuln['issueId'] = issue.get('issueId')
                        vuln['repository'] = issue.get('repository')
                        vuln['project'] = issue.get('project')
                        items.append(vuln)
            elif 'items' in data:
                items = data['items']
            elif 'data' in data:
                items = data['data']
            elif 'results' in data:
                items = data['results']
            elif 'findings' in data:
                items = data['findings']
            else:
                # If it's a dict but no standard collection key, treat as single item
                items = [data]
        elif isinstance(data, list):
            items = data
        
        findings['findings'] = items
        findings['summary']['total_findings'] = len(items)
        
        # Generate summary statistics using Ox Security field names
        for item in items:
            if not isinstance(item, dict):
                continue
            
            # Severity breakdown (Ox Security uses 'oxSeverity')
            severity = item.get('oxSeverity', item.get('severity', 'Unknown'))
            findings['summary']['by_severity'][severity] = findings['summary']['by_severity'].get(severity, 0) + 1
            
            # Repository breakdown
            repo = item.get('repository', item.get('repo', item.get('project', 'Unknown')))
            findings['summary']['by_repository'][repo] = findings['summary']['by_repository'].get(repo, 0) + 1
            
            # Package breakdown (Ox Security uses 'libName')
            package = item.get('libName', item.get('package', item.get('component', item.get('dependency', 'Unknown'))))
            if item.get('libVersion'):
                package = f"{package}:{item['libVersion']}"
            findings['summary']['by_package'][package] = findings['summary']['by_package'].get(package, 0) + 1
            
            # CVE tracking
            cve = item.get('cve', item.get('cve_id', item.get('vulnerability_id')))
            if cve:
                findings['summary']['unique_cves'].add(cve)
        
        # Convert set to list for JSON serialization
        findings['summary']['unique_cves'] = list(findings['summary']['unique_cves'])
        findings['summary']['unique_cves_count'] = len(findings['summary']['unique_cves'])
        
        return findings
    
    def export_findings(self, findings: Dict[str, Any], output_file: str):
        """Export findings to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(findings, f, indent=2, default=str)
            logger.info(f"Findings exported to {output_file}")
        except Exception as e:
            logger.error(f"Failed to export findings: {e}")
    
    def print_summary(self, findings: Dict[str, Any]):
        """Print a formatted summary of the findings"""
        if 'error' in findings:
            print(f"\n❌ Error: {findings['error']}")
            return
        
        summary = findings.get('summary', {})
        
        print("\n" + "="*60)
        print("📊 OX SECURITY SCA FINDINGS SUMMARY")
        print("="*60)
        
        print(f"🔍 Total Findings: {summary.get('total_findings', 0)}")
        print(f"🎯 Unique CVEs: {summary.get('unique_cves_count', 0)}")
        
        # Severity breakdown
        by_severity = summary.get('by_severity', {})
        if by_severity:
            print(f"\n📈 By Severity:")
            for severity, count in sorted(by_severity.items(), key=lambda x: x[1], reverse=True):
                print(f"   {severity}: {count}")
        
        # Top repositories
        by_repository = summary.get('by_repository', {})
        if by_repository:
            print(f"\n📁 Top Repositories:")
            sorted_repos = sorted(by_repository.items(), key=lambda x: x[1], reverse=True)[:10]
            for repo, count in sorted_repos:
                print(f"   {repo}: {count} findings")
        
        # Top packages
        by_package = summary.get('by_package', {})
        if by_package:
            print(f"\n📦 Top Vulnerable Packages:")
            sorted_packages = sorted(by_package.items(), key=lambda x: x[1], reverse=True)[:10]
            for package, count in sorted_packages:
                print(f"   {package}: {count} findings")
        
        metadata = findings.get('metadata', {})
        if metadata:
            print(f"\n📊 API Details:")
            print(f"   Endpoint: {metadata.get('endpoint', 'N/A')}")
            print(f"   Timestamp: {metadata.get('timestamp', 'N/A')}")
            if 'available_endpoints' in metadata:
                print(f"   Available endpoints: {len(metadata['available_endpoints'])}")
        
        print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Fetch SCA findings from Ox Security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Fetch all findings
  %(prog)s --severities Critical High        # Only Critical and High
  %(prog)s --repositories repo1 repo2       # Specific repositories
  %(prog)s --output findings.json           # Export to JSON
  %(prog)s --summary-only                   # Show summary only
  %(prog)s --limit 100                      # Limit to 100 findings
        """
    )
    
    parser.add_argument('--severities', nargs='+', 
                       choices=['Critical', 'High', 'Medium', 'Low'],
                       help='Filter by severity levels')
    parser.add_argument('--repositories', nargs='+', metavar='REPO',
                       help='Filter by repository names')
    parser.add_argument('--status', choices=['open', 'closed', 'all'],
                       default='open', help='Filter by finding status')
    parser.add_argument('--limit', type=int, metavar='N',
                       help='Maximum number of findings to retrieve')
    parser.add_argument('--output', '-o', metavar='FILE',
                       help='Export findings to JSON file')
    parser.add_argument('--summary-only', action='store_true',
                       help='Show only summary, not full findings')
    parser.add_argument('--config', '-c', default='secret.yaml',
                       help='Path to configuration file (default: secret.yaml)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--test-auth', action='store_true',
                       help='Test authentication and exit')
    parser.add_argument('--discover-endpoints', action='store_true',
                       help='Discover available endpoints and exit')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize the fetcher
        fetcher = OxSecuritySCAFetcher(config_file=args.config)
        
        # Test authentication if requested
        if args.test_auth:
            print("🔐 Testing Ox Security API authentication...")
            auth_success = fetcher.test_authentication()
            if auth_success:
                print("✅ Authentication successful!")
                sys.exit(0)
            else:
                print("❌ Authentication failed!")
                sys.exit(1)
        
        # Discover endpoints if requested
        if args.discover_endpoints:
            print("🔍 Discovering Ox Security SCA endpoints...")
            endpoints = fetcher.discover_sca_endpoints()
            if endpoints:
                print(f"✅ Found {len(endpoints)} working endpoints:")
                for endpoint in endpoints:
                    print(f"   {endpoint}")
            else:
                print("❌ No working endpoints found!")
            sys.exit(0)
        
        # Fetch findings
        findings = fetcher.fetch_sca_findings(
            severities=args.severities,
            repositories=args.repositories,
            limit=args.limit,
            status=args.status
        )
        
        # Export to file if requested
        if args.output:
            fetcher.export_findings(findings, args.output)
        
        # Show results
        if args.summary_only:
            fetcher.print_summary(findings)
        else:
            fetcher.print_summary(findings)
            if not args.output:
                print(f"\n💾 Full findings data available. Use --output to save.")
                if findings.get('findings'):
                    print(f"📄 Sample finding:")
                    sample = findings['findings'][0]
                    print(json.dumps(sample, indent=2)[:500] + "..." if len(str(sample)) > 500 else json.dumps(sample, indent=2))
    
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
