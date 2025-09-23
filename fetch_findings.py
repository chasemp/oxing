#!/usr/bin/env python3
"""
Ox Security Findings Fetcher (GraphQL API)

This script fetches all security findings from the Ox Security platform using their GraphQL API.
It provides comprehensive security data including SCA, SAST, Secrets, Infrastructure, and other findings.

Usage:
    python fetch_findings.py [options]

Examples:
    # Fetch all security findings
    python fetch_findings.py

    # Fetch only Critical and High severity findings
    python fetch_findings.py --severities Critical High

    # Fetch findings for specific applications
    python fetch_findings.py --applications app1 app2

    # Fetch only SCA and SAST findings
    python fetch_findings.py --type SCA SAST

    # Fetch only Secret findings
    python fetch_findings.py --type Secret

    # Export to JSON file
    python fetch_findings.py --output security_findings.json

    # Show summary only
    python fetch_findings.py --summary-only

Based on Ox Security GraphQL API:
https://api.ox.security/graphql
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


class OxSecurityGraphQLFetcher:
    """Fetches all security issues from Ox Security GraphQL API using the comprehensive getIssues query"""
    
    def __init__(self, api_key: str = None, api_url: str = None, config_file: str = None):
        """
        Initialize the Ox Security GraphQL fetcher
        
        Args:
            api_key: Ox Security API key
            api_url: Ox Security GraphQL API URL  
            config_file: Path to YAML config file with credentials
        """
        self.api_key = api_key
        self.api_url = api_url or "https://api.ox.security/graphql"
        
        # Load config if not provided directly
        if not self.api_key:
            config = self._load_config(config_file)
            self.api_key = config.get('api_key') or os.getenv('OX_SECURITY_API_KEY')
            if not self.api_url or self.api_url == "https://api.ox.security/graphql":
                self.api_url = config.get('api_url', self.api_url)
        
        if not self.api_key:
            raise ValueError("Ox Security API key must be provided via parameter, config file, or OX_SECURITY_API_KEY environment variable")
        
        self.session = None
        logger.info(f"Initialized Ox Security GraphQL fetcher with API URL: {self.api_url}")
    
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
        
        # Ox Security GraphQL API uses direct API key authentication (no Bearer prefix)
        self.session.headers.update({
            'Authorization': self.api_key,  # Direct API key, not Bearer token
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'OxSecurity-SCA-Fetcher/1.0'
        })
        
        logger.info("Session configured with Ox Security GraphQL API authentication")
    
    def test_authentication(self) -> bool:
        """Test if authentication is working with a simple GraphQL query"""
        if not self.session:
            self.setup_session()
        
        # Simple test query to check authentication - using correct Ox Security API structure
        test_query = {
            'query': '''
            query {
                getApplications {
                    applications {
                        appId
                        appName
                        repoName
                    }
                    total
                }
            }
            '''
        }
        
        try:
            response = self.session.post(self.api_url, json=test_query, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'getApplications' in data['data']:
                    apps_response = data['data']['getApplications']
                    if 'applications' in apps_response:
                        apps = apps_response['applications']
                        logger.info(f"Authentication successful - found {len(apps)} applications")
                        return True
                    else:
                        logger.info("Authentication successful - getApplications response received")
                        return True
                elif 'errors' in data:
                    logger.error(f"GraphQL errors: {data['errors']}")
                    return False
                else:
                    logger.warning("Unexpected response structure")
                    return False
            else:
                logger.error(f"Authentication failed: HTTP {response.status_code}")
                logger.debug(f"Response: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error testing authentication: {e}")
            return False
    
    def fetch_applications(self) -> List[Dict[str, Any]]:
        """Fetch all applications from Ox Security"""
        if not self.session:
            self.setup_session()
        
        query = {
            'query': '''
            query {
                getApplications {
                    applications {
                        appId
                        appName
                        repoName
                        businessPriority
                        risk
                        violationCount
                    }
                    total
                }
            }
            '''
        }
        
        try:
            response = self.session.post(self.api_url, json=query, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            if 'data' in data and 'getApplications' in data['data']:
                apps_response = data['data']['getApplications']
                if 'applications' in apps_response:
                    apps = apps_response['applications']
                    logger.info(f"Found {len(apps)} applications")
                    return apps
                else:
                    logger.warning("No applications array in response")
                    return []
            elif 'errors' in data:
                logger.error(f"GraphQL errors fetching applications: {data['errors']}")
                return []
            else:
                logger.warning("No applications found in response")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching applications: {e}")
            return []
    
    def fetch_sbom_vulnerable_libraries(self) -> List[Dict[str, Any]]:
        """Fetch SCA vulnerabilities using the getSbomVulnerableLibraries query"""
        if not self.session:
            self.setup_session()
        
        # Try a different approach - maybe there are other SCA-related queries
        # Let's try to find SCA issues through the getIssues query with filters
        query = {
            'query': '''
            query {
                getIssues {
                    issues {
                        issueId
                        severity
                        description
                        createdAt
                        scaVulnerabilities {
                            cve
                            libName
                            libVersion
                            oxSeverity
                            description
                        }
                    }
                }
            }
            '''
        }
        
        try:
            response = self.session.post(self.api_url, json=query, timeout=20)
            
            if response.status_code != 200:
                logger.error(f"SBOM GraphQL request failed with status {response.status_code}")
                logger.error(f"Response: {response.text}")
                return []
            
            data = response.json()
            if 'data' in data and 'getIssues' in data['data']:
                sbom_response = data['data']['getIssues']
                # Debug: Log SBOM response structure
                logger.info(f"SBOM response structure: {list(sbom_response.keys())}")
                logger.info(f"SBOM response: {sbom_response}")
                
                if 'issues' in sbom_response:
                    issues = sbom_response['issues']
                    logger.info(f"Fetched {len(issues)} issues from getIssues query for SCA analysis")
                    
                    # Process issues to find SCA-related ones
                    processed_issues = []
                    for issue in issues:
                        # Check if this issue has SCA vulnerabilities
                        sca_vulns = issue.get('scaVulnerabilities', [])
                        if sca_vulns:
                            # This is an SCA issue
                            issue_id = issue.get('issueId', '')
                            severity = issue.get('severity', 'Unknown')
                            description = issue.get('description', '')
                            
                            # Process each SCA vulnerability
                            for vuln in sca_vulns:
                                processed_issue = {
                                    'issueId': issue_id,
                                    'issueType': 'SCA',
                                    'severity': vuln.get('oxSeverity', severity),
                                    'description': vuln.get('description', description),
                                    'createdAt': issue.get('createdAt'),
                                    'findings': [{
                                        'type': 'SCA',
                                        'cve': vuln.get('cve'),
                                        'libName': vuln.get('libName'),
                                        'libVersion': vuln.get('libVersion'),
                                        'oxSeverity': vuln.get('oxSeverity'),
                                        'description': vuln.get('description')
                                    }]
                                }
                                processed_issues.append(processed_issue)
                    
                    logger.info(f"Processed {len(processed_issues)} SCA issues from SBOM data")
                    return processed_issues
                else:
                    logger.warning("No issues array in getIssues response for SCA analysis")
                    return []
            elif 'errors' in data:
                logger.error(f"GraphQL errors fetching SBOM data: {data['errors']}")
                return []
            else:
                logger.debug("No SBOM data found")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching SBOM data: {e}")
            return []

    def fetch_all_issues(self) -> List[Dict[str, Any]]:
        """Fetch all issues from Ox Security using the comprehensive getIssues query"""
        if not self.session:
            self.setup_session()
        
        # Use the getIssues query with available fields from Ox Security schema
        query = {
            'query': '''
            query {
                getIssues {
                    issues {
                        issueId
                        severity
                        description
                        createdAt
                        scaVulnerabilities {
                            cve
                            libName
                            libVersion
                            oxSeverity
                            description
                        }
                    }
                }
            }
            '''
        }
        
        try:
            response = self.session.post(self.api_url, json=query, timeout=20)
            
            if response.status_code != 200:
                logger.error(f"GraphQL request failed with status {response.status_code}")
                logger.error(f"Response: {response.text}")
                return []
            
            data = response.json()
            if 'data' in data and 'getIssues' in data['data']:
                issues_response = data['data']['getIssues']
                if 'issues' in issues_response:
                    issues = issues_response['issues']
                    logger.info(f"Fetched {len(issues)} total issues from Ox Security")
                    
                    # Process issues with available fields
                    processed_issues = []
                    issue_type_counts = {}
                    
                    for issue in issues:
                        # Debug: Log available fields in the first issue
                        if len(processed_issues) == 0:
                            logger.info(f"Sample issue fields: {list(issue.keys())}")
                            logger.info(f"Sample issue data: {issue}")
                        
                        # Determine issue type based on issue ID pattern and available data
                        issue_id = issue.get('issueId', '')
                        if issue.get('scaVulnerabilities'):
                            issue_type = 'SCA'
                        elif 'iac.' in issue_id or 'infrastructure' in issue_id.lower():
                            issue_type = 'Infrastructure'
                        elif 'sast' in issue_id.lower() or 'code' in issue_id.lower():
                            issue_type = 'SAST'
                        elif 'secret' in issue_id.lower():
                            issue_type = 'Secret'
                        elif 'license' in issue_id.lower():
                            issue_type = 'License'
                        else:
                            issue_type = 'Other'
                        
                        issue_type_counts[issue_type] = issue_type_counts.get(issue_type, 0) + 1
                        
                        # Process each issue
                        processed_issue = {
                            'issueId': issue_id,
                            'issueType': issue_type,
                            'severity': issue.get('severity'),
                            'description': issue.get('description'),
                            'createdAt': issue.get('createdAt'),
                            'findings': []
                        }
                        
                        # Extract SCA vulnerabilities
                        for vuln in issue.get('scaVulnerabilities', []):
                            processed_issue['findings'].append({
                                'type': 'SCA',
                                'cve': vuln.get('cve'),
                                'libName': vuln.get('libName'),
                                'libVersion': vuln.get('libVersion'),
                                'oxSeverity': vuln.get('oxSeverity'),
                                'description': vuln.get('description')
                            })
                        
                        # For non-SCA issues, create a finding from the issue itself
                        if not issue.get('scaVulnerabilities'):
                            processed_issue['findings'].append({
                                'type': issue_type,
                                'issueId': issue_id,
                                'severity': issue.get('severity'),
                                'description': issue.get('description')
                            })
                        
                        processed_issues.append(processed_issue)
                    
                    logger.info(f"Processed {len(processed_issues)} issues with breakdown: {issue_type_counts}")
                    return processed_issues
                else:
                    logger.warning("No issues array in getIssues response")
                    return []
            elif 'errors' in data:
                logger.error(f"GraphQL errors fetching issues: {data['errors']}")
                return []
            else:
                logger.debug("No issues found")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching issues: {e}")
            return []
    
    def fetch_all_issues_hybrid(self, 
                               severities: List[str] = None,
                               applications: List[str] = None,
                               issue_types: List[str] = None,
                               include_sbom: bool = True) -> Dict[str, Any]:
        """
        Fetch all security issues using both getIssues and getSbomVulnerableLibraries queries
        
        Args:
            severities: List of severity levels to filter (Critical, High, Medium, Low)
            applications: List of application names/IDs to filter
            issue_types: List of issue types to filter (SCA, SAST, Secret, Infrastructure)
            include_sbom: Whether to include SBOM vulnerable libraries data
            
        Returns:
            Dict containing findings data and metadata
        """
        logger.info("Fetching all security issues using hybrid approach...")
        
        # First, get all applications
        all_apps = self.fetch_applications()
        if not all_apps:
            return {
                'error': 'No applications found or failed to fetch applications',
                'authentication_status': self.test_authentication()
            }
        
        # Filter applications if specified
        target_apps = all_apps
        if applications:
            target_apps = []
            for app in all_apps:
                if app['appName'] in applications or app['appId'] in applications:
                    target_apps.append(app)
            
            if not target_apps:
                logger.warning(f"No applications found matching: {applications}")
                logger.info(f"Available applications: {[app['appName'] for app in all_apps]}")
        
        # Fetch from both sources
        all_issues = []
        sbom_issues = []
        
        # Get issues from getIssues query
        logger.info("Fetching issues from getIssues query...")
        issues_from_getIssues = self.fetch_all_issues()
        all_issues.extend(issues_from_getIssues)
        
        # Get SCA issues from SBOM query if requested
        if include_sbom:
            logger.info("Fetching SCA issues from getSbomVulnerableLibraries query...")
            sbom_issues = self.fetch_sbom_vulnerable_libraries()
            all_issues.extend(sbom_issues)
        
        # Process findings and extract all types of vulnerabilities
        all_findings = []
        app_summary = {}
        issue_type_summary = {}
        processed_issues = []
        
        # Initialize app summary for all target apps
        for app in target_apps:
            app_name = app['appName']
            app_summary[app_name] = {
                'application_id': app['appId'],
                'total_issues': 0,
                'total_findings': 0,
                'by_issue_type': {}
            }
        
        # Process each issue
        for issue in all_issues:
            issue_id = issue['issueId']
            issue_severity = issue['severity']
            issue_type = issue['issueType']
            
            # Apply issue type filter
            if issue_types and issue_type not in issue_types:
                continue
            
            # Apply severity filter
            if severities and issue_severity not in severities:
                continue
            
            # Extract application ID from issue ID
            # Handle different formats:
            # 1. Numeric ID: "1062035891-policy-details" -> "1062035891"
            # 2. Named ID: "*GitHub-Settings (Life360-Sandbox)-policy-details" -> "*GitHub-Settings (Life360-Sandbox)"
            # 3. SBOM ID: "sbom-1062035891-library-version" -> "1062035891"
            if issue_id.startswith('sbom-'):
                # SBOM issues have format: sbom-appId-library-version
                parts = issue_id.split('-')
                if len(parts) >= 3:
                    app_id_from_issue = parts[1]  # Second part is app ID
                else:
                    app_id_from_issue = None
            elif '-' in issue_id:
                # Try to match against known application IDs
                for app in target_apps:
                    app_id = str(app['appId'])
                    if issue_id.startswith(app_id + '-'):
                        app_id_from_issue = app_id
                        break
                else:
                    # Fallback to first part before dash
                    app_id_from_issue = issue_id.split('-')[0]
            else:
                app_id_from_issue = None
            
            # Debug: Log issue ID and extracted app ID for first few issues
            if len(processed_issues) < 3:
                logger.info(f"Issue ID: {issue_id}, Extracted App ID: {app_id_from_issue}")
            
            # Find matching application
            matched_app = None
            app_name = 'Unknown'
            app_id = app_id_from_issue
            
            if app_id_from_issue:
                for app in target_apps:
                    if str(app['appId']) == str(app_id_from_issue):
                        matched_app = app
                        app_name = app['appName']
                        app_id = app['appId']
                        break
            
            # If no application filter or matched application
            if not applications or matched_app:
                
                # Process all findings in this issue
                for finding in issue.get('findings', []):
                    # Add context from the issue and application
                    finding_with_context = finding.copy()
                    finding_with_context.update({
                        'issueId': issue_id,
                        'issueType': issue_type,
                        'issueSeverity': issue_severity,
                        'issueStatus': issue.get('status'),
                        'issueTitle': issue.get('title'),
                        'issueDescription': issue.get('description'),
                        'applicationId': app_id,
                        'applicationName': app_name,
                        'repository': issue.get('repository'),
                        'createdAt': issue.get('createdAt'),
                        'updatedAt': issue.get('updatedAt')
                    })
                    all_findings.append(finding_with_context)
                
                # Update app summary
                if app_name in app_summary:
                    app_summary[app_name]['total_issues'] += 1
                    app_summary[app_name]['total_findings'] += len(issue.get('findings', []))
                    
                    # Track by issue type
                    if issue_type not in app_summary[app_name]['by_issue_type']:
                        app_summary[app_name]['by_issue_type'][issue_type] = 0
                    app_summary[app_name]['by_issue_type'][issue_type] += 1
                
                # Update issue type summary
                if issue_type not in issue_type_summary:
                    issue_type_summary[issue_type] = 0
                issue_type_summary[issue_type] += 1
            
            # Add to processed issues for tracking
            processed_issues.append(issue)
        
        logger.info(f"Processed {len(all_issues)} total issues ({len(issues_from_getIssues)} from getIssues, {len(sbom_issues)} from SBOM), extracted {len(all_findings)} findings")
        logger.info(f"Issue type breakdown: {issue_type_summary}")
        
        # Generate summary
        summary = self._generate_comprehensive_summary(all_findings, app_summary, issue_type_summary)
        
        return {
            'findings': all_findings,
            'summary': summary,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_applications_scanned': len(target_apps),
                'total_applications_available': len(all_apps),
                'total_issues_processed': len(all_issues),
                'issues_from_getIssues': len(issues_from_getIssues),
                'issues_from_sbom': len(sbom_issues),
                'filters': {
                    'severities': severities,
                    'applications': applications,
                    'issue_types': issue_types,
                    'include_sbom': include_sbom
                }
            }
        }

    def fetch_all_issues_comprehensive(self, 
                                     severities: List[str] = None,
                                     applications: List[str] = None,
                                     issue_types: List[str] = None) -> Dict[str, Any]:
        """
        Fetch all security issues from Ox Security using the comprehensive getIssues query
        
        Args:
            severities: List of severity levels to filter (Critical, High, Medium, Low)
            applications: List of application names/IDs to filter
            issue_types: List of issue types to filter (SCA, SAST, Secret, Infrastructure)
            
        Returns:
            Dict containing findings data and metadata
        """
        logger.info("Fetching all security issues from Ox Security...")
        
        # First, get all applications
        all_apps = self.fetch_applications()
        if not all_apps:
            return {
                'error': 'No applications found or failed to fetch applications',
                'authentication_status': self.test_authentication()
            }
        
        # Filter applications if specified
        target_apps = all_apps
        if applications:
            target_apps = []
            for app in all_apps:
                if app['appName'] in applications or app['appId'] in applications:
                    target_apps.append(app)
            
            if not target_apps:
                logger.warning(f"No applications found matching: {applications}")
                logger.info(f"Available applications: {[app['appName'] for app in all_apps]}")
        
        logger.info("Fetching all security issues from Ox Security...")
        
        # Get all issues using the comprehensive getIssues query
        all_issues = self.fetch_all_issues()
        
        # Process findings and extract all types of vulnerabilities
        all_findings = []
        app_summary = {}
        issue_type_summary = {}
        processed_issues = []
        
        # Initialize app summary for all target apps
        for app in target_apps:
            app_name = app['appName']
            app_summary[app_name] = {
                'application_id': app['appId'],
                'total_issues': 0,
                'total_findings': 0,
                'by_issue_type': {}
            }
        
        # Process each issue
        for issue in all_issues:
            issue_id = issue['issueId']
            issue_severity = issue['severity']
            issue_type = issue['issueType']
            
            # Apply issue type filter
            if issue_types and issue_type not in issue_types:
                continue
            
            # Apply severity filter
            if severities and issue_severity not in severities:
                continue
            
            # Extract application ID from issue ID
            # Handle different formats:
            # 1. Numeric ID: "1062035891-policy-details" -> "1062035891"
            # 2. Named ID: "*GitHub-Settings (Life360-Sandbox)-policy-details" -> "*GitHub-Settings (Life360-Sandbox)"
            if '-' in issue_id:
                # Try to match against known application IDs
                for app in target_apps:
                    app_id = str(app['appId'])
                    if issue_id.startswith(app_id + '-'):
                        app_id_from_issue = app_id
                        break
                else:
                    # Fallback to first part before dash
                    app_id_from_issue = issue_id.split('-')[0]
            else:
                app_id_from_issue = None
            
            # Debug: Log issue ID and extracted app ID for first few issues
            if len(processed_issues) < 3:
                logger.info(f"Issue ID: {issue_id}, Extracted App ID: {app_id_from_issue}")
            
            # Find matching application
            matched_app = None
            app_name = 'Unknown'
            app_id = app_id_from_issue
            
            if app_id_from_issue:
                for app in target_apps:
                    if str(app['appId']) == str(app_id_from_issue):
                        matched_app = app
                        app_name = app['appName']
                        app_id = app['appId']
                        break
            
            # If no application filter or matched application
            if not applications or matched_app:
                
                # Process all findings in this issue
                for finding in issue.get('findings', []):
                    # Add context from the issue and application
                    finding_with_context = finding.copy()
                    finding_with_context.update({
                        'issueId': issue_id,
                        'issueType': issue_type,
                        'issueSeverity': issue_severity,
                        'issueStatus': issue.get('status'),
                        'issueTitle': issue.get('title'),
                        'issueDescription': issue.get('description'),
                        'applicationId': app_id,
                        'applicationName': app_name,
                        'repository': issue.get('repository'),
                        'createdAt': issue.get('createdAt'),
                        'updatedAt': issue.get('updatedAt')
                    })
                    all_findings.append(finding_with_context)
                
                # Update app summary
                if app_name in app_summary:
                    app_summary[app_name]['total_issues'] += 1
                    app_summary[app_name]['total_findings'] += len(issue.get('findings', []))
                    
                    # Track by issue type
                    if issue_type not in app_summary[app_name]['by_issue_type']:
                        app_summary[app_name]['by_issue_type'][issue_type] = 0
                    app_summary[app_name]['by_issue_type'][issue_type] += 1
                
                # Update issue type summary
                if issue_type not in issue_type_summary:
                    issue_type_summary[issue_type] = 0
                issue_type_summary[issue_type] += 1
            
            # Add to processed issues for tracking
            processed_issues.append(issue)
        
        logger.info(f"Processed {len(all_issues)} issues, extracted {len(all_findings)} findings")
        logger.info(f"Issue type breakdown: {issue_type_summary}")
        
        # Generate summary
        summary = self._generate_comprehensive_summary(all_findings, app_summary, issue_type_summary)
        
        return {
            'findings': all_findings,
            'summary': summary,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_applications_scanned': len(target_apps),
                'total_applications_available': len(all_apps),
                'total_issues_processed': len(all_issues),
                'filters': {
                    'severities': severities,
                    'applications': applications,
                    'issue_types': issue_types
                }
            }
        }
    
    def _generate_comprehensive_summary(self, findings: List[Dict[str, Any]], app_summary: Dict[str, Any], issue_type_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive summary statistics from all types of findings"""
        summary = {
            'total_findings': len(findings),
            'by_severity': {},
            'by_issue_type': issue_type_summary,
            'by_finding_type': {},
            'by_application': app_summary,
            'by_package': {},
            'by_repository': {},
            'unique_cves': set(),
            'top_packages': {},
            'top_repositories': {},
            'severity_distribution': {}
        }
        
        for finding in findings:
            # Severity breakdown
            severity = finding.get('oxSeverity', finding.get('issueSeverity', 'Unknown'))
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Finding type breakdown
            finding_type = finding.get('type', 'Unknown')
            summary['by_finding_type'][finding_type] = summary['by_finding_type'].get(finding_type, 0) + 1
            
            # Repository breakdown
            repo = finding.get('repository', 'Unknown')
            summary['by_repository'][repo] = summary['by_repository'].get(repo, 0) + 1
            
            # Package breakdown (for SCA findings)
            if finding_type == 'SCA':
                lib_name = finding.get('libName', 'Unknown')
                lib_version = finding.get('libVersion', '')
                package = f"{lib_name}:{lib_version}" if lib_version else lib_name
                summary['by_package'][package] = summary['by_package'].get(package, 0) + 1
                
                # CVE tracking
                cve = finding.get('cve')
                if cve:
                    summary['unique_cves'].add(cve)
                
                # Top vulnerable packages
                summary['top_packages'][lib_name] = summary['top_packages'].get(lib_name, 0) + 1
        
        # Convert set to list and count
        summary['unique_cves'] = list(summary['unique_cves'])
        summary['unique_cves_count'] = len(summary['unique_cves'])
        
        # Sort top packages and repositories
        summary['top_packages'] = dict(sorted(summary['top_packages'].items(), key=lambda x: x[1], reverse=True))
        summary['top_repositories'] = dict(sorted(summary['by_repository'].items(), key=lambda x: x[1], reverse=True))
        
        return summary
    
    def _generate_summary(self, findings: List[Dict[str, Any]], app_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics from findings (legacy method for SCA-only)"""
        summary = {
            'total_findings': len(findings),
            'by_severity': {},
            'by_application': app_summary,
            'by_package': {},
            'unique_cves': set(),
            'top_packages': {},
            'severity_distribution': {}
        }
        
        for finding in findings:
            # Severity breakdown (use oxSeverity from Ox Security)
            severity = finding.get('oxSeverity', finding.get('issueSeverity', 'Unknown'))
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Package breakdown
            lib_name = finding.get('libName', 'Unknown')
            lib_version = finding.get('libVersion', '')
            package = f"{lib_name}:{lib_version}" if lib_version else lib_name
            summary['by_package'][package] = summary['by_package'].get(package, 0) + 1
            
            # CVE tracking
            cve = finding.get('cve')
            if cve:
                summary['unique_cves'].add(cve)
            
            # Top vulnerable packages
            summary['top_packages'][lib_name] = summary['top_packages'].get(lib_name, 0) + 1
        
        # Convert set to list and count
        summary['unique_cves'] = list(summary['unique_cves'])
        summary['unique_cves_count'] = len(summary['unique_cves'])
        
        # Sort top packages
        summary['top_packages'] = dict(sorted(summary['top_packages'].items(), key=lambda x: x[1], reverse=True))
        
        return summary
    
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
        metadata = findings.get('metadata', {})
        
        print("\n" + "="*60)
        print("📊 OX SECURITY SECURITY ISSUES SUMMARY")
        print("="*60)
        
        print(f"🔍 Total Findings: {summary.get('total_findings', 0)}")
        print(f"🎯 Unique CVEs: {summary.get('unique_cves_count', 0)}")
        print(f"📱 Applications Scanned: {metadata.get('total_applications_scanned', 0)}")
        print(f"📋 Total Issues Processed: {metadata.get('total_issues_processed', 0)}")
        
        # Show hybrid approach breakdown
        if 'issues_from_getIssues' in metadata and 'issues_from_sbom' in metadata:
            print(f"🔧 Data Sources: {metadata.get('issues_from_getIssues', 0)} from getIssues, {metadata.get('issues_from_sbom', 0)} from SBOM")
        
        # Issue type breakdown
        by_issue_type = summary.get('by_issue_type', {})
        if by_issue_type:
            print(f"\n🔍 By Issue Type:")
            for issue_type, count in sorted(by_issue_type.items(), key=lambda x: x[1], reverse=True):
                print(f"   {issue_type}: {count}")
        
        # Finding type breakdown
        by_finding_type = summary.get('by_finding_type', {})
        if by_finding_type:
            print(f"\n📊 By Finding Type:")
            for finding_type, count in sorted(by_finding_type.items(), key=lambda x: x[1], reverse=True):
                print(f"   {finding_type}: {count}")
        
        # Severity breakdown
        by_severity = summary.get('by_severity', {})
        if by_severity:
            print(f"\n📈 By Severity:")
            for severity, count in sorted(by_severity.items(), key=lambda x: x[1], reverse=True):
                print(f"   {severity}: {count}")
        
        # Application breakdown
        by_application = summary.get('by_application', {})
        if by_application:
            print(f"\n📱 By Application:")
            for app_name, app_data in by_application.items():
                findings_count = app_data.get('total_findings', 0)
                issue_count = app_data.get('total_issues', 0)
                print(f"   {app_name}: {findings_count} findings ({issue_count} issues)")
                
                # Show breakdown by issue type for this app
                by_issue_type = app_data.get('by_issue_type', {})
                if by_issue_type:
                    issue_breakdown = ", ".join([f"{k}: {v}" for k, v in by_issue_type.items()])
                    print(f"      └─ {issue_breakdown}")
        
        # Top repositories
        top_repositories = summary.get('top_repositories', {})
        if top_repositories:
            print(f"\n📁 Top Repositories:")
            for repo, count in list(top_repositories.items())[:10]:
                print(f"   {repo}: {count} findings")
        
        # Top vulnerable packages (SCA only)
        top_packages = summary.get('top_packages', {})
        if top_packages:
            print(f"\n📦 Top Vulnerable Packages (SCA):")
            for package, count in list(top_packages.items())[:10]:
                print(f"   {package}: {count} vulnerabilities")
        
        # Metadata
        if metadata:
            print(f"\n📊 Scan Details:")
            print(f"   Timestamp: {metadata.get('timestamp', 'N/A')}")
            filters = metadata.get('filters', {})
            if filters.get('severities'):
                print(f"   Severity Filter: {', '.join(filters['severities'])}")
            if filters.get('applications'):
                print(f"   Application Filter: {', '.join(filters['applications'])}")
            if filters.get('issue_types'):
                print(f"   Issue Type Filter: {', '.join(filters['issue_types'])}")
        
        print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Fetch all security findings from Ox Security GraphQL API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Fetch all findings (hybrid approach)
  %(prog)s --severities Critical High        # Only Critical and High
  %(prog)s --applications app1 app2         # Specific applications
  %(prog)s --type SCA SAST                  # Only SCA and SAST findings
  %(prog)s --type Secret                    # Only Secret findings
  %(prog)s --no-sbom                        # Exclude SBOM data, use getIssues only
  %(prog)s --output findings.json           # Export to JSON
  %(prog)s --summary-only                   # Show summary only
        """
    )
    
    parser.add_argument('--severities', nargs='+', 
                       choices=['Critical', 'High', 'Medium', 'Low'],
                       help='Filter by severity levels')
    parser.add_argument('--applications', nargs='+', metavar='APP',
                       help='Filter by application names or IDs')
    parser.add_argument('--type', '--issue-types', nargs='+', 
                       choices=['SCA', 'SAST', 'Secret', 'Infrastructure', 'License', 'Other'],
                       help='Filter by issue types')
    parser.add_argument('--include-sbom', action='store_true', default=True,
                       help='Include SBOM vulnerable libraries data (default: True)')
    parser.add_argument('--no-sbom', action='store_true',
                       help='Exclude SBOM vulnerable libraries data')
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
    parser.add_argument('--list-applications', action='store_true',
                       help='List available applications and exit')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize the fetcher
        fetcher = OxSecurityGraphQLFetcher(config_file=args.config)
        
        # Test authentication if requested
        if args.test_auth:
            print("🔐 Testing Ox Security GraphQL API authentication...")
            auth_success = fetcher.test_authentication()
            if auth_success:
                print("✅ Authentication successful!")
                sys.exit(0)
            else:
                print("❌ Authentication failed!")
                sys.exit(1)
        
        # List applications if requested
        if args.list_applications:
            print("📱 Listing available applications...")
            apps = fetcher.fetch_applications()
            if apps:
                print(f"✅ Found {len(apps)} applications:")
                for app in apps:
                    repo_info = f" - {app['repoName']}" if app.get('repoName') else ""
                    risk_info = f" (Risk: {app['risk']})" if app.get('risk') else ""
                    violations = f" [{app['violationCount']} violations]" if app.get('violationCount') else ""
                    print(f"   {app['appName']} (ID: {app['appId']}){repo_info}{risk_info}{violations}")
            else:
                print("❌ No applications found!")
            sys.exit(0)
        
        # Determine whether to include SBOM data
        include_sbom = args.include_sbom and not args.no_sbom
        
        # Fetch findings using hybrid approach (getIssues + SBOM)
        findings = fetcher.fetch_all_issues_hybrid(
            severities=args.severities,
            applications=args.applications,
            issue_types=args.type,
            include_sbom=include_sbom
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
                    print(json.dumps(sample, indent=2)[:800] + "..." if len(str(sample)) > 800 else json.dumps(sample, indent=2))
    
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
