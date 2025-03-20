import re
import hashlib
import logging
import ipaddress
from typing import Set, Dict, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from abuse_checker import AbuseIPDBChecker
from domain_resolver import DomainResolver

class EmailAnalyzer:
    def __init__(self, abuseipdb_api_key: str):
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        self.ip_url_pattern = re.compile(
            r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/|:|\Z)'
        )
        self.processed_hashes: Set[str] = set()
        self.domain_resolver = DomainResolver()
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.abuse_checker = AbuseIPDBChecker(abuseipdb_api_key)

    def get_file_hash(self, filepath: str) -> str:
        """Generate a hash of file content to prevent redundant processing."""
        with open(filepath, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()

    def extract_urls(self, text: str) -> set:
        """Extract unique URLs from text content."""
        return set(self.url_pattern.findall(text))

    def extract_sender_info(self, email_address: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract domain/IP and resolve if needed from email address."""
        try:
            sender_host = email_address.split('@', 1)[1].strip('<>')

            try:
                ipaddress.ip_address(sender_host)
                return sender_host, sender_host
            except ValueError:
                ip = self.domain_resolver.get_ip_address(sender_host)
                return sender_host, ip
        except (IndexError, AttributeError):
            return None, None

    def extract_email_from_header(self, header: str) -> Optional[str]:
        """Extract clean email address from header."""
        if not header:
            return None
            
        # Match email address inside angle brackets
        match = re.search(r'<([^<>]+@[^<>]+)>', header)
        if match:
            return match.group(1)
            
        # Match plain email address
        match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', header)
        if match:
            return match.group(1)
            
        return None

    def parse_authentication_results(self, header: str) -> Dict:
        """Parse Authentication-Results header."""
        auth_results = {
            'spf': None,
            'dkim': None,
            'dmarc': None
        }
        
        if not header:
            return auth_results
            
        # Extract SPF
        spf_match = re.search(r'spf=([a-z]+)', header.lower())
        if spf_match:
            auth_results['spf'] = spf_match.group(1)
            
        # Extract DKIM
        dkim_match = re.search(r'dkim=([a-z]+)', header.lower())
        if dkim_match:
            auth_results['dkim'] = dkim_match.group(1)
            
        # Extract DMARC
        dmarc_match = re.search(r'dmarc=([a-z]+)', header.lower())
        if dmarc_match:
            auth_results['dmarc'] = dmarc_match.group(1)
            
        return auth_results

    def parse_url_host_and_ip(self, url: str) -> Tuple[str, Optional[str]]:
        """Extract host from URL and resolve if needed."""
        try:
            ip_match = self.ip_url_pattern.match(url)
            if ip_match:
                ip = ip_match.group(1)
                return ip, ip

            parsed = urlparse(url)
            host = parsed.netloc

            if ':' in host:
                host = host.split(':', 1)[0]

            try:
                ipaddress.ip_address(host)
                return host, host
            except ValueError:
                ip = self.domain_resolver.get_ip_address(host) if host else None
                return host, ip
        except Exception as e:
            logging.error(f"Error parsing URL {url}: {str(e)}")
            return url, None

    def check_ip_abuse(self, ip: Optional[str]) -> Dict:
        """Check IP for abuse reports if it exists."""
        if ip:
            return self.abuse_checker.check_ip(ip)
        return {"error": "No IP available"}

    def is_suspicious(self, results: Dict) -> Tuple[bool, list]:
        """Check if any indicators are suspicious."""
        suspicious_findings = []

        # Check sender authentication
        auth_results = results.get('authentication_results', {})
        if auth_results:
            if auth_results.get('spf') == 'fail':
                suspicious_findings.append("SPF authentication failed")
            if auth_results.get('dkim') == 'fail':
                suspicious_findings.append("DKIM authentication failed")
            if auth_results.get('dmarc') == 'fail':
                suspicious_findings.append("DMARC authentication failed")

        # Check sender email vs return path
        sender_email = results.get('sender_email')
        return_path_email = results.get('return_path_email')
        if sender_email and return_path_email and sender_email != return_path_email:
            suspicious_findings.append(f"Sender email ({sender_email}) does not match return path ({return_path_email})")

        # Check sender IP
        if results.get('sender_ip'):
            abuse_report = results.get('sender_abuse_report', {})
            if not isinstance(abuse_report, dict):
                abuse_report = {}

            # Convert to int before comparison
            abuse_score = int(abuse_report.get('abuseConfidenceScore', 0))
            total_reports = int(abuse_report.get('totalReports', 0))

            if abuse_score > 0:
                suspicious_findings.append(f"Sender IP has abuse score of {abuse_score}%")

            if total_reports > 0:
                suspicious_findings.append(f"Sender IP has {total_reports} abuse reports")

        # Check URLs
        for url_info in results.get('urls', []):
            if url_info.get('ip'):
                abuse_report = url_info.get('abuse_report', {})
                if isinstance(abuse_report, dict):
                    # Convert to int before comparison
                    abuse_score = int(abuse_report.get('abuseConfidenceScore', 0))
                    total_reports = int(abuse_report.get('totalReports', 0))

                    if abuse_score > 0:
                        suspicious_findings.append(f"URL IP has abuse score of {abuse_score}%")
                    if total_reports > 0:
                        suspicious_findings.append(f"URL IP has {total_reports} abuse reports")

        return len(suspicious_findings) > 0, suspicious_findings

    def analyze_email_file(self, filepath: str) -> Dict:
        """Analyze a single email file without modifying it."""
        try:
            import email
            from email import policy
            
            file_hash = self.get_file_hash(filepath)

            if file_hash in self.processed_hashes:
                return None

            self.processed_hashes.add(file_hash)

            with open(filepath, 'rb') as f:
                msg = email.message_from_bytes(f.read(), policy=policy.default)

            # Extract sender information
            from_header = msg.get('From', '')
            sender_email = self.extract_email_from_header(from_header)
            sender_host, sender_ip = self.extract_sender_info(from_header)
            sender_abuse_report = self.check_ip_abuse(sender_ip)
            
            # Extract receiver information
            to_header = msg.get('To', '')
            receiver_email = self.extract_email_from_header(to_header)
            
            # Extract return path
            return_path_header = msg.get('Return-Path', '')
            return_path_email = self.extract_email_from_header(return_path_header)
            
            # Parse authentication results
            auth_results_header = msg.get('Authentication-Results', '')
            authentication_results = self.parse_authentication_results(auth_results_header)

            # Extract and check URLs
            urls_info = []
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    content = part.get_content()
                    urls = self.extract_urls(content)
                    for url in urls:
                        host, ip = self.parse_url_host_and_ip(url)
                        abuse_report = self.check_ip_abuse(ip)

                        urls_info.append({
                            'url': url,
                            'host': host,
                            'is_ip_host': host == ip,
                            'ip': ip,
                            'abuse_report': abuse_report
                        })

            results = {
                'sender_email': sender_email,
                'sender_host': sender_host,
                'is_ip_sender': sender_host == sender_ip,
                'sender_ip': sender_ip,
                'sender_abuse_report': sender_abuse_report,
                'receiver_email': receiver_email,
                'return_path': return_path_header,
                'return_path_email': return_path_email,
                'authentication_results': authentication_results,
                'urls': urls_info,
                'file_hash': file_hash,
                'timestamp': datetime.now().isoformat(),
                'msg': msg  # Include the parsed email message for tagging
            }

            # Check if email is suspicious but don't modify it
            is_suspicious, findings = self.is_suspicious(results)
            results['is_suspicious'] = is_suspicious
            results['suspicious_findings'] = findings

            return results

        except Exception as e:
            logging.error(f"Error processing file {filepath}: {str(e)}")
            return None