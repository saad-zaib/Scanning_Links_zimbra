import os
import time
import logging
from typing import Set
from watchdog.events import FileSystemEventHandler

from email_analyzer import EmailAnalyzer
from zimbra_tagger import ZimbraEmailTagger
from json_logger import JSONLogger

class ZimbraMonitor(FileSystemEventHandler):
    def __init__(self, zimbra_store_path: str, abuseipdb_api_key: str, tag_name="MALICIOUS", json_log_path="/var/log/scanning.json"):
        self.zimbra_store_path = zimbra_store_path
        self.analyzer = EmailAnalyzer(abuseipdb_api_key)
        self.tagger = ZimbraEmailTagger(tag_name)
        self.json_logger = JSONLogger(json_log_path)
        self.processed_paths: Set[str] = set()
        self.last_cleanup = time.time()
        self.cleanup_interval = 3600  # Clean up processed emails cache every hour

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.msg'):
            self.process_email_file(event.src_path)

    def process_email_file(self, filepath: str):
        """Process a newly detected email file, analyze it, and tag if suspicious."""
        if filepath in self.processed_paths:
            return

        self.processed_paths.add(filepath)
        
        # Analyze the email for malicious content
        results = self.analyzer.analyze_email_file(filepath)

        if not results:
            return

        logging.info(f"\nNew email detected - Hash: {results['file_hash'][:8]}")
        logging.info(f"Timestamp: {results['timestamp']}")

        # Log to JSON file
        self.json_logger.log_email(results)

        # Display analysis results
        self.display_analysis_results(results)

        # If the email is suspicious, tag it in Zimbra
        if results.get('is_suspicious'):
            logging.info("\n🚨 MALICIOUS EMAIL DETECTED - Tagging in Zimbra 🚨")
            if self.tagger.tag_malicious_email(filepath, results):
                logging.info(f"Successfully tagged email as {self.tagger.tag_name}")
            else:
                logging.error("Failed to tag email")

        # Perform cleanup of processed emails cache if needed
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            self.tagger.cleanup_processed_emails()
            self.last_cleanup = current_time

    def display_analysis_results(self, results):
        """Display the analysis results in a readable format."""
        if results.get('is_suspicious'):
            logging.info("\n🚨 MALICIOUS EMAIL DETECTED 🚨")
            logging.info("Suspicious findings:")
            for finding in results['suspicious_findings']:
                logging.info(f"  - {finding}")
            logging.info("")

        # Sender information
        sender_host_desc = "sender IP" if results.get('is_ip_sender') else "sender domain"
        logging.info(f"{sender_host_desc.capitalize()}: {results.get('sender_host', 'Unknown')}")

        if not results.get('is_ip_sender') and results.get('sender_ip'):
            logging.info(f"Resolved IP: {results['sender_ip']}")

        # Display AbuseIPDB results for sender
        if results.get('sender_ip') and 'error' not in results.get('sender_abuse_report', {}):
            abuse_report = results['sender_abuse_report']
            logging.info(f"Sender IP Abuse Score: {abuse_report.get('abuseConfidenceScore', 'N/A')}%")
            logging.info(f"Total Reports: {abuse_report.get('totalReports', 'N/A')}")
            logging.info(f"Last Reported: {abuse_report.get('lastReportedAt', 'Never')}")

        # Display URL information
        if results.get('urls'):
            logging.info("\nURLs found:")
            for url_info in sorted(results['urls'], key=lambda x: x['url']):
                logging.info(f"  - {url_info['url']}")

                host_desc = "IP" if url_info.get('is_ip_host') else "Domain"
                logging.info(f"    {host_desc}: {url_info.get('host', 'Unknown')}")

                if not url_info.get('is_ip_host') and url_info.get('ip'):
                    logging.info(f"    Resolved IP: {url_info['ip']}")

                # Display AbuseIPDB results
                if url_info.get('ip') and 'error' not in url_info.get('abuse_report', {}):
                    abuse_report = url_info['abuse_report']
                    logging.info(f"    IP Abuse Score: {abuse_report.get('abuseConfidenceScore', 'N/A')}%")
                    logging.info(f"    Total Reports: {abuse_report.get('totalReports', 'N/A')}")
                    logging.info(f"    Last Reported: {abuse_report.get('lastReportedAt', 'Never')}")

    def scan_existing_files(self):
        """Scan existing email files in the store."""
        existing_files = set()
        for root, _, files in os.walk(self.zimbra_store_path):
            for file in files:
                if file.endswith('.msg'):
                    filepath = os.path.join(root, file)
                    existing_files.add(filepath)

        logging.info(f"Found {len(existing_files)} existing email files to scan")
        for filepath in sorted(existing_files):
            self.process_email_file(filepath)