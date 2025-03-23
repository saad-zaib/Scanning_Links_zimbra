import json
import os
import logging
from datetime import datetime
from typing import Dict, Any

class JSONLogger:
    def __init__(self, log_path="/var/log/scanning.json"):
        self.log_path = log_path
        self.ensure_dir_exists()
        
    def ensure_dir_exists(self):
        """Ensure the directory exists for the log file."""
        directory = os.path.dirname(self.log_path)
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
            except Exception as e:
                logging.error(f"Failed to create directory {directory}: {e}")
                
    def log_email(self, results: Dict[str, Any]):
        """Log email analysis results to JSON file."""
        try:
            # Extract only the necessary information for the JSON log
            email_info = {}
            
            # Add basic information
            email_info['timestamp'] = datetime.now().isoformat()
            email_info['suspicious'] = results.get('is_suspicious', False)
            
            # Extract msg object to get headers
            msg = results.get('msg')
            if msg:
                # Extract sender and receiver
                email_info['sender'] = msg.get('From', '')
                email_info['receiver'] = msg.get('To', '')
                email_info['subject'] = msg.get('Subject', '')
                
                # Extract authentication results
                auth_results = msg.get('Authentication-Results', '')
                if auth_results:
                    email_info['authentication_results'] = auth_results
                
                # Extract DMARC results
                email_info['dmarc'] = self._extract_dmarc_results(auth_results)
                
                # Extract Return-Path
                email_info['return_path'] = msg.get('Return-Path', '')
                
            # Add sender IP information
            email_info['sender_host'] = results.get('sender_host', '')
            email_info['sender_ip'] = results.get('sender_ip', '')
            
            # Add threat reports
            if 'sender_threat_report' in results and isinstance(results['sender_threat_report'], dict):
                threat_report = results['sender_threat_report']
                email_info['sender_is_malicious'] = threat_report.get('isMalicious', False)
                email_info['sender_threat_score'] = threat_report.get('highestScore', 0)
                
                if 'data' in threat_report and threat_report['data']:
                    email_info['sender_threats'] = []
                    for item in threat_report['data']:
                        threat_info = {
                            'name': item.get('name', ''),
                            'description': item.get('description', ''),
                            'score': item.get('x_opencti_score', 0),
                            'valid_from': item.get('valid_from', ''),
                            'created_by': item.get('createdBy', {}).get('name', '')
                        }
                        email_info['sender_threats'].append(threat_info)
            
            # Add suspicious findings
            if results.get('is_suspicious'):
                email_info['suspicious_findings'] = results.get('suspicious_findings', [])
            
            # Add URLs information
            if results.get('urls'):
                email_info['urls'] = []
                for url_info in results['urls']:
                    url_data = {
                        'url': url_info.get('url', ''),
                        'host': url_info.get('host', ''),
                        'ip': url_info.get('ip', '')
                    }
                    
                    if 'threat_report' in url_info and isinstance(url_info['threat_report'], dict):
                        threat_report = url_info['threat_report']
                        url_data['is_malicious'] = threat_report.get('isMalicious', False)
                        url_data['threat_score'] = threat_report.get('highestScore', 0)
                        
                        if 'data' in threat_report and threat_report['data']:
                            url_data['threats'] = []
                            for item in threat_report['data']:
                                threat_info = {
                                    'name': item.get('name', ''),
                                    'description': item.get('description', ''),
                                    'score': item.get('x_opencti_score', 0),
                                    'valid_from': item.get('valid_from', ''),
                                    'created_by': item.get('createdBy', {}).get('name', '')
                                }
                                url_data['threats'].append(threat_info)
                    
                    email_info['urls'].append(url_data)
            
            # Write to JSON file
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(email_info) + '\n')
                
            logging.info(f"Logged email analysis to {self.log_path}")
            return True
        except Exception as e:
            logging.error(f"Error logging to JSON file: {e}")
            return False
    
    def _extract_dmarc_results(self, auth_results):
        """Extract DMARC results from Authentication-Results header."""
        dmarc_info = {}
        
        if not auth_results:
            return dmarc_info
        
        # Extract DKIM
        if 'dkim=' in auth_results.lower():
            dkim_parts = auth_results.lower().split('dkim=')
            if len(dkim_parts) > 1:
                dkim_result = dkim_parts[1].split()[0].strip(';')
                dmarc_info['dkim'] = dkim_result
        
        # Extract SPF
        if 'spf=' in auth_results.lower():
            spf_parts = auth_results.lower().split('spf=')
            if len(spf_parts) > 1:
                spf_result = spf_parts[1].split()[0].strip(';')
                dmarc_info['spf'] = spf_result
        
        # Extract DMARC
        if 'dmarc=' in auth_results.lower():
            dmarc_parts = auth_results.lower().split('dmarc=')
            if len(dmarc_parts) > 1:
                dmarc_result = dmarc_parts[1].split()[0].strip(';')
                dmarc_info['dmarc'] = dmarc_result
        
        return dmarc_info