#!/usr/bin/env python3
import argparse
import logging
import time
from watchdog.observers import Observer

from monitor import ZimbraMonitor

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Monitor Zimbra email store for malicious content and tag suspicious emails.')
    parser.add_argument('--abuseipdb-key', required=True, help='AbuseIPDB API key')
    parser.add_argument('--store-path', default='/opt/zimbra/store/', 
                       help='Path to Zimbra store directory (default: /opt/zimbra/store/)')
    parser.add_argument('--log-file', default='zimbra_malicious_monitor.log',
                       help='Path to log file (default: zimbra_malicious_monitor.log)')
    parser.add_argument('--json-log', default='/var/log/scanning.json',
                       help='Path to JSON log file (default: /var/log/scanning.json)')
    parser.add_argument('--tag-name', default='MALICIOUS',
                       help='Tag name to use for malicious emails (default: MALICIOUS)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--scan-only', action='store_true',
                       help='Only scan existing files, don\'t monitor for new ones')

    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(args.log_file)
        ]
    )

    # Create the event handler and observer
    event_handler = ZimbraMonitor(args.store_path, args.abuseipdb_api_key, args.tag_name, args.json_log)
    
    try:
        logging.info("Scanning existing email files...")
        event_handler.scan_existing_files()

        if not args.scan_only:
            logging.info("Starting real-time monitoring...")
            observer = Observer()
            observer.schedule(event_handler, args.store_path, recursive=True)
            observer.start()

            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                observer.stop()
                logging.info("Monitoring stopped by user")
            observer.join()
        else:
            logging.info("Scan completed, exiting (--scan-only was specified)")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    main()