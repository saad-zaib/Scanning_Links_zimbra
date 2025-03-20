import re
import time
import logging
import subprocess
from typing import Dict
from datetime import datetime

class ZimbraEmailTagger:
    def __init__(self, tag_name="MALICIOUS"):
        self.tag_name = tag_name
        self.processed_emails = {}

    def extract_recipient_from_path(self, path):
        """Extract recipient email from the Zimbra path structure."""
        # Try to extract from path pattern
        # Example: /opt/zimbra/store/0/..../user@domain.com/...
        match = re.search(r'/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)/', path)
        if match:
            return match.group(1)
            
        # Fallback to default mailbox if needed
        # Replace with a more sophisticated method for your environment
        return "postmaster@example.com"

    def extract_email_info(self, email_path, msg):
        """Extract information needed to tag the email in Zimbra."""
        try:
            import email.utils
            
            # Extract recipient from the message
            mailbox = None
            to_header = msg.get('To', '')

            # Extract email address from To header
            to_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)', to_header)
            if to_match:
                mailbox = to_match.group(1)
                logging.info(f"Extracted recipient from To header: {mailbox}")

            # If recipient not found in headers, try to extract from path
            if not mailbox:
                mailbox = self.extract_recipient_from_path(email_path)
                logging.info(f"Extracted recipient from path: {mailbox}")

            # Get from address and subject for searching
            from_header = msg.get('From', '')
            subject = msg.get('Subject', '')

            # Get date for more precise searching
            date_header = msg.get('Date', '')
            # Get the file modification time as a backup timestamp
            file_timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))

            # Parse the date header to a standardized format if possible
            parsed_date = None
            try:
                if date_header:
                    parsed_date = email.utils.parsedate_to_datetime(date_header)
                    if parsed_date:
                        date_header = parsed_date.strftime("%m/%d/%y %H:%M")
            except Exception as e:
                logging.warning(f"Could not parse date header: {e}")
                date_header = None

            return {
                'mailbox': mailbox,
                'from': from_header,
                'subject': subject,
                'date_header': date_header,
                'file_timestamp': file_timestamp,
                'message_id': msg.get('Message-ID', '')
            }
        except Exception as e:
            logging.error(f"Error extracting email info from {email_path}: {e}")
            return None

    def run_zimbra_command(self, command):
        """Run a Zimbra command and return the output."""
        try:
            logging.info(f"Executing: {command}")
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            stdout = stdout.decode('utf-8')
            stderr = stderr.decode('utf-8')

            if process.returncode != 0:
                logging.error(f"Command failed with return code {process.returncode}")
                logging.error(f"Error: {stderr}")
                return None

            logging.info(f"Command output: {stdout}")
            return stdout
        except Exception as e:
            logging.error(f"Exception executing command: {e}")
            return None

    def extract_all_message_ids(self, output):
        """Extract all message IDs from search results."""
        if not output:
            return []

        message_ids = []
        lines = output.strip().split('\n')
        content_lines = [line for line in lines if line.strip() and not line.startswith('num:') and not '--' in line]

        # Remove header rows
        for i, line in enumerate(content_lines):
            if "Id  Type" in line:
                content_lines = content_lines[i+1:]
                break

        for line in content_lines:
            match = re.search(r'^\s*\d+\.\s+(\d+)', line)
            if match:
                message_ids.append(match.group(1))

        return message_ids

    def search_specific_email(self, mailbox, email_info):
        """Search for a specific email using Zimbra-compatible search criteria."""
        # Start with a base search using the most reliable criteria
        base_criteria = []

        if email_info.get('from'):
            # Clean up the from address for the search query
            clean_from = email_info['from'].replace('<', '').replace('>', '')
            clean_from = clean_from.replace('"', '\\"')
            base_criteria.append(f'from:"{clean_from}"')

        if email_info.get('subject'):
            # Escape special characters in subject
            clean_subject = email_info['subject'].replace('"', '\\"')
            base_criteria.append(f'subject:"{clean_subject}"')

        # Add date criteria - format MM/DD/YY
        date_criteria = None
        if email_info.get('date_header'):
            # Extract just the date part
            date_parts = email_info['date_header'].split()
            if date_parts:
                date_criteria = date_parts[0]

        if not date_criteria and email_info.get('file_timestamp'):
            # Try to get date from file timestamp
            date_parts = email_info['file_timestamp'].split()
            if date_parts and len(date_parts) > 0:
                # Convert YYYY-MM-DD to MM/DD/YY
                try:
                    year, month, day = date_parts[0].split('-')
                    date_criteria = f"{month}/{day}/{year[2:]}"
                except:
                    pass

        if date_criteria:
            base_criteria.append(f'date:{date_criteria}')
        else:
            # If no date criteria could be determined, use a recent timeframe
            base_criteria.append('after:-1day')

        # Use a two-stage approach:
        # 1. First search with base criteria (from, subject, date)
        base_query = " ".join(base_criteria)
        command = f'su - zimbra -c "zmmailbox -z -m {mailbox} s -t message \'{base_query}\'"'

        logging.info(f"Searching with criteria: {base_query}")
        output = self.run_zimbra_command(command)

        # Extract message IDs from the search results
        message_ids = self.extract_all_message_ids(output) if output else []

        # If we found exactly one message, return it
        if len(message_ids) == 1:
            return message_ids[0]

        # If we found multiple messages, try to refine the search
        if len(message_ids) > 1:
            # Try to extract the time from the headers
            email_time = None

            # Extract from date_header
            if email_info.get('date_header'):
                time_parts = email_info['date_header'].split()
                if len(time_parts) > 1:
                    email_time = time_parts[1]

            # Or extract from file_timestamp
            if not email_time and email_info.get('file_timestamp'):
                time_parts = email_info['file_timestamp'].split()
                if len(time_parts) > 1:
                    email_time = time_parts[1]

            # If we have a time, try to match it with the search results
            if email_time:
                logging.info(f"Trying to match emails with time: {email_time}")
                # We'll need to get the full details of each message to compare times
                for msg_id in message_ids:
                    # Get message details
                    get_command = f'su - zimbra -c "zmmailbox -z -m {mailbox} gm {msg_id}"'
                    msg_details = self.run_zimbra_command(get_command)

                    if msg_details and email_time in msg_details:
                        logging.info(f"Found message with matching time: {msg_id}")
                        return msg_id

            # If we couldn't match by time, try message-id
            if email_info.get('message_id') and email_info['message_id'].strip():
                clean_msgid = email_info['message_id'].replace('<', '').replace('>', '')
                for msg_id in message_ids:
                    # Get message details and look for matching message ID
                    get_command = f'su - zimbra -c "zmmailbox -z -m {mailbox} gm {msg_id}"'
                    msg_details = self.run_zimbra_command(get_command)

                    if msg_details and clean_msgid in msg_details:
                        logging.info(f"Found message with matching Message-ID: {msg_id}")
                        return msg_id

            # If we still can't determine which message, use the most recent one
            logging.info(f"Unable to narrow down messages, using most recent of {len(message_ids)} messages")
            return message_ids[0]

        # If we couldn't find any messages, return None
        logging.info("No matching messages found")
        return None

    def check_tag_exists(self, mailbox, tag=None):
        """Check if the specified tag exists for the mailbox."""
        if tag is None:
            tag = self.tag_name
            
        command = f'su - zimbra -c "zmmailbox -z -m {mailbox} gat"'
        output = self.run_zimbra_command(command)

        if output is None:
            return False

        return tag in output

    def create_tag(self, mailbox, tag=None):
        """Create a tag for the mailbox if it doesn't exist."""
        if tag is None:
            tag = self.tag_name
            
        if not self.check_tag_exists(mailbox, tag):
            logging.info(f"Creating tag {tag} for mailbox {mailbox}")
            command = f'su - zimbra -c "zmmailbox -z -m {mailbox} ct {tag}"'
            return self.run_zimbra_command(command) is not None
        else:
            logging.info(f"Tag {tag} already exists for mailbox {mailbox}")
            return True

    def check_if_email_already_tagged(self, mailbox, message_id, tag=None):
        """Check if a specific email is already tagged."""
        if tag is None:
            tag = self.tag_name
            
        command = f'su - zimbra -c "zmmailbox -z -m {mailbox} gm {message_id}"'
        output = self.run_zimbra_command(command)

        if not output:
            return False

        # Check if the tag appears in the message details
        tag_pattern = f't="{tag}"|Tag: {tag}'
        return bool(re.search(tag_pattern, output))

    def add_tag_to_email(self, mailbox, message_id, tag=None):
        """Add the email to the specified tag if not already tagged."""
        if tag is None:
            tag = self.tag_name
            
        # First check if the email is already tagged
        if self.check_if_email_already_tagged(mailbox, message_id, tag):
            logging.info(f"Message {message_id} is already tagged with {tag}, skipping")
            return True

        logging.info(f"Adding message {message_id} to tag {tag} for mailbox {mailbox}")
        command = f'su - zimbra -c "zmmailbox -z -m {mailbox} tm {message_id} {tag}"'
        return self.run_zimbra_command(command) is not None

    def tag_malicious_email(self, email_path, analysis_results):
        """Tag an email as malicious in Zimbra."""
        logging.info(f"Attempting to tag email {email_path}")

        if not analysis_results or not analysis_results.get('is_suspicious'):
            logging.info(f"Email {email_path} is not suspicious, skipping tagging")
            return False

        try:
            # Extract email info from the message
            msg = analysis_results.get('msg')
            if not msg:
                logging.error("No message object found in analysis results")
                return False

            email_info = self.extract_email_info(email_path, msg)
            logging.info(f"Extracted email info: {email_info}")

            if not email_info or not email_info.get('mailbox'):
                logging.error(f"Could not extract email info from {email_path}")
                return False

            mailbox = email_info['mailbox']
            logging.info(f"Extracted mailbox: {mailbox}")

            # Ensure the tag exists
            tag_exists = self.check_tag_exists(mailbox)
            logging.info(f"Tag exists check result: {tag_exists}")

            if not tag_exists:
                create_tag_result = self.create_tag(mailbox)
                logging.info(f"Create tag result: {create_tag_result}")

                if not create_tag_result:
                    logging.error(f"Could not create tag for mailbox {mailbox}")
                    return False

            # Find the message ID in Zimbra
            logging.info(f"Searching for email in Zimbra with info: {email_info}")
            message_id = self.search_specific_email(mailbox, email_info)
            logging.info(f"Search result message ID: {message_id}")

            if not message_id:
                logging.error(f"Could not find message in Zimbra for {email_path}")
                return False

            # Tag the email
            tag_result = self.add_tag_to_email(mailbox, message_id)
            logging.info(f"Tag email result: {tag_result}")

            if tag_result:
                logging.info(f"Successfully tagged message {message_id} as {self.tag_name}")
                return True
            else:
                logging.error(f"Failed to tag message {message_id}")
                return False

        except Exception as e:
            logging.error(f"Error tagging email {email_path}: {e}")
            logging.exception("Exception details:")
            return False

    def cleanup_processed_emails(self, max_age=86400):
        """Remove old entries from the processed emails dictionary to prevent memory bloat."""
        current_time = time.time()
        keys_to_remove = []

        for key, info in self.processed_emails.items():
            timestamp = info.get('processed_timestamp') or info.get('tagged_timestamp')
            if timestamp and (current_time - timestamp) > max_age:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.processed_emails[key]

        if keys_to_remove:
            logging.info(f"Cleaned up {len(keys_to_remove)} old entries from processed emails cache")