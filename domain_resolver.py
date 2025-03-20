import socket
import logging
import ipaddress
import dns.resolver
from typing import Dict, Tuple, Optional
from datetime import datetime

class DomainResolver:
    def __init__(self):
        self.cache: Dict[str, Tuple[str, datetime]] = {}
        self.cache_duration = 3600  # Cache IP lookups for 1 hour
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

    def get_ip_address(self, host: str) -> Optional[str]:
        """
        Resolve host to IP address with caching.
        If host is already an IP address, return it directly.
        """
        # If host is already an IP address, return it directly
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass

        try:
            # Check cache first
            if host in self.cache:
                ip, timestamp = self.cache[host]
                if (datetime.now() - timestamp).total_seconds() < self.cache_duration:
                    return ip

            # Try to resolve using DNS
            answers = self.resolver.resolve(host, 'A')
            if answers:
                ip = str(answers[0])
                self.cache[host] = (ip, datetime.now())
                return ip
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.resolver.NoNameservers):
            try:
                # Fallback to socket if DNS resolution fails
                ip = socket.gethostbyname(host)
                self.cache[host] = (ip, datetime.now())
                return ip
            except socket.gaierror:
                logging.warning(f"Could not resolve host: {host}")
                return None
        except Exception as e:
            logging.error(f"Error resolving {host}: {str(e)}")
            return None
        return None