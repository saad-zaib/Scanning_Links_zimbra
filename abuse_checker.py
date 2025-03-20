import requests
import logging
from typing import Dict, Tuple
from datetime import datetime

class AbuseIPDBChecker:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.cache: Dict[str, Tuple[dict, datetime]] = {}
        self.cache_duration = 3600  # Cache results for 1 hour

    def check_ip(self, ip: str) -> Dict:
        """Check IP against AbuseIPDB with caching."""
        if not ip:
            return {"error": "No IP provided"}

        # Check cache first
        if ip in self.cache:
            result, timestamp = self.cache[ip]
            if (datetime.now() - timestamp).total_seconds() < self.cache_duration:
                return result

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }

        try:
            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params=params
            )

            if response.status_code == 200:
                result = response.json()['data']
                self.cache[ip] = (result, datetime.now())
                return result
            else:
                return {"error": f"API Error: {response.status_code}"}
        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}