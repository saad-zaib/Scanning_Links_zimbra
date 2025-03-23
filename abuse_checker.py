import requests
import logging
from typing import Dict, Tuple
from datetime import datetime

class CybersiloChecker:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://tip.cybersilo.tech/api/ioc/search"
        self.cache: Dict[str, Tuple[dict, datetime]] = {}
        self.cache_duration = 3600  # Cache results for 1 hour

    def check_ip(self, ip: str) -> Dict:
        """Check IP against Cybersilo with caching."""
        if not ip:
            return {"error": "No IP provided"}

        # Check cache first
        if ip in self.cache:
            result, timestamp = self.cache[ip]
            if (datetime.now() - timestamp).total_seconds() < self.cache_duration:
                return result

        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        data = {
            "pattern": ip
        }

        try:
            logging.info(f"Checking IP: {ip} against Cybersilo")
            response = requests.post(
                self.base_url,
                headers=headers,
                json=data
            )

            if response.status_code == 200:
                # Process the response
                api_result = response.json()
                logging.info(f"Cybersilo raw response: {api_result}")

                # Transform to a consistent format
                result = {
                    "data": api_result.get("data", []),
                    "isMalicious": False,
                    "highestScore": 0
                }

                # Check if any entry has a score > 10
                for item in result["data"]:
                    score = item.get("x_opencti_score", 0)
                    logging.info(f"Found score: {score} for item: {item.get('name', 'unknown')}")
                    if score > result["highestScore"]:
                        result["highestScore"] = score

                    if score > 10:
                        logging.info(f"Marking IP as malicious with score: {score}")
                        result["isMalicious"] = True

                logging.info(f"Final result for {ip}: isMalicious={result['isMalicious']}, highestScore={result['highestScore']}")
                self.cache[ip] = (result, datetime.now())
                return result
            else:
                error_msg = {"error": f"API Error: {response.status_code}", "message": response.text}
                logging.error(f"Cybersilo API error: {error_msg}")
                return error_msg
        except Exception as e:
            error_msg = {"error": f"Request failed: {str(e)}"}
            logging.error(f"Exception in check_ip: {error_msg}")
            return error_msg
