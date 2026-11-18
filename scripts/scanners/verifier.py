import re
import requests
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import logging

logger = logging.getLogger(__name__)

class SecretVerifier:
    def __init__(self):
        # Regex patterns for advanced detection
        self.patterns = {
            'aws_access': re.compile(r'(AKIA|ASIA)[0-9A-Z]{16}'),
            'aws_secret': re.compile(r'[0-9a-zA-Z/+]{40}'),
            'github_pat': re.compile(r'ghp_[A-Za-z0-9]{36}'),
            'postgres_url': re.compile(r'postgresql://.*:.*@.*:\d+'),
            'generic_uuid': re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
        }

    def identify_and_verify(self, secret_value, context=""):
        """Main entry point to identify and verify a secret."""
        result = {"secret_preview": secret_value[:10] + "...", "status": "unknown", "type": "unknown"}
        
        # 1. AWS Credentials Check
        if self.patterns['aws_access'].search(secret_value):
            result['type'] = 'AWS_Credential'
            return self._verify_aws(secret_value)

        # 2. GitHub PAT Check
        if self.patterns['github_pat'].search(secret_value):
            result['type'] = 'GitHub_PAT'
            return self._verify_github(secret_value)

        # 3. Database URL Check (Internal Pivot Detection)
        if self.patterns['postgres_url'].search(secret_value):
            result['type'] = 'Database_URL'
            return self._analyze_db_url(secret_value)

        # 4. Generic UUID/API Key Check
        if self.patterns['generic_uuid'].search(secret_value):
            result['type'] = 'Generic_API_Key'
            return self._analyze_generic_key(secret_value, context)

        return result

    def _verify_aws(self, key_id):
        """Verify AWS keys using STS GetCallerIdentity."""
        try:
            # Note: In a real bulk hunter, you'd need to extract the secret key too.
            # For now, we check if the Access Key ID format is valid and potentially active.
            session = boto3.Session(aws_access_key_id=key_id) 
            sts = session.client('sts', region_name='us-east-1')
            identity = sts.get_caller_identity()
            return {
                "status": "ACTIVE",
                "type": "AWS_Credential",
                "details": f"Account: {identity['Account']}, ARN: {identity['Arn']}"
            }
        except NoCredentialsError:
            return {"status": "NO_CREDS_PROVIDED", "type": "AWS_Credential"}
        except ClientError as e:
            if "ExpiredToken" in str(e):
                return {"status": "EXPIRED", "type": "AWS_Credential"}
            return {"status": "INVALID", "type": "AWS_Credential"}

    def _verify_github(self, token):
        """Verify GitHub PAT by hitting the /user endpoint."""
        try:
            headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
            resp = requests.get("https://api.github.com/user", headers=headers, timeout=5)
            if resp.status_code == 200:
                user = resp.json().get('login')
                return {"status": "ACTIVE", "type": "GitHub_PAT", "details": f"User: {user}"}
            elif resp.status_code == 401:
                return {"status": "INVALID", "type": "GitHub_PAT"}
        except Exception:
            pass
        return {"status": "UNKNOWN", "type": "GitHub_PAT"}

    def _analyze_db_url(self, url):
        """Analyze DB URLs for internal pivots without connecting."""
        info = {"status": "INFO_ONLY", "type": "Database_URL", "details": []}
        if "10." in url or "192.168." in url or ".internal" in url:
            info['details'].append("⚠️ INTERNAL NETWORK PIVOT DETECTED")
        if "localhost" in url or "127.0.0.1" in url:
            info['details'].append("ℹ️ LOCALHOST CONFIGURATION")
        return info

    def _analyze_generic_key(self, key, context):
        """Heuristic analysis for generic keys."""
        info = {"status": "HEURISTIC", "type": "Generic_API_Key"}
        if len(key) > 20:
            info['details'] = "High entropy detected; likely a real service token."
        if "test" in context.lower() or "example" in context.lower():
            info['status'] = "LIKELY_FALSE_POSITIVE"
        return info
