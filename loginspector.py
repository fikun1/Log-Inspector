import re
import argparse 
from collections import defaultdict
from pathlib import Path

IP_PATTERN = re.compile(
    r'\b('
    r'(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}'
    r'(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b'
)

FAILED_LOGIN_PATTERNS = [
    r'Failed password',
    r'authentication failure'
]

SENSITIVE_PATHS = ['/admin', '/wp-login', '/login', '/config']