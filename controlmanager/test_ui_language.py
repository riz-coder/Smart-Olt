"""Guard application-owned UI copy against known Roman Urdu wording."""
import re
from pathlib import Path

from django.test import SimpleTestCase


class EnglishInterfaceTests(SimpleTestCase):
    def test_application_copy_has_no_known_roman_urdu_phrases(self):
        root = Path(__file__).resolve().parent.parent
        pattern = re.compile(
            r'\b(?:hai|hain|hoga|hogi|honge|karein|karain|karna|mein|nahi|nahin|'
            r'rahega|banega|aayega|misal|sirf|abhi|warna|chhor|rakhein|'
            r'chahiye|pehle|dobara|apne|yahan|yeh|chalegi|jayenge|darmiyan)\b',
            re.IGNORECASE,
        )
        matches = []
        for package in ('controlmanager', 'oltmanager', 'controlplane', 'oltportal'):
            for path in (root / package).rglob('*'):
                if path.suffix not in {'.py', '.html', '.js'}:
                    continue
                if path.name.startswith('test') or any(part in {'migrations', 'vendor', '__pycache__'} for part in path.parts):
                    continue
                for number, line in enumerate(path.read_text(encoding='utf-8-sig').splitlines(), 1):
                    if pattern.search(line):
                        matches.append(f'{path.relative_to(root)}:{number}')
        self.assertEqual(matches, [], 'Review non-English application copy: ' + ', '.join(matches))
