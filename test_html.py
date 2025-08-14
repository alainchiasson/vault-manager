#!/usr/bin/env python3
"""
Simple test script to verify HTML generation works.
"""

from scan_functions import generate_html_report
import datetime

# Create sample test data
test_data = {
    'vault_version': '1.15.0+ent',
    'is_enterprise': True,
    'scanned_namespaces': ['root', 'dev', 'prod'],
    'all_namespaces_scan': True,
    'pki_engines': [
        {
            'path': 'pki',
            'namespace': 'root',
            'description': 'Root PKI for demo',
            'accessor': 'pki_abc123',
            'ca_certificate': True,
            'cert_not_before': datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
            'cert_not_after': datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
            'roles': ['server', 'client'],
            'issuers': [
                {
                    'id': 'issuer-123',
                    'name': 'Demo Root CA',
                    'common_name': 'Demo Root CA',
                    'not_before': datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                    'not_after': datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
                }
            ]
        }
    ]
}

try:
    print("Testing HTML generation...")
    html_output = generate_html_report(test_data, timeline_width=80)
    print(f"✅ HTML generated successfully! Length: {len(html_output)} characters")
    
    # Write to file for visual inspection
    with open('test_report.html', 'w') as f:
        f.write(html_output)
    print("✅ Test HTML file written to: test_report.html")
    
except Exception as e:
    print(f"❌ Error generating HTML: {e}")
    import traceback
    traceback.print_exc()
