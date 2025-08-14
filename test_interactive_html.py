#!/usr/bin/env python3
"""
Test script to verify enhanced HTML generation with interactive features.
"""

from scan_functions import generate_html_report
import datetime

# Create comprehensive test data with multiple engines and certificates
test_data = {
    'vault_version': '1.15.0+ent',
    'is_enterprise': True,
    'scanned_namespaces': ['root', 'dev', 'prod'],
    'all_namespaces_scan': True,
    'pki_engines': [
        {
            'path': 'pki-root',
            'namespace': 'root',
            'description': 'Root PKI for production',
            'accessor': 'pki_abc123',
            'ca_certificate': True,
            'cert_not_before': datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
            'cert_not_after': datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc),
            'roles': ['server', 'client'],
            'issuers': [
                {
                    'id': 'root-issuer-123',
                    'name': 'Production Root CA',
                    'common_name': 'Production Root CA',
                    'not_before': datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                    'not_after': datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc),
                }
            ]
        },
        {
            'path': 'pki-intermediate',
            'namespace': 'root',
            'description': 'Intermediate PKI for applications',
            'accessor': 'pki_def456',
            'ca_certificate': True,
            'cert_not_before': datetime.datetime(2024, 2, 1, tzinfo=datetime.timezone.utc),
            'cert_not_after': datetime.datetime(2024, 12, 1, tzinfo=datetime.timezone.utc),  # Expires soon
            'roles': ['web-server', 'api-server'],
            'issuers': [
                {
                    'id': 'intermediate-issuer-456',
                    'name': 'App Intermediate CA',
                    'common_name': 'Application Intermediate CA',
                    'not_before': datetime.datetime(2024, 2, 1, tzinfo=datetime.timezone.utc),
                    'not_after': datetime.datetime(2024, 12, 1, tzinfo=datetime.timezone.utc),
                },
                {
                    'id': 'intermediate-issuer-789',
                    'name': 'Backup Intermediate CA',
                    'common_name': 'Backup Intermediate CA',
                    'not_before': datetime.datetime(2024, 3, 1, tzinfo=datetime.timezone.utc),
                    'not_after': datetime.datetime(2026, 3, 1, tzinfo=datetime.timezone.utc),
                }
            ]
        },
        {
            'path': 'pki-dev',
            'namespace': 'dev',
            'description': 'Development PKI',
            'accessor': 'pki_ghi789',
            'ca_certificate': True,
            'cert_not_before': datetime.datetime(2024, 1, 15, tzinfo=datetime.timezone.utc),
            'cert_not_after': datetime.datetime(2023, 12, 15, tzinfo=datetime.timezone.utc),  # Expired
            'roles': ['dev-server'],
            'issuers': [
                {
                    'id': 'dev-issuer-321',
                    'name': 'Dev CA',
                    'common_name': 'Development CA',
                    'not_before': datetime.datetime(2024, 1, 15, tzinfo=datetime.timezone.utc),
                    'not_after': datetime.datetime(2023, 12, 15, tzinfo=datetime.timezone.utc),
                }
            ]
        }
    ]
}

try:
    print("Testing enhanced HTML generation with interactive features...")
    html_output = generate_html_report(test_data, timeline_width=80)
    print(f"✅ Enhanced HTML generated successfully! Length: {len(html_output)} characters")
    
    # Write to file for visual inspection
    with open('interactive_report.html', 'w') as f:
        f.write(html_output)
    print("✅ Interactive HTML report written to: interactive_report.html")
    
    # Check for interactive features in the HTML
    interactive_features = [
        'toggleEngine(',
        'filterTimeline(',
        'showTooltip(',
        'collapse-indicator',
        'timeline-controls',
        'cert-tooltip'
    ]
    
    print("\n📊 Interactive features check:")
    for feature in interactive_features:
        if feature in html_output:
            print(f"  ✅ {feature}")
        else:
            print(f"  ❌ {feature}")
    
except Exception as e:
    print(f"❌ Error generating HTML: {e}")
    import traceback
    traceback.print_exc()
