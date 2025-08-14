#!/usr/bin/env python3

import sys
import datetime
from scan_functions import generate_html_report

# Create sample PKI data with diverse certificate statuses for testing
def create_sample_data():
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Create certificates with different expiration statuses
    sample_data = {
        'vault_version': 'Vault v1.15.0 (dev)',
        'is_enterprise': True,
        'scanned_namespaces': ['root', 'dev', 'prod'],
        'all_namespaces_scan': True,
        'pki_engines': [
            {
                'path': 'pki-root',
                'namespace': 'root',
                'description': 'Root Certificate Authority',
                'accessor': 'pki_12345',
                'ca_certificate': 'sample-cert-data',
                'cert_not_before': now - datetime.timedelta(days=365),
                'cert_not_after': now + datetime.timedelta(days=1825),  # Valid for 5 years total
                'roles': ['root-ca'],
                'issuers': [
                    {
                        'id': 'root-issuer-1',
                        'name': 'Example Root CA',
                        'common_name': 'Example Root CA',
                        'not_before': now - datetime.timedelta(days=365),
                        'not_after': now + datetime.timedelta(days=1825)
                    }
                ]
            },
            {
                'path': 'pki-intermediate',
                'namespace': 'dev',
                'description': 'Development Intermediate CA',
                'accessor': 'pki_67890',
                'ca_certificate': 'sample-cert-data',
                'cert_not_before': now - datetime.timedelta(days=180),
                'cert_not_after': now + datetime.timedelta(days=15),  # Expires soon (warning)
                'roles': ['intermediate-ca', 'server-cert'],
                'issuers': [
                    {
                        'id': 'int-issuer-1',
                        'name': 'Dev Intermediate CA',
                        'common_name': 'Development Intermediate CA',
                        'not_before': now - datetime.timedelta(days=180),
                        'not_after': now + datetime.timedelta(days=15)
                    }
                ]
            },
            {
                'path': 'pki-prod',
                'namespace': 'prod',
                'description': 'Production PKI Engine',
                'accessor': 'pki_abcdef',
                'ca_certificate': 'sample-cert-data',
                'cert_not_before': now - datetime.timedelta(days=90),
                'cert_not_after': now + datetime.timedelta(days=270),  # Valid
                'roles': ['web-server', 'client-cert'],
                'issuers': [
                    {
                        'id': 'prod-issuer-1',
                        'name': 'Prod Web Server CA',
                        'common_name': 'Production Web Server CA',
                        'not_before': now - datetime.timedelta(days=90),
                        'not_after': now + datetime.timedelta(days=270)
                    },
                    {
                        'id': 'prod-issuer-2',
                        'name': 'Prod Client CA',
                        'common_name': 'Production Client CA',
                        'not_before': now - datetime.timedelta(days=60),
                        'not_after': now + datetime.timedelta(days=5)  # Critical (expires very soon)
                    }
                ]
            },
            {
                'path': 'pki-expired',
                'namespace': 'dev',
                'description': 'Expired Test CA',
                'accessor': 'pki_xyz789',
                'ca_certificate': 'sample-cert-data',
                'cert_not_before': now - datetime.timedelta(days=400),
                'cert_not_after': now - datetime.timedelta(days=30),  # Expired
                'roles': ['test-cert'],
                'issuers': [
                    {
                        'id': 'expired-issuer-1',
                        'name': 'Expired Test CA',
                        'common_name': 'Expired Test Certificate Authority',
                        'not_before': now - datetime.timedelta(days=400),
                        'not_after': now - datetime.timedelta(days=30)
                    }
                ]
            },
            {
                'path': 'pki-future',
                'namespace': 'prod',
                'description': 'Future Certificate Authority',
                'accessor': 'pki_future1',
                'ca_certificate': 'sample-cert-data',
                'cert_not_before': now + datetime.timedelta(days=30),  # Starts in the future
                'cert_not_after': now + datetime.timedelta(days=395),
                'roles': ['future-ca'],
                'issuers': [
                    {
                        'id': 'future-issuer-1',
                        'name': 'Future CA',
                        'common_name': 'Future Certificate Authority',
                        'not_before': now + datetime.timedelta(days=30),
                        'not_after': now + datetime.timedelta(days=395)
                    }
                ]
            }
        ]
    }
    
    return sample_data

def main():
    print("🔧 Testing Enhanced Chart Timeline Visualization...")
    
    # Generate sample data
    sample_data = create_sample_data()
    
    # Generate HTML report with enhanced chart
    html_content = generate_html_report(sample_data)
    
    # Write to file
    output_file = "enhanced_chart_timeline_report.html"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    # Report statistics
    print(f"✅ Enhanced chart timeline report generated successfully!")
    print(f"📄 File: {output_file}")
    print(f"📊 Report size: {len(html_content):,} characters")
    print(f"🏛️ PKI Engines: {len(sample_data['pki_engines'])}")
    
    # Count certificates by status
    now = datetime.datetime.now(datetime.timezone.utc)
    statuses = {'valid': 0, 'warning': 0, 'critical': 0, 'expired': 0, 'future': 0}
    
    for engine in sample_data['pki_engines']:
        for issuer in engine.get('issuers', []):
            cert_expiry = issuer['not_after']
            cert_start = issuer['not_before']
            
            if now < cert_start:
                statuses['future'] += 1
            elif now > cert_expiry:
                statuses['expired'] += 1
            else:
                days_remaining = (cert_expiry - now).days
                if days_remaining < 30:
                    statuses['critical'] += 1
                elif days_remaining < 90:
                    statuses['warning'] += 1
                else:
                    statuses['valid'] += 1
    
    print(f"📈 Certificate Status Distribution:")
    for status, count in statuses.items():
        print(f"   {status.title()}: {count}")
    
    print(f"\n🌐 Open the file in a web browser to see the enhanced interactive chart timeline!")
    print(f"💡 Features to test:")
    print(f"   • Hover over certificate bars for detailed tooltips")
    print(f"   • Use filter buttons to show different certificate types/statuses")
    print(f"   • Notice the improved visual design with gradients and better colors")
    print(f"   • Check the responsive legend and timeline axis")

if __name__ == "__main__":
    main()
