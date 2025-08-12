import hvac
import datetime
from typing import List, Dict, Any, Optional

# Import helper functions from main
from main import (
    parse_certificate_dates,
    extract_common_name_from_certificate,
    process_issuer_details,
    get_ca_certificate_info
)

# Import utility functions
from utils import format_datetime


def create_timeline_visualization(pki_engines: List[Dict[str, Any]], timeline_width: int = 50) -> None:
    """
    Create a visual timeline showing certificate validity periods.
    
    Args:
        pki_engines: List of PKI engine information dictionaries
        timeline_width: Width of the timeline in characters (default: 50)
    """
    
    # Collect all certificates with their validity periods and hierarchy info
    certs = []
    ca_engines = {}  # Track CA engines for hierarchy mapping
    
    for engine in pki_engines:
        # Add main CA certificate if available
        if engine.get('cert_not_before') and engine.get('cert_not_after'):
            cert_entry = {
                'name': f"{engine['path']} (Main CA)",
                'not_before': engine['cert_not_before'],
                'not_after': engine['cert_not_after'],
                'engine_path': engine['path'],
                'cert_type': 'root_ca',
                'parent_ca': None
            }
            certs.append(cert_entry)
            ca_engines[engine['path']] = cert_entry
        
        # Add all issuers
        for issuer in engine.get('issuers', []):
            if issuer.get('not_before') and issuer.get('not_after'):
                issuer_name = issuer.get('common_name') or issuer.get('name', 'Unknown')
                
                # Try to determine if this is an intermediate CA by checking if it's signed by another CA
                # For now, assume issuers in different engines than main CAs are intermediates
                is_intermediate = engine['path'] not in ca_engines or len(engine.get('issuers', [])) > 1
                
                cert_entry = {
                    'name': f"{engine['path']}/{issuer_name}",
                    'not_before': issuer['not_before'],
                    'not_after': issuer['not_after'],
                    'engine_path': engine['path'],
                    'cert_type': 'intermediate' if is_intermediate else 'issuer',
                    'parent_ca': None  # Will be determined below
                }
                certs.append(cert_entry)
    
    # Try to establish parent-child relationships for intermediate CAs
    # Look for naming patterns that suggest hierarchy (e.g., pki-int signed by pki)
    for cert in certs:
        if cert['cert_type'] == 'intermediate':
            # Look for a potential parent CA in a different engine with similar naming
            cert_engine = cert['engine_path']
            
            # Common patterns: pki-int -> pki, pki-intermediate -> pki-root, etc.
            potential_parents = []
            for other_cert in certs:
                if (other_cert['cert_type'] == 'root_ca' and 
                    other_cert['engine_path'] != cert_engine):
                    # Simple heuristic: if the intermediate engine name contains the root engine name
                    if (other_cert['engine_path'] in cert_engine or 
                        cert_engine.replace('-int', '').replace('-intermediate', '') == other_cert['engine_path']):
                        potential_parents.append(other_cert)
            
            # If we found potential parents, pick the first one (could be made more sophisticated)
            if potential_parents:
                cert['parent_ca'] = potential_parents[0]['name']
    
    if not certs:
        return
    
    # Normalize timezone for all certificates
    for cert in certs:
        if cert['not_before'].tzinfo is None:
            cert['not_before'] = cert['not_before'].replace(tzinfo=datetime.timezone.utc)
        if cert['not_after'].tzinfo is None:
            cert['not_after'] = cert['not_after'].replace(tzinfo=datetime.timezone.utc)
    
    # Find the overall time range
    all_start_dates = [cert['not_before'] for cert in certs]
    all_end_dates = [cert['not_after'] for cert in certs]
    
    earliest_start = min(all_start_dates)
    latest_end = max(all_end_dates)
    
    # Add some padding to the timeline
    time_range = latest_end - earliest_start
    padding = time_range * 0.05  # 5% padding on each side
    timeline_start = earliest_start - padding
    timeline_end = latest_end + padding
    timeline_duration = timeline_end - timeline_start
    
    print(f"\n{'='*60}")
    print("CERTIFICATE VALIDITY TIMELINE")
    print(f"{'='*60}")
    print(f"Timeline: {format_datetime(timeline_start)} to {format_datetime(timeline_end)}")
    
    # Current time marker
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Use the provided timeline width
    # timeline_width = 50  # This line is now removed since it's a parameter
    
    print(f"\n{'Certificate Name':<50} {'Timeline':<{timeline_width}} {'Status'}")
    print(f"{'-'*50} {'-'*timeline_width} {'-'*15}")
    
    # Sort certificates: root CAs first, then intermediates, then others
    def sort_key(cert):
        if cert['cert_type'] == 'root_ca':
            return (0, cert['not_before'])
        elif cert['cert_type'] == 'intermediate':
            return (1, cert['not_before'])
        else:
            return (2, cert['not_before'])
    
    sorted_certs = sorted(certs, key=sort_key)
    
    for i, cert in enumerate(sorted_certs):
        # Calculate positions on the timeline
        start_pos = int((cert['not_before'] - timeline_start) / timeline_duration * timeline_width)
        end_pos = int((cert['not_after'] - timeline_start) / timeline_duration * timeline_width)
        now_pos = int((now - timeline_start) / timeline_duration * timeline_width)
        
        # Ensure positions are within bounds
        start_pos = max(0, min(start_pos, timeline_width - 1))
        end_pos = max(0, min(end_pos, timeline_width - 1))
        now_pos = max(0, min(now_pos, timeline_width - 1))
        
        # Create the timeline visualization
        timeline = [' '] * timeline_width
        
        # Fill the validity period
        for i in range(start_pos, min(end_pos + 1, timeline_width)):
            timeline[i] = '█'
        
        # Mark start and end
        if start_pos < timeline_width:
            timeline[start_pos] = '├'
        if end_pos < timeline_width and end_pos != start_pos:
            timeline[end_pos] = '┤'
        
        # Mark current time
        if 0 <= now_pos < timeline_width:
            if timeline[now_pos] == '█':
                timeline[now_pos] = '●'  # Current time within validity
            else:
                timeline[now_pos] = '│'  # Current time outside validity
        
        # Determine status
        if now < cert['not_before']:
            status = "Future"
        elif now > cert['not_after']:
            days_expired = (now - cert['not_after']).days
            status = f"EXPIRED ({days_expired}d)"
        else:
            days_remaining = (cert['not_after'] - now).days
            if days_remaining < 30:
                status = f"⚠️ {days_remaining}d left"
            elif days_remaining < 90:
                status = f"⚡ {days_remaining}d left"
            else:
                status = f"✓ {days_remaining}d left"
        
        # Truncate certificate name if too long
        cert_name = cert['name']
        if len(cert_name) > 48:
            cert_name = cert_name[:45] + "..."
        
        # Add hierarchy indicator for intermediate CAs
        if cert['cert_type'] == 'intermediate' and cert['parent_ca']:
            cert_name = f"  ↳ {cert_name}"  # Indent and add arrow for intermediate
        elif cert['cert_type'] == 'root_ca':
            cert_name = f"📜 {cert_name}"  # Add certificate icon for root CA
        
        timeline_str = ''.join(timeline)
        print(f"{cert_name:<50} {timeline_str:<{timeline_width}} {status}")
        
        # Print connection line for intermediate CAs
        if cert['cert_type'] == 'intermediate' and cert['parent_ca'] and i > 0:
            # Find the parent CA in our sorted list
            parent_index = None
            for j, parent_cert in enumerate(sorted_certs[:i]):
                if parent_cert['name'] == cert['parent_ca']:
                    parent_index = j
                    break
            
            if parent_index is not None:
                # Create a visual connection line
                connection_line = "  │" + " " * 47 + " " * timeline_width + " " * 15
                print(connection_line)
    
    # Legend
    print(f"\n{'Legend:'}")
    print(f"  📜       Root CA certificate")
    print(f"  ↳        Intermediate CA (signed by parent)")
    print(f"  │        Hierarchy connection")
    print(f"  ├{'█'*8}┤  Certificate validity period")
    print(f"  ●        Current time (within validity)")
    print(f"  │        Current time (outside validity)")
    print(f"  ✓        Valid (>90 days remaining)")
    print(f"  ⚡       Expires soon (30-90 days)")
    print(f"  ⚠️        Critical (< 30 days)")


def scan_pki_secrets_engines(client: hvac.Client) -> List[Dict[str, Any]]:
    """
    Scan Vault for PKI secrets engines.
    
    Args:
        client: Authenticated Vault client
        
    Returns:
        List of dictionaries containing PKI engine information
    """
    try:
        # List all mounted secrets engines
        mounts = client.sys.list_mounted_secrets_engines()
        pki_engines = []
        
        for mount_path, mount_info in mounts['data'].items():
            # Check if the secrets engine type is 'pki'
            if mount_info.get('type') != 'pki':
                continue
                
            mount_path = mount_path.rstrip('/')
            
            # Build basic PKI info
            pki_info = {
                'path': mount_path,
                'type': mount_info.get('type'),
                'description': mount_info.get('description', ''),
                'config': mount_info.get('config', {}),
                'options': mount_info.get('options', {}),
                'accessor': mount_info.get('accessor', ''),
            }
            
            # Get CA certificate information
            ca_info = get_ca_certificate_info(client, mount_path)
            pki_info.update(ca_info)
            
            # Get PKI configuration
            try:
                config_response = client.read(f"{mount_path}/config/ca")
                pki_info['ca_config'] = config_response['data'] if config_response else None
            except Exception:
                pki_info['ca_config'] = None
            
            # Get certificate roles
            try:
                roles_response = client.list(f"{mount_path}/roles")
                pki_info['roles'] = roles_response['data'].get('keys', []) if roles_response else []
            except Exception:
                pki_info['roles'] = []
            
            # Get all issuers
            try:
                issuers_response = client.list(f"{mount_path}/issuers")
                if issuers_response and 'data' in issuers_response:
                    issuer_ids = issuers_response['data'].get('keys', [])
                    pki_info['issuers'] = []
                    
                    for issuer_id in issuer_ids:
                        issuer_info = process_issuer_details(client, mount_path, issuer_id)
                        if issuer_info:
                            pki_info['issuers'].append(issuer_info)
                else:
                    pki_info['issuers'] = []
            except Exception:
                pki_info['issuers'] = []
            
            pki_engines.append(pki_info)
        
        return pki_engines
        
    except Exception as e:
        raise Exception(f"Failed to scan for PKI secrets engines: {str(e)}")


def print_pki_scan_results(pki_engines: List[Dict[str, Any]], timeline_width: int = 50) -> None:
    """
    Print the PKI scan results in a formatted way.
    
    Args:
        pki_engines: List of PKI engine information dictionaries
        timeline_width: Width of the timeline visualization in characters
    """
    if not pki_engines:
        print("No PKI secrets engines found.")
        return
    
    print(f"Found {len(pki_engines)} PKI secrets engine(s):")
    print("=" * 50)
    
    for i, engine in enumerate(pki_engines, 1):
        print(f"\n{i}. PKI Engine: {engine['path']}")
        print(f"   Description: {engine['description'] or 'No description'}")
        print(f"   Accessor: {engine['accessor']}")
        
        if engine['ca_certificate']:
            print("   ✓ CA Certificate configured")
            
            # Display certificate validity period
            start_date = format_datetime(engine.get('cert_not_before'))
            end_date = format_datetime(engine.get('cert_not_after'))
            print(f"   Valid from: {start_date}")
            print(f"   Valid until: {end_date}")
            
            # Check if certificate is expired or expiring soon
            if engine.get('cert_not_after'):
                cert_expiry = engine['cert_not_after']
                
                # Ensure both datetimes are timezone-aware for comparison
                if cert_expiry.tzinfo is None:
                    # Certificate datetime is naive, assume UTC
                    cert_expiry = cert_expiry.replace(tzinfo=datetime.timezone.utc)
                
                # Get current time in UTC
                now = datetime.datetime.now(datetime.timezone.utc)
                
                days_until_expiry = (cert_expiry - now).days
                
                if days_until_expiry < 0:
                    print(f"   ⚠️  EXPIRED {abs(days_until_expiry)} days ago")
                elif days_until_expiry < 30:
                    print(f"   ⚠️  Expires in {days_until_expiry} days")
                elif days_until_expiry < 90:
                    print(f"   ⚡ Expires in {days_until_expiry} days")
        else:
            print("   ✗ CA Certificate not configured")
        
        if engine['roles']:
            print(f"   Roles: {', '.join(engine['roles'])}")
        else:
            print("   Roles: None configured")
        
        # Display issuers information
        if engine.get('issuers'):
            print(f"   Issuers: {len(engine['issuers'])} certificate(s)")
            for j, issuer in enumerate(engine['issuers'], 1):
                issuer_name = issuer.get('common_name') or issuer.get('name', 'Unknown')
                print(f"     {j}. {issuer_name}")
                print(f"        ID: {issuer['id']}")
                
                if issuer.get('not_before') and issuer.get('not_after'):
                    start_date = format_datetime(issuer['not_before'])
                    end_date = format_datetime(issuer['not_after'])
                    print(f"        Valid: {start_date} to {end_date}")
                    
                    # Check expiration status for this issuer
                    cert_expiry = issuer['not_after']
                    if cert_expiry.tzinfo is None:
                        cert_expiry = cert_expiry.replace(tzinfo=datetime.timezone.utc)
                    
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_until_expiry = (cert_expiry - now).days
                    
                    if days_until_expiry < 0:
                        print(f"        ⚠️  EXPIRED {abs(days_until_expiry)} days ago")
                    elif days_until_expiry < 30:
                        print(f"        ⚠️  Expires in {days_until_expiry} days")
                    elif days_until_expiry < 90:
                        print(f"        ⚡ Expires in {days_until_expiry} days")
                else:
                    print(f"        Valid: Unknown")
        else:
            print("   Issuers: None found")
        
        if engine['ca_config']:
            print("   CA Configuration:")
            for key, value in engine['ca_config'].items():
                if key != 'private_key':  # Don't print sensitive data
                    print(f"     {key}: {value}")
    
    # Add timeline visualization
    create_timeline_visualization(pki_engines, timeline_width)
