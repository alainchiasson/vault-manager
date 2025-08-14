import hvac
import datetime
from typing import List, Dict, Any, Optional

# Import helper functions from main
# (none currently needed)

# Import common CA helper functions
from ca_helpers import (
    parse_certificate_dates,
    extract_common_name_from_certificate,
    process_issuer_details,
    list_issuers_for_selection,
    set_default_issuer,
    get_ca_certificate_info
)

# Import utility functions
from utils import format_datetime


def create_timeline_visualization(pki_engines: List[Dict[str, Any]], timeline_width: int = 50, all_namespaces: bool = False) -> str:
    """
    Create a visual timeline showing certificate validity periods.
    
    Args:
        pki_engines: List of PKI engine information dictionaries
        timeline_width: Width of the timeline in characters (default: 50)
        all_namespaces: Whether this is an all-namespaces scan
        
    Returns:
        Formatted string containing the timeline visualization
    """
    
    # Collect all certificates with their validity periods and hierarchy info
    certs = []
    ca_engines = {}  # Track CA engines for hierarchy mapping
    
    for engine in pki_engines:
        # Add main CA certificate if available
        if engine.get('cert_not_before') and engine.get('cert_not_after'):
            engine_namespace = engine.get('namespace', 'root')
            if all_namespaces and engine_namespace != 'root':
                cert_name = f"{engine_namespace}::{engine['path']} (Main CA)"
            else:
                cert_name = f"{engine['path']} (Main CA)"
            
            cert_entry = {
                'name': cert_name,
                'not_before': engine['cert_not_before'],
                'not_after': engine['cert_not_after'],
                'engine_path': engine['path'],
                'namespace': engine_namespace,
                'cert_type': 'root_ca',
                'parent_ca': None
            }
            certs.append(cert_entry)
            ca_engines[engine['path']] = cert_entry
        
        # Add all issuers
        for issuer in engine.get('issuers', []):
            if issuer.get('not_before') and issuer.get('not_after'):
                issuer_name = issuer.get('common_name') or issuer.get('name', 'Unknown')
                engine_namespace = engine.get('namespace', 'root')
                
                # Try to determine if this is an intermediate CA by checking if it's signed by another CA
                # For now, assume issuers in different engines than main CAs are intermediates
                is_intermediate = engine['path'] not in ca_engines or len(engine.get('issuers', [])) > 1
                
                if all_namespaces and engine_namespace != 'root':
                    full_name = f"{engine_namespace}::{engine['path']}/{issuer_name}"
                else:
                    full_name = f"{engine['path']}/{issuer_name}"
                
                cert_entry = {
                    'name': full_name,
                    'not_before': issuer['not_before'],
                    'not_after': issuer['not_after'],
                    'engine_path': engine['path'],
                    'namespace': engine_namespace,
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
        return ""
    
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
    
    # Build the timeline visualization string
    output_lines = []
    output_lines.append(f"\n{'='*60}")
    output_lines.append("CERTIFICATE VALIDITY TIMELINE")
    output_lines.append(f"{'='*60}")
    output_lines.append(f"Timeline: {format_datetime(timeline_start)} to {format_datetime(timeline_end)}")
    
    # Current time marker
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Use the provided timeline width
    # timeline_width = 50  # This line is now removed since it's a parameter
    
    output_lines.append(f"\n{'Certificate Name':<50} {'Timeline':<{timeline_width}} {'Status'}")
    output_lines.append(f"{'-'*50} {'-'*timeline_width} {'-'*15}")
    
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
        output_lines.append(f"{cert_name:<50} {timeline_str:<{timeline_width}} {status}")
        
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
                output_lines.append(connection_line)
    
    # Legend
    output_lines.append(f"\n{'Legend:'}")
    output_lines.append(f"  📜       Root CA certificate")
    output_lines.append(f"  ↳        Intermediate CA (signed by parent)")
    output_lines.append(f"  │        Hierarchy connection")
    output_lines.append(f"  ├{'█'*8}┤  Certificate validity period")
    output_lines.append(f"  ●        Current time (within validity)")
    output_lines.append(f"  │        Current time (outside validity)")
    output_lines.append(f"  ✓        Valid (>90 days remaining)")
    output_lines.append(f"  ⚡       Expires soon (30-90 days)")
    output_lines.append(f"  ⚠️        Critical (< 30 days)")
    
    return '\n'.join(output_lines)


def scan_pki_secrets_engines(client: hvac.Client, all_namespaces: bool = False) -> Dict[str, Any]:
    """
    Scan Vault for PKI secrets engines.
    
    Args:
        client: Authenticated Vault client
        all_namespaces: If True, scan all namespaces (Enterprise feature)
        
    Returns:
        Dictionary containing vault info and PKI engine information
    """
    try:
        # Check if this is Vault Enterprise
        try:
            sys_health = client.sys.read_health_status()
            version_info = sys_health.get('version', '')
            is_enterprise = '+ent' in version_info or 'enterprise' in version_info.lower()
        except Exception:
            version_info = 'Unknown'
            is_enterprise = False
        
        if all_namespaces and not is_enterprise:
            raise Exception("All namespaces scan requires Vault Enterprise")
        
        # Store original namespace
        original_namespace = getattr(client.adapter, 'namespace', None)
        
        if all_namespaces:
            # Get list of all namespaces
            namespaces_to_scan = _get_all_namespaces(client)
            print(f"Found {len(namespaces_to_scan)} namespace(s) to scan: {', '.join(namespaces_to_scan)}")
        else:
            # Get current namespace (if any)
            current_namespace = original_namespace or 'root'
            namespaces_to_scan = [current_namespace]
        
        all_pki_engines = []
        scanned_namespaces = []
        
        # Scan each namespace
        for namespace in namespaces_to_scan:
            try:
                # Set the namespace
                if namespace != 'root':
                    client.adapter.namespace = namespace
                else:
                    client.adapter.namespace = None
                
                print(f"  Scanning namespace: {namespace}")
                
                # Scan PKI engines in this namespace
                namespace_engines = _scan_pki_in_namespace(client, namespace, is_enterprise)
                all_pki_engines.extend(namespace_engines)
                scanned_namespaces.append(namespace)
                
            except Exception as e:
                print(f"  ⚠️ Error scanning namespace '{namespace}': {e}")
                continue
        
        # Restore original namespace
        client.adapter.namespace = original_namespace
        
        return {
            'vault_version': version_info,
            'is_enterprise': is_enterprise,
            'scanned_namespaces': scanned_namespaces,
            'all_namespaces_scan': all_namespaces,
            'pki_engines': all_pki_engines
        }
        
    except Exception as e:
        # Restore original namespace on error
        if 'original_namespace' in locals():
            client.adapter.namespace = original_namespace
        raise Exception(f"Failed to scan for PKI secrets engines: {str(e)}")


def _get_all_namespaces(client: hvac.Client) -> List[str]:
    """
    Get list of all available namespaces.
    
    Args:
        client: Authenticated Vault client
        
    Returns:
        List of namespace names
    """
    try:
        # Reset to root namespace to list all namespaces
        original_namespace = getattr(client.adapter, 'namespace', None)
        client.adapter.namespace = None
        
        # List namespaces
        namespaces_response = client.sys.list_namespaces()
        namespace_keys = namespaces_response.get('data', {}).get('keys', [])
        
        # Start with root namespace
        namespaces = ['root']
        
        # Add other namespaces (remove trailing slashes)
        for ns in namespace_keys:
            ns_clean = ns.rstrip('/')
            if ns_clean and ns_clean != 'root':
                namespaces.append(ns_clean)
        
        # Restore original namespace
        client.adapter.namespace = original_namespace
        
        return namespaces
    except Exception as e:
        # Restore original namespace on error
        client.adapter.namespace = original_namespace
        raise Exception(f"Failed to list namespaces: {str(e)}")


def _scan_pki_in_namespace(client: hvac.Client, namespace: str, is_enterprise: bool) -> List[Dict[str, Any]]:
    """
    Scan PKI engines in a specific namespace.
    
    Args:
        client: Authenticated Vault client
        namespace: Namespace to scan
        is_enterprise: Whether this is Vault Enterprise
        
    Returns:
        List of PKI engine information dictionaries
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
                'namespace': namespace,
                'type': mount_info.get('type'),
                'description': mount_info.get('description', ''),
                'config': mount_info.get('config', {}),
                'options': mount_info.get('options', {}),
                'accessor': mount_info.get('accessor', ''),
                'is_enterprise': is_enterprise,
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
        raise Exception(f"Failed to scan PKI engines in namespace '{namespace}': {str(e)}")


def print_pki_scan_results(scan_data: Dict[str, Any], timeline_width: int = 50) -> str:
    """
    Format the PKI scan results as a string.
    
    Args:
        scan_data: Dictionary containing vault info and PKI engine information
        timeline_width: Width of the timeline visualization in characters
        
    Returns:
        Formatted string containing the scan results
    """
    # Extract data from the scan results
    vault_version = scan_data.get('vault_version', 'Unknown')
    is_enterprise = scan_data.get('is_enterprise', False)
    scanned_namespaces = scan_data.get('scanned_namespaces', ['root'])
    all_namespaces_scan = scan_data.get('all_namespaces_scan', False)
    pki_engines = scan_data.get('pki_engines', [])
    
    output_lines = []
    
    # Display vault information
    output_lines.append("VAULT INFORMATION")
    output_lines.append("=" * 20)
    output_lines.append(f"Version: {vault_version}")
    if is_enterprise:
        output_lines.append("Edition: ✓ Vault Enterprise")
        if all_namespaces_scan:
            output_lines.append(f"Scanned Namespaces: {', '.join(scanned_namespaces)} ({len(scanned_namespaces)} total)")
        else:
            output_lines.append(f"Namespace: {scanned_namespaces[0] if scanned_namespaces else 'root'}")
    else:
        output_lines.append("Edition: ℹ️ Vault Open Source")
        if len(scanned_namespaces) > 1 or (scanned_namespaces and scanned_namespaces[0] != 'root'):
            output_lines.append(f"Namespace: {scanned_namespaces[0] if scanned_namespaces else 'root'} (Note: Namespaces are Enterprise feature)")
    
    # Display PKI engines information
    if not pki_engines:
        output_lines.append("\nNo PKI secrets engines found.")
        return '\n'.join(output_lines)
    
    output_lines.append(f"\nFound {len(pki_engines)} PKI secrets engine(s):")
    output_lines.append("=" * 50)
    
    for i, engine in enumerate(pki_engines, 1):
        # Show namespace if scanning multiple namespaces or not in root
        engine_namespace = engine.get('namespace', 'root')
        if all_namespaces_scan or engine_namespace != 'root':
            output_lines.append(f"\n{i}. PKI Engine: {engine['path']} (namespace: {engine_namespace})")
        else:
            output_lines.append(f"\n{i}. PKI Engine: {engine['path']}")
        output_lines.append(f"   Description: {engine['description'] or 'No description'}")
        output_lines.append(f"   Accessor: {engine['accessor']}")
        
        if engine['ca_certificate']:
            output_lines.append("   ✓ CA Certificate configured")
            
            # Display certificate validity period
            start_date = format_datetime(engine.get('cert_not_before'))
            end_date = format_datetime(engine.get('cert_not_after'))
            output_lines.append(f"   Valid from: {start_date}")
            output_lines.append(f"   Valid until: {end_date}")
            
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
                    output_lines.append(f"   ⚠️  EXPIRED {abs(days_until_expiry)} days ago")
                elif days_until_expiry < 30:
                    output_lines.append(f"   ⚠️  Expires in {days_until_expiry} days")
                elif days_until_expiry < 90:
                    output_lines.append(f"   ⚡ Expires in {days_until_expiry} days")
        else:
            output_lines.append("   ✗ CA Certificate not configured")
        
        if engine['roles']:
            output_lines.append(f"   Roles: {', '.join(engine['roles'])}")
        else:
            output_lines.append("   Roles: None configured")
        
        # Display issuers information
        if engine.get('issuers'):
            output_lines.append(f"   Issuers: {len(engine['issuers'])} certificate(s)")
            for j, issuer in enumerate(engine['issuers'], 1):
                issuer_name = issuer.get('common_name') or issuer.get('name', 'Unknown')
                output_lines.append(f"     {j}. {issuer_name}")
                output_lines.append(f"        ID: {issuer['id']}")
                
                if issuer.get('not_before') and issuer.get('not_after'):
                    start_date = format_datetime(issuer['not_before'])
                    end_date = format_datetime(issuer['not_after'])
                    output_lines.append(f"        Valid: {start_date} to {end_date}")
                    
                    # Check expiration status for this issuer
                    cert_expiry = issuer['not_after']
                    if cert_expiry.tzinfo is None:
                        cert_expiry = cert_expiry.replace(tzinfo=datetime.timezone.utc)
                    
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_until_expiry = (cert_expiry - now).days
                    
                    if days_until_expiry < 0:
                        output_lines.append(f"        ⚠️  EXPIRED {abs(days_until_expiry)} days ago")
                    elif days_until_expiry < 30:
                        output_lines.append(f"        ⚠️  Expires in {days_until_expiry} days")
                    elif days_until_expiry < 90:
                        output_lines.append(f"        ⚡ Expires in {days_until_expiry} days")
                else:
                    output_lines.append(f"        Valid: Unknown")
        else:
            output_lines.append("   Issuers: None found")
        
        if engine['ca_config']:
            output_lines.append("   CA Configuration:")
            for key, value in engine['ca_config'].items():
                if key != 'private_key':  # Don't print sensitive data
                    output_lines.append(f"     {key}: {value}")
    
    # Add timeline visualization
    timeline_output = create_timeline_visualization(pki_engines, timeline_width, all_namespaces_scan)
    if timeline_output:
        output_lines.append(timeline_output)
    
    return '\n'.join(output_lines)


def generate_html_report(scan_data: Dict[str, Any], timeline_width: int = 50) -> str:
    """
    Generate an HTML report for PKI scan results with interactive features.
    
    Args:
        scan_data: Dictionary containing vault info and PKI engine information
        timeline_width: Width of the timeline visualization in characters
        
    Returns:
        Complete HTML document as a string
    """
    import datetime
    from utils import format_datetime
    
    # Extract data from the scan results
    vault_version = scan_data.get('vault_version', 'Unknown')
    is_enterprise = scan_data.get('is_enterprise', False)
    scanned_namespaces = scan_data.get('scanned_namespaces', ['root'])
    all_namespaces_scan = scan_data.get('all_namespaces_scan', False)
    pki_engines = scan_data.get('pki_engines', [])
    
    # Generate timestamp
    report_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vault PKI Manager Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-top: 30px;
        }}
        h3 {{
            color: #2c3e50;
            margin-top: 25px;
        }}
        .vault-info {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 25px;
        }}
        .vault-info h2 {{
            color: white;
            border-left: 4px solid #ffffff;
            margin-top: 0;
        }}
        
        /* Collapsible PKI Engine Cards */
        .engine-card {{
            border: 1px solid #ddd;
            border-radius: 8px;
            margin: 15px 0;
            background: #fdfdfd;
            transition: all 0.3s ease;
            overflow: hidden;
        }}
        .engine-card:hover {{
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        .engine-header {{
            padding: 20px;
            cursor: pointer;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.3s ease;
        }}
        .engine-header:hover {{
            background: linear-gradient(135deg, #e9ecef 0%, #dee2e6 100%);
        }}
        .engine-title {{
            font-size: 1.2em;
            font-weight: bold;
            color: #2c3e50;
            display: flex;
            align-items: center;
        }}
        .collapse-indicator {{
            font-size: 1.5em;
            color: #6c757d;
            transition: transform 0.3s ease;
        }}
        .collapse-indicator.collapsed {{
            transform: rotate(-90deg);
        }}
        .engine-content {{
            padding: 20px;
            display: block;
        }}
        .engine-content.collapsed {{
            display: none;
        }}
        .namespace-badge {{
            background: #3498db;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-left: 10px;
        }}
        .status-valid {{
            color: #27ae60;
            font-weight: bold;
        }}
        .status-warning {{
            color: #f39c12;
            font-weight: bold;
        }}
        .status-expired {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .status-configured {{
            color: #27ae60;
        }}
        .status-not-configured {{
            color: #e74c3c;
        }}
        
        /* Interactive Timeline Chart */
        .timeline-container {{
            margin: 30px 0;
            background: #f8f9fa;
            padding: 25px;
            border-radius: 12px;
            border: 1px solid #e9ecef;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        }}
        .timeline-controls {{
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .timeline-control {{
            padding: 8px 16px;
            border: 2px solid #dee2e6;
            border-radius: 25px;
            background: white;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .timeline-control:hover {{
            background: #e9ecef;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }}
        .timeline-control.active {{
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            border-color: #2980b9;
            box-shadow: 0 4px 12px rgba(52, 152, 219, 0.3);
        }}
        
        /* Chart Container */
        .chart-container {{
            position: relative;
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        #timelineChart {{
            width: 100%;
            height: 400px;
            cursor: crosshair;
        }}
        
        /* Chart Tooltip */
        .chart-tooltip {{
            position: absolute;
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: #ecf0f1;
            padding: 12px 16px;
            border-radius: 8px;
            border: 1px solid #34495e;
            font-size: 12px;
            z-index: 1000;
            display: none;
            max-width: 320px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
            backdrop-filter: blur(10px);
        }}
        .chart-tooltip::before {{
            content: '';
            position: absolute;
            top: -6px;
            left: 15px;
            width: 0;
            height: 0;
            border-left: 6px solid transparent;
            border-right: 6px solid transparent;
            border-bottom: 6px solid #2c3e50;
        }}
        
        /* Chart Legend */
        .chart-legend {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .chart-legend h3 {{
            margin: 0 0 15px 0;
            color: #2c3e50;
            font-size: 1.1em;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }}
        .legend-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 12px;
            margin-bottom: 15px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px;
            border-radius: 6px;
            transition: background 0.3s ease;
        }}
        .legend-item:hover {{
            background: #f8f9fa;
        }}
        .legend-color {{
            width: 20px;
            height: 12px;
            border-radius: 3px;
            border: 1px solid rgba(0,0,0,0.1);
        }}
        .legend-marker.current-time {{
            width: 20px;
            height: 12px;
            background: repeating-linear-gradient(
                45deg,
                #e74c3c,
                #e74c3c 3px,
                transparent 3px,
                transparent 6px
            );
            border: 1px solid #e74c3c;
            border-radius: 3px;
        }}
        
        /* Responsive design */
        @media (max-width: 768px) {{
            .timeline-controls {{
                flex-direction: column;
                align-items: stretch;
            }}
            .timeline-control {{
                text-align: center;
                margin-bottom: 5px;
            }}
            #timelineChart {{
                height: 300px;
            }}
            .legend-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        
        .legend {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }}
        .issuer-list {{
            margin-left: 20px;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            border-left: 3px solid #3498db;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .no-engines {{
            text-align: center;
            color: #7f8c8d;
            font-style: italic;
            padding: 40px;
        }}
        
        /* Utility classes */
        .collapsed {{
            display: none !important;
        }}
        .show {{
            display: block !important;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Vault PKI Manager Report</h1>
        
        <div class="vault-info">
            <h2>📊 Vault Information</h2>
            <p><strong>Version:</strong> {vault_version}</p>"""
    
    if is_enterprise:
        html_content += f"""
            <p><strong>Edition:</strong> ✓ Vault Enterprise</p>"""
        if all_namespaces_scan:
            html_content += f"""
            <p><strong>Scanned Namespaces:</strong> {', '.join(scanned_namespaces)} ({len(scanned_namespaces)} total)</p>"""
        else:
            html_content += f"""
            <p><strong>Namespace:</strong> {scanned_namespaces[0] if scanned_namespaces else 'root'}</p>"""
    else:
        html_content += f"""
            <p><strong>Edition:</strong> ℹ️ Vault Open Source</p>"""
        if len(scanned_namespaces) > 1 or (scanned_namespaces and scanned_namespaces[0] != 'root'):
            html_content += f"""
            <p><strong>Namespace:</strong> {scanned_namespaces[0] if scanned_namespaces else 'root'} <em>(Note: Namespaces are Enterprise feature)</em></p>"""
    
    html_content += f"""
        </div>
        
        <h2>🏛️ PKI Secrets Engines ({len(pki_engines)} found)</h2>"""
    
    if not pki_engines:
        html_content += """
        <div class="no-engines">
            <p>No PKI secrets engines found.</p>
        </div>"""
    else:
        # Add PKI engines information with collapsible sections
        for i, engine in enumerate(pki_engines, 1):
            engine_namespace = engine.get('namespace', 'root')
            namespace_badge = ""
            if all_namespaces_scan or engine_namespace != 'root':
                namespace_badge = f'<span class="namespace-badge">{engine_namespace}</span>'
            
            ca_status = "status-configured" if engine['ca_certificate'] else "status-not-configured"
            ca_text = "✓ Configured" if engine['ca_certificate'] else "✗ Not configured"
            
            html_content += f"""
        <div class="engine-card">
            <div class="engine-header" onclick="toggleEngine('{i}')">
                <div class="engine-title">
                    {i}. PKI Engine: {engine['path']}{namespace_badge}
                    <span style="margin-left: 15px; font-size: 0.8em; color: #6c757d;">
                        <span class="{ca_status}">{ca_text}</span>
                    </span>
                </div>
                <div class="collapse-indicator" id="indicator-{i}">▼</div>
            </div>
            <div class="engine-content" id="content-{i}">
                <p><strong>Description:</strong> {engine['description'] or 'No description'}</p>
                <p><strong>Accessor:</strong> {engine['accessor']}</p>
                <p><strong>CA Certificate:</strong> <span class="{ca_status}">{ca_text}</span></p>"""
            
            if engine['ca_certificate']:
                start_date = format_datetime(engine.get('cert_not_before'))
                end_date = format_datetime(engine.get('cert_not_after'))
                html_content += f"""
                <p><strong>Valid from:</strong> {start_date}</p>
                <p><strong>Valid until:</strong> {end_date}</p>"""
                
                # Check expiration status
                if engine.get('cert_not_after'):
                    cert_expiry = engine['cert_not_after']
                    if cert_expiry.tzinfo is None:
                        cert_expiry = cert_expiry.replace(tzinfo=datetime.timezone.utc)
                    
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_until_expiry = (cert_expiry - now).days
                    
                    if days_until_expiry < 0:
                        status_class = "status-expired"
                        status_text = f"⚠️ EXPIRED {abs(days_until_expiry)} days ago"
                    elif days_until_expiry < 30:
                        status_class = "status-expired"
                        status_text = f"⚠️ Expires in {days_until_expiry} days"
                    elif days_until_expiry < 90:
                        status_class = "status-warning"
                        status_text = f"⚡ Expires in {days_until_expiry} days"
                    else:
                        status_class = "status-valid"
                        status_text = f"✓ {days_until_expiry} days remaining"
                    
                    html_content += f"""
                <p><strong>Status:</strong> <span class="{status_class}">{status_text}</span></p>"""
            
            # Roles
            if engine['roles']:
                html_content += f"""
                <p><strong>Roles:</strong> {', '.join(engine['roles'])}</p>"""
            else:
                html_content += f"""
                <p><strong>Roles:</strong> None configured</p>"""
            
            # Issuers
            if engine.get('issuers'):
                html_content += f"""
                <h3>📜 Issuers ({len(engine['issuers'])} certificate(s))</h3>
                <div class="issuer-list">"""
                
                for j, issuer in enumerate(engine['issuers'], 1):
                    issuer_name = issuer.get('common_name') or issuer.get('name', 'Unknown')
                    html_content += f"""
                    <div>
                        <strong>{j}. {issuer_name}</strong><br>
                        <small>ID: {issuer['id']}</small><br>"""
                    
                    if issuer.get('not_before') and issuer.get('not_after'):
                        start_date = format_datetime(issuer['not_before'])
                        end_date = format_datetime(issuer['not_after'])
                        html_content += f"""
                        <small>Valid: {start_date} to {end_date}</small><br>"""
                        
                        # Check issuer expiration status
                        cert_expiry = issuer['not_after']
                        if cert_expiry.tzinfo is None:
                            cert_expiry = cert_expiry.replace(tzinfo=datetime.timezone.utc)
                        
                        now = datetime.datetime.now(datetime.timezone.utc)
                        days_until_expiry = (cert_expiry - now).days
                        
                        if days_until_expiry < 0:
                            status_class = "status-expired"
                            status_text = f"⚠️ EXPIRED {abs(days_until_expiry)} days ago"
                        elif days_until_expiry < 30:
                            status_class = "status-expired"
                            status_text = f"⚠️ Expires in {days_until_expiry} days"
                        elif days_until_expiry < 90:
                            status_class = "status-warning"
                            status_text = f"⚡ Expires in {days_until_expiry} days"
                        else:
                            status_class = "status-valid"
                            status_text = f"✓ Valid"
                        
                        html_content += f"""
                        <small><span class="{status_class}">{status_text}</span></small>"""
                    else:
                        html_content += f"""
                        <small>Valid: Unknown</small>"""
                    
                    html_content += """
                    </div><br>"""
                
                html_content += """
                </div>"""
            else:
                html_content += f"""
                <p><strong>Issuers:</strong> None found</p>"""
            
            html_content += """
            </div>
        </div>"""
        
        # Add interactive timeline visualization
        timeline_html = _generate_interactive_html_timeline(pki_engines, timeline_width, all_namespaces_scan)
        html_content += timeline_html
    
    html_content += f"""
        <div class="footer">
            <p>Report generated by Vault PKI Manager on {report_time}</p>
        </div>
    </div>
    
    <script>
        // Collapsible PKI Engine functionality
        function toggleEngine(engineId) {{
            const content = document.getElementById('content-' + engineId);
            const indicator = document.getElementById('indicator-' + engineId);
            
            if (content.classList.contains('collapsed')) {{
                content.classList.remove('collapsed');
                indicator.classList.remove('collapsed');
                indicator.textContent = '▼';
            }} else {{
                content.classList.add('collapsed');
                indicator.classList.add('collapsed');
                indicator.textContent = '▶';
            }}
        }}
        
        // Legacy timeline filtering (kept for compatibility)
        function filterTimeline(filter) {{
            // This function is kept for backward compatibility
            // The new chart uses filterTimelineChart instead
            filterTimelineChart(filter);
        }}
        
        // Certificate tooltip functionality
        let tooltip = null;
        
        function showTooltip(event, certData) {{
            hideTooltip();
            
            tooltip = document.createElement('div');
            tooltip.className = 'cert-tooltip';
            tooltip.innerHTML = certData;
            document.body.appendChild(tooltip);
            
            const rect = event.target.getBoundingClientRect();
            tooltip.style.left = (rect.left + window.scrollX) + 'px';
            tooltip.style.top = (rect.bottom + window.scrollY + 5) + 'px';
            tooltip.style.display = 'block';
        }}
        
        function hideTooltip() {{
            if (tooltip) {{
                document.body.removeChild(tooltip);
                tooltip = null;
            }}
        }}
        
        // Expand/Collapse all engines
        function toggleAllEngines(expand) {{
            const engines = document.querySelectorAll('.engine-content');
            const indicators = document.querySelectorAll('.collapse-indicator');
            
            engines.forEach((content, index) => {{
                const indicator = indicators[index];
                if (expand) {{
                    content.classList.remove('collapsed');
                    indicator.classList.remove('collapsed');
                    indicator.textContent = '▼';
                }} else {{
                    content.classList.add('collapsed');
                    indicator.classList.add('collapsed');
                    indicator.textContent = '▶';
                }}
            }});
        }}
        
        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {{
            // Add global controls
            const header = document.querySelector('h2');
            if (header && header.textContent.includes('PKI Secrets Engines')) {{
                const controls = document.createElement('div');
                controls.style.marginTop = '10px';
                controls.innerHTML = `
                    <button onclick="toggleAllEngines(true)" style="margin-right: 10px; padding: 5px 10px; border: 1px solid #dee2e6; border-radius: 4px; background: white; cursor: pointer;">Expand All</button>
                    <button onclick="toggleAllEngines(false)" style="padding: 5px 10px; border: 1px solid #dee2e6; border-radius: 4px; background: white; cursor: pointer;">Collapse All</button>
                `;
                header.appendChild(controls);
            }}
        }});
        
        // Hide tooltip when clicking elsewhere
        document.addEventListener('click', function(event) {{
            if (!event.target.closest('.cert-row')) {{
                hideTooltip();
            }}
        }});
    </script>
</body>
</html>"""
    
    return html_content


def _generate_interactive_html_timeline(pki_engines: List[Dict[str, Any]], timeline_width: int = 50, all_namespaces: bool = False) -> str:
    """
    Generate interactive HTML timeline visualization with a proper chart view.
    
    Args:
        pki_engines: List of PKI engine information dictionaries
        timeline_width: Width of the timeline in characters (not used in chart view)
        all_namespaces: Whether this is an all-namespaces scan
        
    Returns:
        HTML string containing the interactive chart timeline visualization
    """
    import datetime
    import json
    from utils import format_datetime
    
    # Collect all certificates (reusing logic from text timeline)
    certs = []
    ca_engines = {}
    
    for engine in pki_engines:
        if engine.get('cert_not_before') and engine.get('cert_not_after'):
            engine_namespace = engine.get('namespace', 'root')
            if all_namespaces and engine_namespace != 'root':
                cert_name = f"{engine_namespace}::{engine['path']} (Main CA)"
            else:
                cert_name = f"{engine['path']} (Main CA)"
            
            cert_entry = {
                'name': cert_name,
                'not_before': engine['cert_not_before'],
                'not_after': engine['cert_not_after'],
                'engine_path': engine['path'],
                'namespace': engine_namespace,
                'cert_type': 'root_ca',
                'parent_ca': None,
                'description': engine.get('description', ''),
                'accessor': engine.get('accessor', '')
            }
            certs.append(cert_entry)
            ca_engines[engine['path']] = cert_entry
        
        for issuer in engine.get('issuers', []):
            if issuer.get('not_before') and issuer.get('not_after'):
                issuer_name = issuer.get('common_name') or issuer.get('name', 'Unknown')
                engine_namespace = engine.get('namespace', 'root')
                
                is_intermediate = engine['path'] not in ca_engines or len(engine.get('issuers', [])) > 1
                
                if all_namespaces and engine_namespace != 'root':
                    full_name = f"{engine_namespace}::{engine['path']}/{issuer_name}"
                else:
                    full_name = f"{engine['path']}/{issuer_name}"
                
                cert_entry = {
                    'name': full_name,
                    'not_before': issuer['not_before'],
                    'not_after': issuer['not_after'],
                    'engine_path': engine['path'],
                    'namespace': engine_namespace,
                    'cert_type': 'intermediate' if is_intermediate else 'issuer',
                    'parent_ca': None,
                    'issuer_id': issuer.get('id', ''),
                    'description': f"Issuer in {engine['path']}"
                }
                certs.append(cert_entry)
    
    if not certs:
        return ""
    
    # Normalize timezone for all certificates and prepare data for JavaScript
    chart_data = []
    now = datetime.datetime.now(datetime.timezone.utc)
    
    for cert in certs:
        if cert['not_before'].tzinfo is None:
            cert['not_before'] = cert['not_before'].replace(tzinfo=datetime.timezone.utc)
        if cert['not_after'].tzinfo is None:
            cert['not_after'] = cert['not_after'].replace(tzinfo=datetime.timezone.utc)
        
        # Determine status
        if now < cert['not_before']:
            status = "Future"
            status_class = "future"
        elif now > cert['not_after']:
            days_expired = (now - cert['not_after']).days
            status = f"EXPIRED ({days_expired}d)"
            status_class = "expired"
        else:
            days_remaining = (cert['not_after'] - now).days
            if days_remaining < 30:
                status = f"Critical ({days_remaining}d left)"
                status_class = "critical"
            elif days_remaining < 90:
                status = f"Warning ({days_remaining}d left)"
                status_class = "warning"
            else:
                status = f"Valid ({days_remaining}d left)"
                status_class = "valid"
        
        chart_data.append({
            'name': cert['name'],
            'start': cert['not_before'].isoformat(),
            'end': cert['not_after'].isoformat(),
            'type': cert['cert_type'],
            'status': status,
            'status_class': status_class,
            'engine_path': cert['engine_path'],
            'namespace': cert['namespace'],
            'description': cert.get('description', ''),
            'issuer_id': cert.get('issuer_id', ''),
            'days_remaining': (cert['not_after'] - now).days if now <= cert['not_after'] else -(now - cert['not_after']).days
        })
    
    # Sort certificates by type and start date
    chart_data.sort(key=lambda x: (
        0 if x['type'] == 'root_ca' else 1 if x['type'] == 'intermediate' else 2,
        x['start']
    ))
    
    # Calculate timeline bounds
    all_starts = [datetime.datetime.fromisoformat(cert['start']) for cert in chart_data]
    all_ends = [datetime.datetime.fromisoformat(cert['end']) for cert in chart_data]
    
    timeline_start = min(all_starts)
    timeline_end = max(all_ends)
    
    # Add some padding
    time_range = timeline_end - timeline_start
    padding = time_range * 0.05
    timeline_start -= padding
    timeline_end += padding
    
    html = f"""
        <div class="timeline-container">
            <h2>📊 Interactive Certificate Timeline Chart</h2>
            <p><strong>Timeline Range:</strong> {format_datetime(timeline_start)} to {format_datetime(timeline_end)}</p>
            
            <div class="timeline-controls">
                <span style="font-weight: bold; margin-right: 15px;">Filter:</span>
                <div class="timeline-control active" onclick="filterTimelineChart('all')">All Certificates</div>
                <div class="timeline-control" onclick="filterTimelineChart('valid')">Valid</div>
                <div class="timeline-control" onclick="filterTimelineChart('warning')">Warning</div>
                <div class="timeline-control" onclick="filterTimelineChart('critical')">Critical</div>
                <div class="timeline-control" onclick="filterTimelineChart('expired')">Expired</div>
                <div class="timeline-control" onclick="filterTimelineChart('root_ca')">Root CAs</div>
                <div class="timeline-control" onclick="filterTimelineChart('intermediate')">Intermediates</div>
            </div>
            
            <div class="chart-container">
                <canvas id="timelineChart" width="1000" height="400"></canvas>
                <div id="chartTooltip" class="chart-tooltip"></div>
            </div>
            
            <div class="chart-legend">
                <h3>📋 Chart Legend</h3>
                <div class="legend-grid">
                    <div class="legend-item">
                        <div class="legend-color" style="background: linear-gradient(90deg, #27ae60, #2ecc71);"></div>
                        <span>Valid Certificate (>90 days)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: linear-gradient(90deg, #f39c12, #e67e22);"></div>
                        <span>Warning (30-90 days)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: linear-gradient(90deg, #e74c3c, #c0392b);"></div>
                        <span>Critical (<30 days)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: linear-gradient(90deg, #95a5a6, #7f8c8d);"></div>
                        <span>Expired</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: linear-gradient(90deg, #3498db, #2980b9);"></div>
                        <span>Future Certificate</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-marker current-time"></div>
                        <span>Current Time</span>
                    </div>
                </div>
                <p><strong>💡 Tip:</strong> Hover over certificate bars for detailed information. Click filter buttons to show specific certificate types or statuses.</p>
            </div>
        </div>
        
        <script>
            // Chart data and configuration
            const chartData = {json.dumps(chart_data)};
            const timelineStart = new Date('{timeline_start.isoformat()}');
            const timelineEnd = new Date('{timeline_end.isoformat()}');
            const currentTime = new Date();
            
            let filteredData = [...chartData];
            let canvas, ctx, tooltip;
            
            // Initialize chart when DOM is ready
            document.addEventListener('DOMContentLoaded', function() {{
                canvas = document.getElementById('timelineChart');
                ctx = canvas.getContext('2d');
                tooltip = document.getElementById('chartTooltip');
                
                // Set up event listeners
                canvas.addEventListener('mousemove', handleMouseMove);
                canvas.addEventListener('mouseleave', hideChartTooltip);
                canvas.addEventListener('click', handleClick);
                
                // Initial render
                renderChart();
            }});
            
            function renderChart() {{
                if (!ctx) return;
                
                // Clear canvas
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                
                const padding = {{ top: 40, right: 60, bottom: 60, left: 250 }};
                const chartWidth = canvas.width - padding.left - padding.right;
                const chartHeight = canvas.height - padding.top - padding.bottom;
                
                // Calculate time scale
                const timeRange = timelineEnd.getTime() - timelineStart.getTime();
                const timeToX = (time) => padding.left + ((time - timelineStart.getTime()) / timeRange) * chartWidth;
                
                // Draw time axis
                drawTimeAxis(ctx, padding, chartWidth, chartHeight);
                
                // Draw certificate bars
                const barHeight = Math.max(20, (chartHeight - 20) / filteredData.length);
                const barSpacing = 4;
                
                filteredData.forEach((cert, index) => {{
                    const y = padding.top + index * (barHeight + barSpacing);
                    const startX = timeToX(new Date(cert.start).getTime());
                    const endX = timeToX(new Date(cert.end).getTime());
                    const width = Math.max(2, endX - startX);
                    
                    // Get color based on status
                    const colors = getStatusColors(cert.status_class);
                    
                    // Draw certificate bar with gradient
                    const gradient = ctx.createLinearGradient(startX, y, endX, y);
                    gradient.addColorStop(0, colors.start);
                    gradient.addColorStop(1, colors.end);
                    
                    ctx.fillStyle = gradient;
                    ctx.fillRect(startX, y, width, barHeight - 2);
                    
                    // Add border
                    ctx.strokeStyle = colors.border;
                    ctx.lineWidth = 1;
                    ctx.strokeRect(startX, y, width, barHeight - 2);
                    
                    // Draw certificate name
                    ctx.fillStyle = '#2c3e50';
                    ctx.font = '12px Arial';
                    ctx.textAlign = 'right';
                    ctx.textBaseline = 'middle';
                    
                    const displayName = cert.name.length > 35 ? cert.name.substring(0, 32) + '...' : cert.name;
                    const typeIcon = cert.type === 'root_ca' ? '📜' : cert.type === 'intermediate' ? '🔗' : '📄';
                    ctx.fillText(`${{typeIcon}} ${{displayName}}`, padding.left - 10, y + barHeight / 2);
                    
                    // Store bar position for mouse interaction
                    cert._chartBounds = {{ x: startX, y: y, width: width, height: barHeight - 2 }};
                }});
                
                // Draw current time line
                const currentX = timeToX(currentTime.getTime());
                if (currentX >= padding.left && currentX <= padding.left + chartWidth) {{
                    ctx.strokeStyle = '#e74c3c';
                    ctx.lineWidth = 3;
                    ctx.setLineDash([5, 5]);
                    ctx.beginPath();
                    ctx.moveTo(currentX, padding.top);
                    ctx.lineTo(currentX, padding.top + chartHeight);
                    ctx.stroke();
                    ctx.setLineDash([]);
                    
                    // Current time label
                    ctx.fillStyle = '#e74c3c';
                    ctx.font = 'bold 12px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText('NOW', currentX, padding.top - 10);
                }}
            }}
            
            function drawTimeAxis(ctx, padding, chartWidth, chartHeight) {{
                const axisY = padding.top + chartHeight;
                
                // Draw main axis line
                ctx.strokeStyle = '#34495e';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.moveTo(padding.left, axisY);
                ctx.lineTo(padding.left + chartWidth, axisY);
                ctx.stroke();
                
                // Calculate time intervals
                const timeRange = timelineEnd.getTime() - timelineStart.getTime();
                const monthsRange = timeRange / (1000 * 60 * 60 * 24 * 30);
                const interval = monthsRange > 24 ? 6 : monthsRange > 12 ? 3 : 1; // months
                
                // Draw time labels
                let currentDate = new Date(timelineStart);
                currentDate.setDate(1); // Start at beginning of month
                
                while (currentDate <= timelineEnd) {{
                    const x = padding.left + ((currentDate.getTime() - timelineStart.getTime()) / timeRange) * chartWidth;
                    
                    if (x >= padding.left && x <= padding.left + chartWidth) {{
                        // Tick mark
                        ctx.strokeStyle = '#7f8c8d';
                        ctx.lineWidth = 1;
                        ctx.beginPath();
                        ctx.moveTo(x, axisY);
                        ctx.lineTo(x, axisY + 5);
                        ctx.stroke();
                        
                        // Label
                        ctx.fillStyle = '#34495e';
                        ctx.font = '10px Arial';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'top';
                        const label = currentDate.toLocaleDateString('en-US', {{ month: 'short', year: '2-digit' }});
                        ctx.fillText(label, x, axisY + 8);
                    }}
                    
                    // Move to next interval
                    currentDate.setMonth(currentDate.getMonth() + interval);
                }}
            }}
            
            function getStatusColors(statusClass) {{
                switch (statusClass) {{
                    case 'valid':
                        return {{ start: '#27ae60', end: '#2ecc71', border: '#1e8449' }};
                    case 'warning':
                        return {{ start: '#f39c12', end: '#e67e22', border: '#d68910' }};
                    case 'critical':
                        return {{ start: '#e74c3c', end: '#c0392b', border: '#a93226' }};
                    case 'expired':
                        return {{ start: '#95a5a6', end: '#7f8c8d', border: '#5d6d7e' }};
                    case 'future':
                        return {{ start: '#3498db', end: '#2980b9', border: '#1f4e79' }};
                    default:
                        return {{ start: '#bdc3c7', end: '#95a5a6', border: '#85929e' }};
                }}
            }}
            
            function handleMouseMove(event) {{
                const rect = canvas.getBoundingClientRect();
                const x = event.clientX - rect.left;
                const y = event.clientY - rect.top;
                
                // Find hovered certificate
                const hoveredCert = filteredData.find(cert => {{
                    const bounds = cert._chartBounds;
                    return bounds && x >= bounds.x && x <= bounds.x + bounds.width && 
                           y >= bounds.y && y <= bounds.y + bounds.height;
                }});
                
                if (hoveredCert) {{
                    showChartTooltip(event, hoveredCert);
                    canvas.style.cursor = 'pointer';
                }} else {{
                    hideChartTooltip();
                    canvas.style.cursor = 'default';
                }}
            }}
            
            function handleClick(event) {{
                const rect = canvas.getBoundingClientRect();
                const x = event.clientX - rect.left;
                const y = event.clientY - rect.top;
                
                // Find clicked certificate
                const clickedCert = filteredData.find(cert => {{
                    const bounds = cert._chartBounds;
                    return bounds && x >= bounds.x && x <= bounds.x + bounds.width && 
                           y >= bounds.y && y <= bounds.y + bounds.height;
                }});
                
                if (clickedCert) {{
                    // Could implement certificate details modal here
                    console.log('Clicked certificate:', clickedCert);
                }}
            }}
            
            function showChartTooltip(event, cert) {{
                const startDate = new Date(cert.start).toLocaleDateString();
                const endDate = new Date(cert.end).toLocaleDateString();
                const daysText = cert.days_remaining >= 0 ? 
                    `${{cert.days_remaining}} days remaining` : 
                    `Expired ${{Math.abs(cert.days_remaining)}} days ago`;
                
                tooltip.innerHTML = `
                    <strong>${{cert.name}}</strong><br>
                    <strong>Type:</strong> ${{cert.type.replace('_', ' ').replace(/\\b\\w/g, l => l.toUpperCase())}}<br>
                    <strong>Valid:</strong> ${{startDate}} - ${{endDate}}<br>
                    <strong>Engine:</strong> ${{cert.engine_path}}<br>
                    <strong>Namespace:</strong> ${{cert.namespace}}<br>
                    ${{cert.description ? `<strong>Description:</strong> ${{cert.description}}<br>` : ''}}
                    ${{cert.issuer_id ? `<strong>Issuer ID:</strong> ${{cert.issuer_id}}<br>` : ''}}
                    <strong>Status:</strong> ${{cert.status}}<br>
                    <strong>Timeline:</strong> ${{daysText}}
                `;
                
                tooltip.style.display = 'block';
                tooltip.style.left = (event.pageX + 10) + 'px';
                tooltip.style.top = (event.pageY - 10) + 'px';
            }}
            
            function hideChartTooltip() {{
                if (tooltip) {{
                    tooltip.style.display = 'none';
                }}
            }}
            
            function filterTimelineChart(filter) {{
                // Update active filter button
                document.querySelectorAll('.timeline-control').forEach(btn => btn.classList.remove('active'));
                event.target.classList.add('active');
                
                // Filter data
                if (filter === 'all') {{
                    filteredData = [...chartData];
                }} else if (['valid', 'warning', 'critical', 'expired', 'future'].includes(filter)) {{
                    filteredData = chartData.filter(cert => cert.status_class === filter);
                }} else if (['root_ca', 'intermediate', 'issuer'].includes(filter)) {{
                    filteredData = chartData.filter(cert => cert.type === filter);
                }}
                
                // Re-render chart
                renderChart();
            }}
        </script>"""
    
    return html
