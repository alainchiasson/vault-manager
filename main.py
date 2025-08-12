import hvac
import os
import argparse
from typing import List, Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime


def get_vault_client() -> hvac.Client:
    """
    Create and return a configured Vault client.
    
    Environment variables expected:
    - VAULT_ADDR: Vault server address
    - VAULT_TOKEN: Vault authentication token
    """
    vault_addr = os.getenv('VAULT_ADDR')
    vault_token = os.getenv('VAULT_TOKEN')
    
    if not vault_addr:
        raise ValueError("VAULT_ADDR environment variable is required")
    if not vault_token:
        raise ValueError("VAULT_TOKEN environment variable is required")
    
    client = hvac.Client(url=vault_addr, token=vault_token)
    
    if not client.is_authenticated():
        raise ValueError("Failed to authenticate with Vault")
    
    return client


def parse_certificate_dates(cert_pem: str) -> Dict[str, Optional[datetime]]:
    """
    Parse certificate PEM data to extract validity dates.
    
    Args:
        cert_pem: Certificate in PEM format
        
    Returns:
        Dictionary with 'not_before' and 'not_after' datetime objects
    """
    try:
        if not cert_pem or not cert_pem.strip():
            return {'not_before': None, 'not_after': None}
        
        # Parse the certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        
        return {
            'not_before': cert.not_valid_before_utc,
            'not_after': cert.not_valid_after_utc
        }
    except Exception:
        # If we can't parse the certificate, return None values
        return {'not_before': None, 'not_after': None}


def extract_common_name_from_certificate(cert_pem: str) -> Optional[str]:
    """
    Extract the common name from a certificate PEM.
    
    Args:
        cert_pem: Certificate in PEM format
        
    Returns:
        Common name string or None if not found
    """
    try:
        if not cert_pem or not cert_pem.strip():
            return None
        
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        subject = cert.subject
        
        for attribute in subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                return attribute.value
        return None
    except Exception:
        return None


def ensure_timezone_aware(dt: datetime) -> datetime:
    """
    Ensure a datetime object is timezone-aware (UTC).
    
    Args:
        dt: Datetime object to check
        
    Returns:
        Timezone-aware datetime object
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def validate_pki_engine(client: hvac.Client, mount_path: str) -> None:
    """
    Validate that a PKI secrets engine exists at the specified path.
    
    Args:
        client: Authenticated Vault client
        mount_path: Path to validate
        
    Raises:
        ValueError: If the path doesn't exist or isn't a PKI engine
    """
    mount_path = mount_path.rstrip('/')
    mounts = client.sys.list_mounted_secrets_engines()
    
    if f"{mount_path}/" not in mounts['data']:
        raise ValueError(f"No secrets engine mounted at '{mount_path}'. Please mount a PKI engine first.")
    
    if mounts['data'][f"{mount_path}/"].get('type') != 'pki':
        raise ValueError(f"Secrets engine at '{mount_path}' is not a PKI engine.")


def configure_ca_urls(client: hvac.Client, mount_path: str) -> None:
    """
    Configure CA URLs for a PKI engine.
    
    Args:
        client: Authenticated Vault client
        mount_path: PKI mount path
    """
    try:
        vault_addr = os.getenv('VAULT_ADDR', 'http://localhost:8200')
        urls_config = {
            'issuing_certificates': f"{vault_addr}/v1/{mount_path}/ca",
            'crl_distribution_points': f"{vault_addr}/v1/{mount_path}/crl"
        }
        client.write(f"{mount_path}/config/urls", **urls_config)
        print("✓ CA URLs configured")
    except Exception as e:
        print(f"Warning: Failed to configure CA URLs: {e}")


def process_issuer_details(client: hvac.Client, mount_path: str, issuer_id: str) -> Optional[Dict[str, Any]]:
    """
    Process details for a single issuer.
    
    Args:
        client: Authenticated Vault client
        mount_path: PKI mount path
        issuer_id: Issuer ID to process
        
    Returns:
        Issuer information dictionary or None if processing fails
    """
    try:
        issuer_detail = client.read(f"{mount_path}/issuer/{issuer_id}")
        if not issuer_detail or 'data' not in issuer_detail:
            return None
            
        issuer_cert = issuer_detail['data'].get('certificate', '')
        issuer_name = issuer_detail['data'].get('issuer_name', issuer_id)
        
        # Parse certificate details
        cert_dates = parse_certificate_dates(issuer_cert)
        common_name = extract_common_name_from_certificate(issuer_cert)
        
        return {
            'id': issuer_id,
            'name': issuer_name,
            'certificate': issuer_cert,
            'not_before': cert_dates['not_before'],
            'not_after': cert_dates['not_after'],
            'common_name': common_name
        }
    except Exception:
        return None


def get_ca_certificate_info(client: hvac.Client, mount_path: str) -> Dict[str, Any]:
    """
    Get CA certificate information for a PKI engine.
    
    Args:
        client: Authenticated Vault client
        mount_path: PKI mount path
        
    Returns:
        Dictionary with CA certificate info
    """
    try:
        ca_cert_response = client.read(f"{mount_path}/cert/ca")
        if ca_cert_response and 'data' in ca_cert_response:
            cert_pem = ca_cert_response['data'].get('certificate', '')
            cert_dates = parse_certificate_dates(cert_pem)
            return {
                'ca_certificate': cert_pem,
                'cert_not_before': cert_dates['not_before'],
                'cert_not_after': cert_dates['not_after']
            }
    except Exception:
        pass
    
    return {
        'ca_certificate': None,
        'cert_not_before': None,
        'cert_not_after': None
    }


def create_timeline_visualization(pki_engines: List[Dict[str, Any]], timeline_width: int = 50) -> None:
    """
    Create a visual timeline showing certificate validity periods.
    
    Args:
        pki_engines: List of PKI engine information dictionaries
        timeline_width: Width of the timeline in characters (default: 50)
    """
    import datetime as dt
    
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
            cert['not_before'] = cert['not_before'].replace(tzinfo=dt.timezone.utc)
        if cert['not_after'].tzinfo is None:
            cert['not_after'] = cert['not_after'].replace(tzinfo=dt.timezone.utc)
    
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
    now = dt.datetime.now(dt.timezone.utc)
    
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


def format_datetime(dt: Optional[datetime]) -> str:
    """
    Format datetime for display.
    
    Args:
        dt: Datetime object to format
        
    Returns:
        Formatted string or 'Unknown' if None
    """
    if dt is None:
        return "Unknown"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


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


def create_root_ca(client: hvac.Client, mount_path: str, common_name: str, 
                   country: Optional[str] = None, organization: Optional[str] = None,
                   ttl: str = "8760h", key_bits: int = 2048, key_type: str = "rsa") -> Dict[str, Any]:
    """
    Create a new root CA in a PKI secrets engine.
    
    Args:
        client: Authenticated Vault client
        mount_path: Path where PKI engine is mounted (e.g., 'pki')
        common_name: Common name for the root CA certificate
        country: Country code (e.g., 'US')
        organization: Organization name
        ttl: Time to live for the certificate (default: 8760h = 1 year)
        key_bits: Number of bits for the key (default: 2048)
        key_type: Type of key to generate (rsa, ec, ed25519)
        
    Returns:
        Dictionary containing the root CA creation response
    """
    try:
        mount_path = mount_path.rstrip('/')
        validate_pki_engine(client, mount_path)
        
        # Build CA data
        ca_data = build_ca_data(common_name, ttl, key_bits, key_type, country, organization)
        
        # Generate the root CA
        print(f"Creating root CA with common name: {common_name}")
        print(f"Mount path: {mount_path}")
        print(f"TTL: {ttl}")
        print(f"Key type: {key_type} ({key_bits} bits)")
        
        response = client.write(f"{mount_path}/root/generate/internal", **ca_data)
        
        if not response or 'data' not in response:
            raise Exception("Failed to generate root CA - no data returned")
        
        # Configure the CA URLs
        configure_ca_urls(client, mount_path)
        
        return {
            'success': True,
            'certificate': response['data'].get('certificate'),
            'issuing_ca': response['data'].get('issuing_ca'),
            'serial_number': response['data'].get('serial_number'),
            'mount_path': mount_path,
            'common_name': common_name
        }
        
    except Exception as e:
        raise Exception(f"Failed to create root CA: {str(e)}")


def enable_pki_engine(client: hvac.Client, mount_path: str, max_lease_ttl: str = "8760h") -> bool:
    """
    Enable a new PKI secrets engine at the specified path.
    
    Args:
        client: Authenticated Vault client
        mount_path: Path to mount the PKI engine
        max_lease_ttl: Maximum lease TTL for the engine
        
    Returns:
        True if successful
    """
    try:
        mount_path = mount_path.rstrip('/')
        
        # Check if already mounted
        mounts = client.sys.list_mounted_secrets_engines()
        if f"{mount_path}/" in mounts['data']:
            engine_type = mounts['data'][f"{mount_path}/"].get('type')
            if engine_type == 'pki':
                print(f"PKI engine already mounted at '{mount_path}'")
                return True
            else:
                raise ValueError(f"Path '{mount_path}' already has a {engine_type} engine mounted")
        
        # Mount the PKI engine
        client.sys.enable_secrets_engine(
            backend_type='pki',
            path=mount_path,
            config={'max_lease_ttl': max_lease_ttl}
        )
        
        print(f"✓ PKI secrets engine enabled at '{mount_path}'")
        return True
        
    except Exception as e:
        raise Exception(f"Failed to enable PKI engine: {str(e)}")


def print_root_ca_result(result: Dict[str, Any]) -> None:
    """
    Print the root CA creation results in a formatted way.
    
    Args:
        result: Root CA creation result dictionary
    """
    if result['success']:
        print("\n" + "=" * 50)
        print("ROOT CA CREATED SUCCESSFULLY")
        print("=" * 50)
        print(f"Mount Path: {result['mount_path']}")
        print(f"Common Name: {result['common_name']}")
        print(f"Serial Number: {result['serial_number']}")
        
        if result['certificate']:
            print(f"\nCA Certificate:")
            print(result['certificate'])
        
        print("\n✓ Root CA is ready for use!")
        print(f"  You can now create intermediate CAs and certificate roles under '{result['mount_path']}'")


def create_intermediate_ca(client: hvac.Client, mount_path: str, common_name: str,
                          signing_ca_path: str, country: Optional[str] = None,
                          organization: Optional[str] = None, ttl: str = "8760h",
                          key_bits: int = 2048, key_type: str = "rsa") -> Dict[str, Any]:
    """
    Create a new intermediate CA (issuing certificate) in a PKI secrets engine.
    
    Args:
        client: Authenticated Vault client
        mount_path: Path where intermediate PKI engine is mounted
        common_name: Common name for the intermediate CA certificate
        signing_ca_path: Path to the root CA that will sign this intermediate
        country: Country code (e.g., 'US')
        organization: Organization name
        ttl: Time to live for the certificate (default: 8760h = 1 year)
        key_bits: Number of bits for the key (default: 2048)
        key_type: Type of key to generate (rsa, ec, ed25519)
        
    Returns:
        Dictionary containing the intermediate CA creation response
    """
    try:
        # Ensure mount paths don't have trailing slashes
        mount_path = mount_path.rstrip('/')
        signing_ca_path = signing_ca_path.rstrip('/')
        
        # Check if both PKI engines are mounted
        mounts = client.sys.list_mounted_secrets_engines()
        
        if f"{mount_path}/" not in mounts['data']:
            raise ValueError(f"No secrets engine mounted at '{mount_path}'. Please mount a PKI engine first.")
        if mounts['data'][f"{mount_path}/"].get('type') != 'pki':
            raise ValueError(f"Secrets engine at '{mount_path}' is not a PKI engine.")
            
        if f"{signing_ca_path}/" not in mounts['data']:
            raise ValueError(f"No secrets engine mounted at '{signing_ca_path}'. Please ensure the signing CA exists.")
        if mounts['data'][f"{signing_ca_path}/"].get('type') != 'pki':
            raise ValueError(f"Secrets engine at '{signing_ca_path}' is not a PKI engine.")
        
        print(f"Creating intermediate CA with common name: {common_name}")
        print(f"Mount path: {mount_path}")
        print(f"Signing CA path: {signing_ca_path}")
        print(f"TTL: {ttl}")
        print(f"Key type: {key_type} ({key_bits} bits)")
        
        # Step 1: Generate intermediate CA CSR
        csr_data = {
            'common_name': common_name,
            'key_bits': key_bits,
            'key_type': key_type,
            'format': 'pem'
        }
        
        # Add optional fields if provided
        if country:
            csr_data['country'] = country
        if organization:
            csr_data['organization'] = organization
        
        print("  Step 1: Generating intermediate CA CSR...")
        csr_response = client.write(f"{mount_path}/intermediate/generate/internal", **csr_data)
        
        if not csr_response or 'data' not in csr_response:
            raise Exception("Failed to generate intermediate CA CSR")
        
        csr = csr_response['data'].get('csr')
        if not csr:
            raise Exception("No CSR returned from intermediate generation")
        
        # Step 2: Sign the CSR with the root CA
        signing_data = {
            'csr': csr,
            'common_name': common_name,
            'ttl': ttl,
            'format': 'pem'
        }
        
        if country:
            signing_data['country'] = country
        if organization:
            signing_data['organization'] = organization
        
        print("  Step 2: Signing CSR with root CA...")
        sign_response = client.write(f"{signing_ca_path}/root/sign-intermediate", **signing_data)
        
        if not sign_response or 'data' not in sign_response:
            raise Exception("Failed to sign intermediate CA certificate")
        
        signed_cert = sign_response['data'].get('certificate')
        issuing_ca = sign_response['data'].get('issuing_ca')
        serial_number = sign_response['data'].get('serial_number')
        
        if not signed_cert:
            raise Exception("No signed certificate returned")
        
        # Step 3: Set the signed certificate on the intermediate CA
        print("  Step 3: Installing signed certificate...")
        cert_data = {
            'certificate': signed_cert
        }
        
        client.write(f"{mount_path}/intermediate/set-signed", **cert_data)
        
        # Step 4: Configure the CA URLs (optional but recommended)
        try:
            vault_addr = os.getenv('VAULT_ADDR', 'http://localhost:8200')
            urls_config = {
                'issuing_certificates': f"{vault_addr}/v1/{mount_path}/ca",
                'crl_distribution_points': f"{vault_addr}/v1/{mount_path}/crl"
            }
            client.write(f"{mount_path}/config/urls", **urls_config)
            print("  ✓ CA URLs configured")
        except Exception as e:
            print(f"  Warning: Failed to configure CA URLs: {e}")
        
        return {
            'success': True,
            'certificate': signed_cert,
            'issuing_ca': issuing_ca,
            'serial_number': serial_number,
            'mount_path': mount_path,
            'common_name': common_name,
            'signing_ca_path': signing_ca_path
        }
        
    except Exception as e:
        raise Exception(f"Failed to create intermediate CA: {str(e)}")


def print_intermediate_ca_result(result: Dict[str, Any]) -> None:
    """
    Print the intermediate CA creation results in a formatted way.
    
    Args:
        result: Intermediate CA creation result dictionary
    """
    if result['success']:
        print("\n" + "=" * 50)
        print("INTERMEDIATE CA CREATED SUCCESSFULLY")
        print("=" * 50)
        print(f"Mount Path: {result['mount_path']}")
        print(f"Common Name: {result['common_name']}")
        print(f"Signed by: {result['signing_ca_path']}")
        print(f"Serial Number: {result['serial_number']}")
        
        if result['certificate']:
            print(f"\nIntermediate CA Certificate:")
            print(result['certificate'])
        
        print("\n✓ Intermediate CA is ready for use!")
        print(f"  You can now create certificate roles and issue certificates under '{result['mount_path']}'")


def set_default_issuer(client: hvac.Client, mount_path: str, issuer_id: str) -> Dict[str, Any]:
    """
    Set an issuer as the default for a PKI secrets engine.
    
    Args:
        client: Authenticated Vault client
        mount_path: Path where PKI engine is mounted
        issuer_id: ID of the issuer to set as default
        
    Returns:
        Dictionary containing the operation result
    """
    try:
        mount_path = mount_path.rstrip('/')
        validate_pki_engine(client, mount_path)
        
        # Verify the issuer exists
        try:
            issuer_detail = client.read(f"{mount_path}/issuer/{issuer_id}")
            if not issuer_detail or 'data' not in issuer_detail:
                raise ValueError(f"Issuer '{issuer_id}' not found in PKI engine '{mount_path}'")
        except Exception:
            raise ValueError(f"Issuer '{issuer_id}' not found in PKI engine '{mount_path}'")
        
        print(f"Setting issuer '{issuer_id}' as default for PKI engine '{mount_path}'...")
        
        # Set the default issuer
        config_data = {'default': issuer_id}
        client.write(f"{mount_path}/config/issuers", **config_data)
        
        # Get issuer details for confirmation
        issuer_cert = issuer_detail['data'].get('certificate', '')
        issuer_name = issuer_detail['data'].get('issuer_name', issuer_id)
        common_name = extract_common_name_from_certificate(issuer_cert) or issuer_name
        
        return {
            'success': True,
            'mount_path': mount_path,
            'issuer_id': issuer_id,
            'issuer_name': issuer_name,
            'common_name': common_name
        }
        
    except Exception as e:
        raise Exception(f"Failed to set default issuer: {str(e)}")


def list_issuers_for_selection(client: hvac.Client, mount_path: str) -> List[Dict[str, Any]]:
    """
    List all issuers in a PKI engine for user selection.
    
    Args:
        client: Authenticated Vault client
        mount_path: Path where PKI engine is mounted
        
    Returns:
        List of issuer information dictionaries
    """
    try:
        mount_path = mount_path.rstrip('/')
        
        # List all issuers
        issuers_response = client.list(f"{mount_path}/issuers")
        if not issuers_response or 'data' not in issuers_response:
            return []
        
        issuer_ids = issuers_response['data'].get('keys', [])
        issuers = []
        
        for issuer_id in issuer_ids:
            issuer_info = process_issuer_details(client, mount_path, issuer_id)
            if issuer_info:
                # Ensure we have the common_name for display
                if not issuer_info.get('common_name'):
                    issuer_info['common_name'] = issuer_info['name']
                issuers.append(issuer_info)
        
        return issuers
        
    except Exception as e:
        raise Exception(f"Failed to list issuers: {str(e)}")


def print_set_default_issuer_result(result: Dict[str, Any]) -> None:
    """
    Print the set default issuer results in a formatted way.
    
    Args:
        result: Set default issuer result dictionary
    """
    if result['success']:
        print("\n" + "=" * 50)
        print("DEFAULT ISSUER SET SUCCESSFULLY")
        print("=" * 50)
        print(f"PKI Engine: {result['mount_path']}")
        print(f"Default Issuer: {result['common_name']}")
        print(f"Issuer ID: {result['issuer_id']}")
        print("\n✓ Default issuer updated!")
        print(f"  New certificates will be issued by '{result['common_name']}' by default")


def rotate_root_ca(client: hvac.Client, mount_path: str, common_name: str,
                   country: Optional[str] = None, organization: Optional[str] = None,
                   ttl: str = "17520h", key_bits: int = 2048, key_type: str = "rsa") -> Dict[str, Any]:
    """
    Create a new root CA certificate alongside existing ones (dual root setup).
    This allows for gradual migration without breaking existing certificates.
    
    Args:
        client: Authenticated Vault client
        mount_path: Path where PKI engine is mounted (e.g., 'pki')
        common_name: Common name for the new root CA certificate
        country: Country code (e.g., 'US')
        organization: Organization name
        ttl: Time to live for the certificate (default: 17520h = 2 years)
        key_bits: Number of bits for the key (default: 2048)
        key_type: Type of key to generate (rsa, ec, ed25519)
        
    Returns:
        Dictionary containing the root CA rotation response
    """
    try:
        # Ensure the mount path doesn't have trailing slash
        mount_path = mount_path.rstrip('/')
        
        # Check if PKI engine is mounted at the specified path
        mounts = client.sys.list_mounted_secrets_engines()
        if f"{mount_path}/" not in mounts['data']:
            raise ValueError(f"No secrets engine mounted at '{mount_path}'. Please mount a PKI engine first.")
        
        if mounts['data'][f"{mount_path}/"].get('type') != 'pki':
            raise ValueError(f"Secrets engine at '{mount_path}' is not a PKI engine.")
        
        # Get current issuers to show what exists
        print(f"Checking existing issuers in PKI engine '{mount_path}'...")
        existing_issuers = list_issuers_for_selection(client, mount_path)
        
        if existing_issuers:
            print(f"Found {len(existing_issuers)} existing issuer(s):")
            for i, issuer in enumerate(existing_issuers, 1):
                print(f"  {i}. {issuer['common_name']} (ID: {issuer['id']})")
        else:
            print("No existing issuers found.")
        
        # Prepare the new root CA generation request
        ca_data = {
            'common_name': common_name,
            'ttl': ttl,
            'key_bits': key_bits,
            'key_type': key_type,
            'format': 'pem'
        }
        
        # Add optional fields if provided
        if country:
            ca_data['country'] = country
        if organization:
            ca_data['organization'] = organization
        
        # Generate the new root CA (this will add it alongside existing ones)
        print(f"\nCreating new root CA with common name: {common_name}")
        print(f"Mount path: {mount_path}")
        print(f"TTL: {ttl}")
        print(f"Key type: {key_type} ({key_bits} bits)")
        print("⚠️  This will create a NEW root CA alongside existing ones")
        print("✓ Existing certificates will remain valid")
        
        response = client.write(f"{mount_path}/root/generate/internal", **ca_data)
        
        if not response or 'data' not in response:
            raise Exception("Failed to generate new root CA - no data returned")
        
        new_issuer_id = response['data'].get('issuer_id')
        certificate = response['data'].get('certificate')
        serial_number = response['data'].get('serial_number')
        
        # Configure the CA URLs (optional but recommended)
        try:
            vault_addr = os.getenv('VAULT_ADDR', 'http://localhost:8200')
            urls_config = {
                'issuing_certificates': f"{vault_addr}/v1/{mount_path}/ca",
                'crl_distribution_points': f"{vault_addr}/v1/{mount_path}/crl"
            }
            client.write(f"{mount_path}/config/urls", **urls_config)
            print("✓ CA URLs configured")
        except Exception as e:
            print(f"Warning: Failed to configure CA URLs: {e}")
        
        # Set the new issuer as default if it's the only one or if user confirms
        should_set_default = False
        if not existing_issuers:
            should_set_default = True
            print("✓ Setting new root CA as default (no existing issuers)")
        else:
            try:
                choice = input(f"\nSet new root CA '{common_name}' as default? (y/N): ").lower().strip()
                should_set_default = choice in ['y', 'yes']
            except (KeyboardInterrupt, EOFError):
                print("\nSkipping default issuer setting.")
        
        if should_set_default and new_issuer_id:
            try:
                set_default_result = set_default_issuer(client, mount_path, new_issuer_id)
                if set_default_result['success']:
                    print(f"✓ New root CA set as default issuer")
            except Exception as e:
                print(f"Warning: Failed to set new root CA as default: {e}")
        
        return {
            'success': True,
            'certificate': certificate,
            'issuer_id': new_issuer_id,
            'serial_number': serial_number,
            'mount_path': mount_path,
            'common_name': common_name,
            'existing_issuers_count': len(existing_issuers),
            'is_default': should_set_default
        }
        
    except Exception as e:
        raise Exception(f"Failed to rotate root CA: {str(e)}")


def print_root_ca_rotation_result(result: Dict[str, Any]) -> None:
    """
    Print the root CA rotation results in a formatted way.
    
    Args:
        result: Root CA rotation result dictionary
    """
    if result['success']:
        print("\n" + "=" * 60)
        print("ROOT CA ROTATION COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print(f"Mount Path: {result['mount_path']}")
        print(f"New Root CA: {result['common_name']}")
        print(f"Serial Number: {result['serial_number']}")
        print(f"Issuer ID: {result['issuer_id']}")
        
        if result['existing_issuers_count'] > 0:
            print(f"Existing Issuers: {result['existing_issuers_count']} (still valid)")
            print("📋 DUAL ROOT SETUP ACTIVE")
            print("   • Old certificates remain valid under previous root(s)")
            print("   • New certificates can be issued under new root")
            print("   • Gradual migration is now possible")
        else:
            print("📋 FIRST ROOT CA CREATED")
        
        if result['is_default']:
            print(f"✓ New root CA is set as DEFAULT issuer")
        else:
            print(f"⚠️  New root CA is NOT set as default")
            print(f"   Use 'set-default-issuer' command to change default if needed")
        
        if result['certificate']:
            print(f"\nNew Root CA Certificate:")
            print(result['certificate'])
        
        print("\n🚀 NEXT STEPS:")
        print("1. Run 'scan' command to see the updated PKI hierarchy")
        print("2. Create new intermediate CAs using the new root CA")
        print("3. Gradually migrate applications to use new certificates")
        print("4. Eventually retire old root CA when all certificates have migrated")


def setup_scan_parser(subparsers):
    """Setup the scan command parser."""
    scan_parser = subparsers.add_parser('scan', help='Scan for PKI secrets engines')
    scan_parser.add_argument('--wide', action='store_true', help='Use wide timeline (100 characters instead of 50)')
    scan_parser.add_argument('--width', type=int, help='Custom timeline width in characters (overrides --wide)')


def setup_create_root_ca_parser(subparsers):
    """Setup the create-root-ca command parser."""
    create_ca_parser = subparsers.add_parser('create-root-ca', help='Create a new root CA')
    create_ca_parser.add_argument('--mount-path', required=True, help='PKI mount path (e.g., pki)')
    create_ca_parser.add_argument('--common-name', required=True, help='Common name for the root CA')
    create_ca_parser.add_argument('--country', help='Country code (e.g., US)')
    create_ca_parser.add_argument('--organization', help='Organization name')
    create_ca_parser.add_argument('--ttl', default='8760h', help='Certificate TTL (default: 8760h)')
    create_ca_parser.add_argument('--key-bits', type=int, default=2048, help='Key size in bits (default: 2048)')
    create_ca_parser.add_argument('--key-type', default='rsa', choices=['rsa', 'ec', 'ed25519'], help='Key type (default: rsa)')
    create_ca_parser.add_argument('--enable-engine', action='store_true', help='Enable PKI engine if not already mounted')


def setup_create_intermediate_ca_parser(subparsers):
    """Setup the create-intermediate-ca command parser."""
    create_intermediate_parser = subparsers.add_parser('create-intermediate-ca', help='Create a new intermediate CA (issuing certificate)')
    create_intermediate_parser.add_argument('--mount-path', required=True, help='PKI mount path for intermediate CA (e.g., pki-int)')
    create_intermediate_parser.add_argument('--common-name', required=True, help='Common name for the intermediate CA')
    create_intermediate_parser.add_argument('--signing-ca-path', required=True, help='PKI mount path of the root CA that will sign this intermediate')
    create_intermediate_parser.add_argument('--country', help='Country code (e.g., US)')
    create_intermediate_parser.add_argument('--organization', help='Organization name')
    create_intermediate_parser.add_argument('--ttl', default='8760h', help='Certificate TTL (default: 8760h)')
    create_intermediate_parser.add_argument('--key-bits', type=int, default=2048, help='Key size in bits (default: 2048)')
    create_intermediate_parser.add_argument('--key-type', default='rsa', choices=['rsa', 'ec', 'ed25519'], help='Key type (default: rsa)')
    create_intermediate_parser.add_argument('--enable-engine', action='store_true', help='Enable PKI engine if not already mounted')


def setup_set_default_issuer_parser(subparsers):
    """Setup the set-default-issuer command parser."""
    set_default_parser = subparsers.add_parser('set-default-issuer', help='Set an issuer as the default for a PKI engine')
    set_default_parser.add_argument('--mount-path', required=True, help='PKI mount path (e.g., pki)')
    set_default_parser.add_argument('--issuer-id', help='Issuer ID to set as default (if not provided, will list available issuers)')
    set_default_parser.add_argument('--list-only', action='store_true', help='Only list available issuers without setting default')


def setup_rotate_root_ca_parser(subparsers):
    """Setup the rotate-root-ca command parser."""
    rotate_ca_parser = subparsers.add_parser('rotate-root-ca', help='Create a new root CA alongside existing ones (dual root setup)')
    rotate_ca_parser.add_argument('--mount-path', required=True, help='PKI mount path (e.g., pki)')
    rotate_ca_parser.add_argument('--common-name', required=True, help='Common name for the new root CA')
    rotate_ca_parser.add_argument('--country', help='Country code (e.g., US)')
    rotate_ca_parser.add_argument('--organization', help='Organization name')
    rotate_ca_parser.add_argument('--ttl', default='17520h', help='Certificate TTL (default: 17520h = 2 years)')
    rotate_ca_parser.add_argument('--key-bits', type=int, default=2048, help='Key size in bits (default: 2048)')
    rotate_ca_parser.add_argument('--key-type', default='rsa', choices=['rsa', 'ec', 'ed25519'], help='Key type (default: rsa)')


def create_argument_parser():
    """Create and configure the main argument parser with all subcommands."""
    parser = argparse.ArgumentParser(description="Vault PKI Manager")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup all command parsers
    setup_scan_parser(subparsers)
    setup_create_root_ca_parser(subparsers)
    setup_create_intermediate_ca_parser(subparsers)
    setup_set_default_issuer_parser(subparsers)
    setup_rotate_root_ca_parser(subparsers)
    
    return parser


def build_ca_data(common_name: str, ttl: str, key_bits: int, key_type: str, 
                  country: Optional[str] = None, organization: Optional[str] = None) -> Dict[str, Any]:
    """
    Build CA data dictionary for certificate generation.
    
    Args:
        common_name: Common name for the certificate
        ttl: Time to live for the certificate
        key_bits: Number of bits for the key
        key_type: Type of key to generate
        country: Country code (optional)
        organization: Organization name (optional)
        
    Returns:
        Dictionary with CA generation parameters
    """
    ca_data = {
        'common_name': common_name,
        'ttl': ttl,
        'key_bits': key_bits,
        'key_type': key_type,
        'format': 'pem'
    }
    
    # Add optional fields if provided
    if country:
        ca_data['country'] = country
    if organization:
        ca_data['organization'] = organization
    
    return ca_data


def calculate_expiry_status(cert_expiry: datetime) -> str:
    """
    Calculate the expiry status for a certificate.
    
    Args:
        cert_expiry: Certificate expiry datetime
        
    Returns:
        Status string with expiry information
    """
    # Ensure timezone-aware comparison
    cert_expiry = ensure_timezone_aware(cert_expiry)
    now = datetime.datetime.now(datetime.timezone.utc)
    
    days_until_expiry = (cert_expiry - now).days
    
    if days_until_expiry < 0:
        return f"⚠️  EXPIRED {abs(days_until_expiry)} days ago"
    elif days_until_expiry < 30:
        return f"⚠️  Expires in {days_until_expiry} days"
    elif days_until_expiry < 90:
        return f"⚡ Expires in {days_until_expiry} days"
    else:
        return f"✓ Valid ({days_until_expiry} days remaining)"


def handle_scan_command(client: hvac.Client, args) -> int:
    """
    Handle the scan command execution.
    
    Args:
        client: Authenticated Vault client
        args: Parsed command line arguments
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Determine timeline width
        timeline_width = 50  # default
        if args.width:
            timeline_width = args.width
        elif args.wide:
            timeline_width = 100
        
        # Scan for PKI secrets engines
        print("\nScanning for PKI secrets engines...")
        pki_engines = scan_pki_secrets_engines(client)
        print_pki_scan_results(pki_engines, timeline_width)
        return 0
    except Exception as e:
        print(f"Error during scan: {e}")
        return 1


def handle_create_root_ca_command(client: hvac.Client, args) -> int:
    """
    Handle the create-root-ca command execution.
    
    Args:
        client: Authenticated Vault client
        args: Parsed command line arguments
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Enable PKI engine if requested
        if args.enable_engine:
            print(f"\nEnabling PKI secrets engine at '{args.mount_path}'...")
            enable_pki_engine(client, args.mount_path)
        
        # Create root CA
        print(f"\nCreating root CA at '{args.mount_path}'...")
        result = create_root_ca(
            client=client,
            mount_path=args.mount_path,
            common_name=args.common_name,
            country=args.country,
            organization=args.organization,
            ttl=args.ttl,
            key_bits=args.key_bits,
            key_type=args.key_type
        )
        print_root_ca_result(result)
        return 0
    except Exception as e:
        print(f"Error creating root CA: {e}")
        return 1


def handle_create_intermediate_ca_command(client: hvac.Client, args) -> int:
    """
    Handle the create-intermediate-ca command execution.
    
    Args:
        client: Authenticated Vault client
        args: Parsed command line arguments
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Enable PKI engine if requested
        if args.enable_engine:
            print(f"\nEnabling PKI secrets engine at '{args.mount_path}'...")
            enable_pki_engine(client, args.mount_path)
        
        # Create intermediate CA
        print(f"\nCreating intermediate CA at '{args.mount_path}'...")
        result = create_intermediate_ca(
            client=client,
            mount_path=args.mount_path,
            common_name=args.common_name,
            signing_ca_path=args.signing_ca_path,
            country=args.country,
            organization=args.organization,
            ttl=args.ttl,
            key_bits=args.key_bits,
            key_type=args.key_type
        )
        print_intermediate_ca_result(result)
        return 0
    except Exception as e:
        print(f"Error creating intermediate CA: {e}")
        return 1


def handle_set_default_issuer_command(client: hvac.Client, args) -> int:
    """
    Handle the set-default-issuer command execution.
    
    Args:
        client: Authenticated Vault client
        args: Parsed command line arguments
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # List available issuers
        print(f"\nListing issuers in PKI engine '{args.mount_path}'...")
        issuers = list_issuers_for_selection(client, args.mount_path)
        
        if not issuers:
            print("No issuers found in this PKI engine.")
            return 1
        
        print(f"\nFound {len(issuers)} issuer(s):")
        print("=" * 40)
        for i, issuer in enumerate(issuers, 1):
            print(f"{i}. {issuer['common_name']}")
            print(f"   ID: {issuer['id']}")
            if issuer.get('not_before') and issuer.get('not_after'):
                start_date = format_datetime(issuer['not_before'])
                end_date = format_datetime(issuer['not_after'])
                print(f"   Valid: {start_date} to {end_date}")
            else:
                print(f"   Valid: Unknown")
        
        # If list-only flag is set, just show the list
        if args.list_only:
            return 0
        
        # If issuer-id is provided, use it; otherwise prompt for selection
        if args.issuer_id:
            # Verify the provided issuer ID exists
            issuer_found = None
            for issuer in issuers:
                if issuer['id'] == args.issuer_id:
                    issuer_found = issuer
                    break
            
            if not issuer_found:
                print(f"\nError: Issuer ID '{args.issuer_id}' not found.")
                print("Use --list-only to see available issuer IDs.")
                return 1
            
            selected_issuer_id = args.issuer_id
        else:
            # Interactive selection
            try:
                choice = input(f"\nSelect issuer to set as default (1-{len(issuers)}): ")
                choice_num = int(choice)
                if 1 <= choice_num <= len(issuers):
                    selected_issuer_id = issuers[choice_num - 1]['id']
                else:
                    print("Invalid selection.")
                    return 1
            except (ValueError, KeyboardInterrupt):
                print("\nOperation cancelled.")
                return 1
        
        # Set the default issuer
        result = set_default_issuer(client, args.mount_path, selected_issuer_id)
        print_set_default_issuer_result(result)
        return 0
    except Exception as e:
        print(f"Error setting default issuer: {e}")
        return 1


def handle_rotate_root_ca_command(client: hvac.Client, args) -> int:
    """
    Handle the rotate-root-ca command execution.
    
    Args:
        client: Authenticated Vault client
        args: Parsed command line arguments
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Rotate root CA (create new root alongside existing ones)
        print(f"\nRotating root CA at '{args.mount_path}'...")
        print("This will create a NEW root CA alongside existing certificates.")
        print("Existing certificates will remain valid during transition.\n")
        
        try:
            confirmation = input("Continue with root CA rotation? (y/N): ").lower().strip()
            if confirmation not in ['y', 'yes']:
                print("Root CA rotation cancelled.")
                return 0
        except (KeyboardInterrupt, EOFError):
            print("\nRoot CA rotation cancelled.")
            return 0
        
        result = rotate_root_ca(
            client=client,
            mount_path=args.mount_path,
            common_name=args.common_name,
            country=args.country,
            organization=args.organization,
            ttl=args.ttl,
            key_bits=args.key_bits,
            key_type=args.key_type
        )
        print_root_ca_rotation_result(result)
        return 0
    except Exception as e:
        print(f"Error rotating root CA: {e}")
        return 1


def main():
    parser = create_argument_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    print("Vault PKI Manager")
    print("=" * 20)
    
    # Command mapping dictionary
    command_handlers = {
        'scan': handle_scan_command,
        'create-root-ca': handle_create_root_ca_command,
        'create-intermediate-ca': handle_create_intermediate_ca_command,
        'set-default-issuer': handle_set_default_issuer_command,
        'rotate-root-ca': handle_rotate_root_ca_command
    }
    
    try:
        # Get Vault client
        client = get_vault_client()
        print("✓ Successfully connected to Vault")
        
        # Execute the appropriate command handler
        handler = command_handlers.get(args.command)
        if handler:
            return handler(client, args)
        else:
            print(f"Unknown command: {args.command}")
            parser.print_help()
            return 1
        
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
