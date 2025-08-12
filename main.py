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
            'not_before': cert.not_valid_before,
            'not_after': cert.not_valid_after
        }
    except Exception:
        # If we can't parse the certificate, return None values
        return {'not_before': None, 'not_after': None}


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
            if mount_info.get('type') == 'pki':
                pki_info = {
                    'path': mount_path.rstrip('/'),
                    'type': mount_info.get('type'),
                    'description': mount_info.get('description', ''),
                    'config': mount_info.get('config', {}),
                    'options': mount_info.get('options', {}),
                    'accessor': mount_info.get('accessor', ''),
                }
                
                # Try to get additional PKI-specific information
                try:
                    # Get CA certificate info if available
                    ca_cert_response = client.read(f"{pki_info['path']}/cert/ca")
                    if ca_cert_response and 'data' in ca_cert_response:
                        cert_pem = ca_cert_response['data'].get('certificate', '')
                        pki_info['ca_certificate'] = cert_pem
                        
                        # Parse certificate dates
                        cert_dates = parse_certificate_dates(cert_pem)
                        pki_info['cert_not_before'] = cert_dates['not_before']
                        pki_info['cert_not_after'] = cert_dates['not_after']
                    else:
                        pki_info['ca_certificate'] = None
                        pki_info['cert_not_before'] = None
                        pki_info['cert_not_after'] = None
                except Exception:
                    # CA cert might not be configured yet
                    pki_info['ca_certificate'] = None
                    pki_info['cert_not_before'] = None
                    pki_info['cert_not_after'] = None
                
                try:
                    # Get PKI configuration
                    config_response = client.read(f"{pki_info['path']}/config/ca")
                    if config_response and 'data' in config_response:
                        pki_info['ca_config'] = config_response['data']
                except Exception:
                    pki_info['ca_config'] = None
                
                try:
                    # List certificate roles
                    roles_response = client.list(f"{pki_info['path']}/roles")
                    if roles_response and 'data' in roles_response:
                        pki_info['roles'] = roles_response['data'].get('keys', [])
                    else:
                        pki_info['roles'] = []
                except Exception:
                    pki_info['roles'] = []
                
                pki_engines.append(pki_info)
        
        return pki_engines
        
    except Exception as e:
        raise Exception(f"Failed to scan for PKI secrets engines: {str(e)}")


def print_pki_scan_results(pki_engines: List[Dict[str, Any]]) -> None:
    """
    Print the PKI scan results in a formatted way.
    
    Args:
        pki_engines: List of PKI engine information dictionaries
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
        
        if engine['ca_config']:
            print("   CA Configuration:")
            for key, value in engine['ca_config'].items():
                if key != 'private_key':  # Don't print sensitive data
                    print(f"     {key}: {value}")


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
        # Ensure the mount path doesn't have trailing slash
        mount_path = mount_path.rstrip('/')
        
        # Check if PKI engine is mounted at the specified path
        mounts = client.sys.list_mounted_secrets_engines()
        if f"{mount_path}/" not in mounts['data']:
            raise ValueError(f"No secrets engine mounted at '{mount_path}'. Please mount a PKI engine first.")
        
        if mounts['data'][f"{mount_path}/"].get('type') != 'pki':
            raise ValueError(f"Secrets engine at '{mount_path}' is not a PKI engine.")
        
        # Prepare the root CA generation request
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
        
        # Generate the root CA
        print(f"Creating root CA with common name: {common_name}")
        print(f"Mount path: {mount_path}")
        print(f"TTL: {ttl}")
        print(f"Key type: {key_type} ({key_bits} bits)")
        
        response = client.write(f"{mount_path}/root/generate/internal", **ca_data)
        
        if not response or 'data' not in response:
            raise Exception("Failed to generate root CA - no data returned")
        
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


def main():
    parser = argparse.ArgumentParser(description="Vault PKI Manager")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan for PKI secrets engines')
    
    # Create root CA command
    create_ca_parser = subparsers.add_parser('create-root-ca', help='Create a new root CA')
    create_ca_parser.add_argument('--mount-path', required=True, help='PKI mount path (e.g., pki)')
    create_ca_parser.add_argument('--common-name', required=True, help='Common name for the root CA')
    create_ca_parser.add_argument('--country', help='Country code (e.g., US)')
    create_ca_parser.add_argument('--organization', help='Organization name')
    create_ca_parser.add_argument('--ttl', default='8760h', help='Certificate TTL (default: 8760h)')
    create_ca_parser.add_argument('--key-bits', type=int, default=2048, help='Key size in bits (default: 2048)')
    create_ca_parser.add_argument('--key-type', default='rsa', choices=['rsa', 'ec', 'ed25519'], help='Key type (default: rsa)')
    create_ca_parser.add_argument('--enable-engine', action='store_true', help='Enable PKI engine if not already mounted')
    
    # Create intermediate CA command
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
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    print("Vault PKI Manager")
    print("=" * 20)
    
    try:
        # Get Vault client
        client = get_vault_client()
        print("✓ Successfully connected to Vault")
        
        if args.command == 'scan':
            # Scan for PKI secrets engines
            print("\nScanning for PKI secrets engines...")
            pki_engines = scan_pki_secrets_engines(client)
            print_pki_scan_results(pki_engines)
            
        elif args.command == 'create-root-ca':
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
            
        elif args.command == 'create-intermediate-ca':
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
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
