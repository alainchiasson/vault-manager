import hvac
import os
import argparse
from typing import List, Dict, Any, Optional


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
                        pki_info['ca_certificate'] = ca_cert_response['data'].get('certificate', '')
                except Exception:
                    # CA cert might not be configured yet
                    pki_info['ca_certificate'] = None
                
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
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
