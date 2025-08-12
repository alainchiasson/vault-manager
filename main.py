import hvac
import os
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


def main():
    from cli_handlers import create_argument_parser, get_command_handlers
    
    parser = create_argument_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    print("Vault PKI Manager")
    print("=" * 20)
    
    # Get command handlers from the CLI module
    command_handlers = get_command_handlers()
    
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
