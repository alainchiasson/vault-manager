#!/usr/bin/env python3

import hvac
import os
from typing import Dict, Any, Optional

# Import helper functions from ca_helpers
from ca_helpers import configure_ca_urls


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
        configure_ca_urls(client, mount_path)
        
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
