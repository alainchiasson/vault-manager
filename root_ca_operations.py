#!/usr/bin/env python3

import hvac
import os
from typing import Dict, Any, Optional

# Import helper functions from main
from main import (
    list_issuers_for_selection
)

# Import common CA helper functions
from ca_helpers import (
    validate_pki_engine,
    configure_ca_urls,
    enable_pki_engine,
    set_default_issuer
)


def build_ca_data(common_name: str, ttl: str, key_bits: int, key_type: str,
                  country: Optional[str] = None, organization: Optional[str] = None) -> Dict[str, Any]:
    """
    Build CA data dictionary for root CA creation.
    
    Args:
        common_name: Common name for the CA
        ttl: Time to live for the certificate
        key_bits: Number of bits for the key
        key_type: Type of key to generate
        country: Country code (optional)
        organization: Organization name (optional)
        
    Returns:
        Dictionary with CA data for Vault API
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
        ca_data = build_ca_data(common_name, ttl, key_bits, key_type, country, organization)
        
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
