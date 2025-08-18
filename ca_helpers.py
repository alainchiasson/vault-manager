#!/usr/bin/env python3

import hvac
import os
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime


def parse_certificate_dates(cert_pem: str) -> Dict[str, Optional[datetime.datetime]]:
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


def extract_certificate_hierarchy_info(cert_pem: str) -> Dict[str, Optional[str]]:
    """
    Extract hierarchy information from a certificate PEM.
    
    Args:
        cert_pem: Certificate in PEM format
        
    Returns:
        Dictionary with subject CN, issuer CN, and basic CA information
    """
    try:
        if not cert_pem or not cert_pem.strip():
            return {'subject_cn': None, 'issuer_cn': None, 'is_ca': False, 'is_self_signed': False}
        
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        
        # Extract subject common name
        subject_cn = None
        for attribute in cert.subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                subject_cn = attribute.value
                break
        
        # Extract issuer common name
        issuer_cn = None
        for attribute in cert.issuer:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                issuer_cn = attribute.value
                break
        
        # Check if it's a CA certificate
        is_ca = False
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            # If no basic constraints, it's likely not a CA
            is_ca = False
        
        # Check if self-signed (subject == issuer)
        is_self_signed = cert.subject == cert.issuer
        
        return {
            'subject_cn': subject_cn,
            'issuer_cn': issuer_cn,
            'is_ca': is_ca,
            'is_self_signed': is_self_signed
        }
    except Exception:
        return {'subject_cn': None, 'issuer_cn': None, 'is_ca': False, 'is_self_signed': False}


def ensure_timezone_aware(dt: datetime.datetime) -> datetime.datetime:
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
        hierarchy_info = extract_certificate_hierarchy_info(issuer_cert)
        
        return {
            'id': issuer_id,
            'name': issuer_name,
            'certificate': issuer_cert,
            'not_before': cert_dates['not_before'],
            'not_after': cert_dates['not_after'],
            'common_name': common_name,
            'subject_cn': hierarchy_info['subject_cn'],
            'issuer_cn': hierarchy_info['issuer_cn'],
            'is_ca': hierarchy_info['is_ca'],
            'is_self_signed': hierarchy_info['is_self_signed']
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
            hierarchy_info = extract_certificate_hierarchy_info(cert_pem)
            return {
                'ca_certificate': cert_pem,
                'cert_not_before': cert_dates['not_before'],
                'cert_not_after': cert_dates['not_after'],
                'ca_subject_cn': hierarchy_info['subject_cn'],
                'ca_issuer_cn': hierarchy_info['issuer_cn'],
                'ca_is_self_signed': hierarchy_info['is_self_signed']
            }
    except Exception:
        pass
    
    return {
        'ca_certificate': None,
        'cert_not_before': None,
        'cert_not_after': None,
        'ca_subject_cn': None,
        'ca_issuer_cn': None,
        'ca_is_self_signed': False
    }


def list_issuers_for_selection(client: hvac.Client, mount_path: str) -> list:
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
