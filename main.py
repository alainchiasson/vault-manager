#!/usr/bin/env python3
"""
Vault PKI Manager - A comprehensive tool for managing HashiCorp Vault PKI secrets engines.

SSL/TLS Configuration:
=====================
The tool supports various SSL/TLS configuration options for secure connections to Vault:

Environment Variables:
- VAULT_ADDR: Vault server address (required)
- VAULT_TOKEN: Vault authentication token (required)
- VAULT_SKIP_VERIFY: Skip SSL certificate verification (true/false, default: false)
- VAULT_CACERT: Path to CA certificate file for SSL verification
- VAULT_CAPATH: Path to directory containing CA certificates

Command Line Options (override environment variables):
- --skip-verify: Skip SSL certificate verification
- --ca-cert: Path to CA certificate file
- --ca-path: Path to CA certificate directory

Examples:
--------
# Use default system CA bundle
export VAULT_ADDR="https://vault.example.com:8200"
python main.py scan

# Skip SSL verification (not recommended for production)
python main.py scan --skip-verify

# Use custom CA certificate
export VAULT_CACERT="/path/to/ca.crt"
python main.py scan

# Use custom CA certificate via command line
python main.py scan --ca-cert /path/to/ca.crt
"""

import hvac
import os
from typing import List, Dict, Any, Optional
import datetime

# Import common CA helper functions
from ca_helpers import (
    validate_pki_engine,
    extract_common_name_from_certificate,
    process_issuer_details,
    set_default_issuer
)

from cli_handlers import create_argument_parser, get_command_handlers


def get_vault_client(skip_verify: bool = None, ca_cert: str = None, ca_path: str = None) -> hvac.Client:
    """
    Create and return a configured Vault client.
    
    Args:
        skip_verify: Override SSL verification skip (command line argument)
        ca_cert: Override CA certificate file path (command line argument)
        ca_path: Override CA certificate directory path (command line argument)
    
    Environment variables expected:
    - VAULT_ADDR: Vault server address
    - VAULT_TOKEN: Vault authentication token
    - VAULT_SKIP_VERIFY: Skip SSL certificate verification (optional, default: False)
    - VAULT_CACERT: Path to CA certificate file for SSL verification (optional)
    - VAULT_CAPATH: Path to directory containing CA certificates (optional)
    """
    vault_addr = os.getenv('VAULT_ADDR')
    vault_token = os.getenv('VAULT_TOKEN')
    vault_skip_verify = os.getenv('VAULT_SKIP_VERIFY', '').lower() in ('true', '1', 'yes')
    vault_cacert = os.getenv('VAULT_CACERT')
    vault_capath = os.getenv('VAULT_CAPATH')
    
    # Command line arguments override environment variables
    if skip_verify is not None:
        vault_skip_verify = skip_verify
    if ca_cert is not None:
        vault_cacert = ca_cert
    if ca_path is not None:
        vault_capath = ca_path
    
    if not vault_addr:
        raise ValueError("VAULT_ADDR environment variable is required")
    if not vault_token:
        raise ValueError("VAULT_TOKEN environment variable is required")
    
    # Configure SSL verification
    verify = None
    if vault_skip_verify:
        verify = False
        print("⚠️ SSL certificate verification disabled")
    elif vault_cacert:
        verify = vault_cacert
        print(f"📋 Using CA certificate file: {vault_cacert}")
    elif vault_capath:
        verify = vault_capath
        print(f"📁 Using CA certificate directory: {vault_capath}")
    else:
        verify = True  # Use system's default CA bundle
        if vault_addr.startswith('https://'):
            print("🔒 SSL certificate verification enabled")
    
    client = hvac.Client(url=vault_addr, token=vault_token, verify=verify)
    
    if not client.is_authenticated():
        raise ValueError("Failed to authenticate with Vault")
    
    return client


def main():
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
        # Get Vault client with SSL configuration
        client = get_vault_client(
            skip_verify=args.skip_verify,
            ca_cert=args.ca_cert,
            ca_path=args.ca_path
        )
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
