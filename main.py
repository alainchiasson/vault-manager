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
