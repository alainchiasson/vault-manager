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
