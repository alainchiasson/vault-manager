import argparse
import hvac
import datetime
from typing import Dict, Any

# Import the core functions from main
# (none currently needed)

# Import root CA operations from root_ca_operations module
from root_ca_operations import (
    create_root_ca,
    print_root_ca_result,
    rotate_root_ca,
    print_root_ca_rotation_result
)

# Import intermediate CA operations from intermediate_ca_operations module
from intermediate_ca_operations import (
    create_intermediate_ca,
    print_intermediate_ca_result
)

# Import common CA helper functions
from ca_helpers import (
    enable_pki_engine, 
    set_default_issuer,
    list_issuers_for_selection,
    print_set_default_issuer_result
)

# Import scan functions from scan_functions module
from scan_functions import scan_pki_secrets_engines, print_pki_scan_results

# Import utility functions
from utils import format_datetime


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
        scan_data = scan_pki_secrets_engines(client)
        scan_results = print_pki_scan_results(scan_data, timeline_width)
        print(scan_results)
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


def get_command_handlers() -> Dict[str, Any]:
    """
    Get the command mapping dictionary.
    
    Returns:
        Dictionary mapping command names to their handler functions
    """
    return {
        'scan': handle_scan_command,
        'create-root-ca': handle_create_root_ca_command,
        'create-intermediate-ca': handle_create_intermediate_ca_command,
        'set-default-issuer': handle_set_default_issuer_command,
        'rotate-root-ca': handle_rotate_root_ca_command
    }
