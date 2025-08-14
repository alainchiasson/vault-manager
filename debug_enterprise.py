#!/usr/bin/env python3
"""
Test script to debug Vault E        # Try other methods
        print("\n=== Testing Alternative Methods ===")
        
        is_enterprise_license = False
        is_enterprise_namespaces = False  
        is_enterprise_capabilities = False
        
        # Try sys/license endpoint (Enterprise only)
        try:
            license_response = client.read('sys/license')
            print(f"✅ License endpoint accessible (Enterprise feature)")
            print(f"License response keys: {list(license_response.get('data', {}).keys()) if license_response else 'None'}")
            is_enterprise_license = True
        except Exception as e:
            print(f"❌ License endpoint not accessible: {e}")
            is_enterprise_license = Falsetection.
"""

import hvac
import os
import sys

def test_enterprise_detection():
    """Test how we detect if Vault is Enterprise edition."""
    
    # Get Vault connection details
    vault_addr = os.getenv('VAULT_ADDR', 'https://vault.example.com:8200')
    vault_token = os.getenv('VAULT_TOKEN')
    
    if not vault_token:
        print("❌ VAULT_TOKEN environment variable not set")
        return
        
    try:
        # Create client
        client = hvac.Client(url=vault_addr, token=vault_token)
        
        print(f"🔗 Connecting to: {vault_addr}")
        print(f"🎫 Using token: {vault_token[:8]}...")
        
        # Test 1: Check health status
        print("\n=== Testing Health Status ===")
        is_enterprise_current = False  # Initialize variable
        try:
            sys_health = client.sys.read_health_status()
            print(f"Health response type: {type(sys_health)}")
            print(f"Health response status: {sys_health.status_code}")
            print(f"Health response text: '{sys_health.text}'")
            print(f"Health response headers: {dict(sys_health.headers)}")
            
            # If it's a Response object, check if it has JSON content
            if hasattr(sys_health, 'json') and sys_health.text.strip():
                try:
                    health_data = sys_health.json()
                    print(f"Health JSON data: {health_data}")
                    version_info = health_data.get('version', 'Not found')
                except Exception as json_error:
                    print(f"JSON parse error: {json_error}")
                    version_info = 'JSON parse failed'
            else:
                print("Empty response or no JSON content")
                version_info = 'No content'
                
            print(f"Version from health: '{version_info}'")
            
            # Current detection logic
            is_enterprise_current = '+ent' in str(version_info) or 'enterprise' in str(version_info).lower()
            print(f"Current detection result: {is_enterprise_current}")
            
        except Exception as e:
            print(f"❌ Health status error: {e}")
            print(f"Error type: {type(e)}")
            
        # Try alternative health check method
        print("\n=== Testing Alternative Health Check ===")
        try:
            # Try using the standard vault health endpoint directly
            health_response = client.read('sys/health')
            print(f"Direct health read: {health_response}")
            if health_response and 'data' in health_response:
                version_alt = health_response['data'].get('version', 'Not found')
                print(f"Version from direct read: '{version_alt}'")
        except Exception as e:
            print(f"❌ Direct health read error: {e}")
            
        # Try checking server status
        print("\n=== Testing Server Info ===")
        try:
            # Check if we can just check the server version some other way
            response = client.read('sys/version-history')
            print(f"Version history: {response}")
        except Exception as e:
            print(f"❌ Version history error: {e}")
        
        # Test 2: Try other methods
        print("\n=== Testing Alternative Methods ===")
        
        # Try sys/license endpoint (Enterprise only)
        try:
            license_response = client.read('sys/license')
            print(f"✅ License endpoint accessible (Enterprise feature)")
            print(f"License response keys: {list(license_response.get('data', {}).keys()) if license_response else 'None'}")
            is_enterprise_license = True
        except Exception as e:
            print(f"❌ License endpoint not accessible: {e}")
            is_enterprise_license = False
        
        # Try sys/namespaces endpoint (Enterprise only) 
        try:
            namespaces_response = client.sys.list_namespaces()
            print(f"✅ Namespaces endpoint accessible (Enterprise feature)")
            is_enterprise_namespaces = True
        except Exception as e:
            print(f"❌ Namespaces endpoint not accessible: {e}")
            is_enterprise_namespaces = False
            
        # Try checking capabilities
        try:
            capabilities = client.sys.get_capabilities('sys/namespaces')
            print(f"Capabilities for sys/namespaces: {capabilities}")
            is_enterprise_capabilities = 'read' in capabilities.get('capabilities', [])
        except Exception as e:
            print(f"❌ Capabilities check error: {e}")
            is_enterprise_capabilities = False
        
        print("\n=== Final Detection Results ===")
        print(f"Health version detection: {is_enterprise_current}")
        print(f"License endpoint detection: {is_enterprise_license}")
        print(f"Namespaces endpoint detection: {is_enterprise_namespaces}")
        print(f"Capabilities detection: {is_enterprise_capabilities}")
        
        # Recommend best method
        if is_enterprise_license or is_enterprise_namespaces:
            print("\n✅ Vault Enterprise detected via endpoints")
        elif is_enterprise_current:
            print("\n✅ Vault Enterprise detected via version string")
        else:
            print("\n❌ Vault Open Source detected")
            
    except Exception as e:
        print(f"❌ Connection error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_enterprise_detection()
