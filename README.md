# Vault PKI Manager

A comprehensive command-line tool for managing HashiCorp Vault PKI (Public Key Infrastructure) secrets engines. This tool provides functionality to scan, visualize, create, and manage PKI certificates and certificate authorities.

## Features

- **PKI Scanning**: Discover and analyze PKI secrets engines across Vault namespaces
- **Certificate Timeline Visualization**: Visual representation of certificate validity periods
- **Root CA Management**: Create and rotate root certificate authorities
- **Intermediate CA Management**: Create intermediate certificate authorities
- **Default Issuer Management**: Set and manage default issuers for PKI engines
- **Enterprise Support**: Full support for Vault Enterprise features including namespaces
- **HTTPS/SSL Support**: Secure connections to Vault with SSL certificate verification
- **HTML Reports**: Generate comprehensive web-viewable reports

## Requirements

- Python 3.13+
- HashiCorp Vault (tested with 1.15.0+)
- Required Python packages (automatically installed with uv):
  - hvac >= 2.3.0
  - cryptography >= 41.0.0

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd vault-manager

# Install dependencies using uv
uv sync

# Or install manually with pip
pip install hvac cryptography
```

## Configuration

### Environment Variables

Set the following environment variables to configure Vault connection:

```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="your-vault-token"
export VAULT_NAMESPACE="your-namespace"  # For Vault Enterprise

# SSL Configuration (optional)
export VAULT_CACERT="/path/to/ca.pem"
export VAULT_CLIENT_CERT="/path/to/client.pem" 
export VAULT_CLIENT_KEY="/path/to/client-key.pem"
export VAULT_SKIP_VERIFY="false"  # Set to "true" to skip SSL verification (not recommended)
```

### Command Line SSL Options

You can also configure SSL settings via command line arguments:

```bash
# Use specific CA certificate
python main.py scan --ca-cert /path/to/ca.pem

# Skip SSL verification (not recommended for production)
python main.py scan --skip-verify

# Use client certificate authentication
python main.py scan --client-cert /path/to/client.pem --client-key /path/to/client-key.pem
```

## Usage

### Scanning PKI Engines

#### Basic Scan
```bash
# Scan PKI engines in current namespace
python main.py scan

# Scan with wide timeline visualization
python main.py scan --wide

# Scan with custom timeline width
python main.py scan --width 80
```

#### Enterprise Features
```bash
# Scan specific namespace (Vault Enterprise)
python main.py scan --namespace dev

# Scan all namespaces (Vault Enterprise)
python main.py scan --all-namespaces
```

#### HTML Report Generation
```bash
# Generate both text output and HTML report
python main.py scan --html-output report.html

# Generate only HTML report (suppress text output)
python main.py scan --html-output report.html --html-only

# Generate HTML report with custom timeline width
python main.py scan --html-output report.html --width 100
```

**Interactive HTML Features:**
- **Collapsible PKI Engines**: Click on engine headers to expand/collapse details
- **Interactive Timeline**: Filter certificates by status (valid, expiring, expired) or type (root CA, intermediate)
- **Certificate Tooltips**: Hover over certificate names for detailed information
- **Global Controls**: Expand/collapse all engines with dedicated buttons
- **Responsive Design**: Optimized for both desktop and mobile viewing

### Root CA Management

#### Create Root CA
```bash
# Create a new root CA
python main.py create-root-ca

# Create root CA with specific parameters
python main.py create-root-ca
# Follow the interactive prompts for:
# - PKI engine path
# - Common name
# - Country, organization, etc.
# - Key type and size
# - Validity period
```

#### Rotate Root CA
```bash
# Rotate an existing root CA
python main.py rotate-root-ca

# Choose from rotation options:
# 1. Create new root CA in same engine (replace current)
# 2. Create new root CA in new engine (parallel setup)
# 3. Create new root + intermediate setup (recommended)
```

### Intermediate CA Management

```bash
# Create an intermediate CA
python main.py create-intermediate-ca

# Follow prompts for:
# - PKI engine path (will be created if doesn't exist)
# - Parent CA selection
# - Certificate parameters
# - CSR signing options
```

### Default Issuer Management

```bash
# Set a default issuer for a PKI engine
python main.py set-default-issuer

# Select from available PKI engines and issuers
```

## Output Examples

### Text Output
```
VAULT INFORMATION
==================
Version: 1.15.0+ent
Edition: ✓ Vault Enterprise
Namespace: root

Found 2 PKI secrets engine(s):
==================================================

1. PKI Engine: pki
   Description: Root PKI for production
   Accessor: pki_abc123
   ✓ CA Certificate configured
   Valid from: 2024-01-01 00:00:00 UTC
   Valid until: 2025-01-01 00:00:00 UTC
   ✓ Valid (365 days remaining)
   Roles: server, client
   Issuers: 1 certificate(s)
     1. Production Root CA
        ID: issuer-123
        Valid: 2024-01-01 00:00:00 UTC to 2025-01-01 00:00:00 UTC
        ✓ Valid

CERTIFICATE VALIDITY TIMELINE
==============================
Timeline: 2023-12-17 00:00:00 UTC to 2025-01-14 00:00:00 UTC

Certificate Name                           Timeline                                          Status
------------------------------------------ -------------------------------------------------- ---------------
📜 pki (Main CA)                           ├████████████████████████████████████████████████┤ ✓ 365d left

Legend:
  📜       Root CA certificate
  ↳        Intermediate CA (signed by parent)
  │        Hierarchy connection
  ├████████┤  Certificate validity period
  ●        Current time (within validity)
  │        Current time (outside validity)
  ✓        Valid (>90 days remaining)
  ⚡       Expires soon (30-90 days)
  ⚠️        Critical (< 30 days)
```

### HTML Output

The HTML output provides a professional, web-viewable report with interactive features:

- **Responsive Design**: Works on desktop and mobile devices
- **Collapsible Sections**: Click PKI engine headers to expand/collapse details
- **Interactive Chart Timeline**: Professional HTML5 canvas chart with advanced filtering and tooltips
- **Smart Tooltips**: Hover over certificate bars for comprehensive details
- **Color-Coded Status**: Visual indicators for certificate health with gradient effects
- **Namespace Support**: Clear namespace identification for Enterprise
- **Chart Visualization**: Interactive graphical timeline showing certificate lifecycles with precision
- **Professional Formatting**: Clean, modern design suitable for stakeholder reports

**Interactive Chart Features:**
- **HTML5 Canvas Timeline**: High-quality chart visualization with smooth gradients and precise rendering
- **Advanced Status Coding**: 
  - 🟢 Valid (>90 days) - Green gradient
  - 🟡 Warning (30-90 days) - Orange gradient
  - 🔴 Critical (<30 days) - Red gradient
  - ⚫ Expired - Gray gradient
  - 🔵 Future certificates - Blue gradient
- **Smart Filtering**: Filter by status (All, Valid, Warning, Critical, Expired) or type (Root CAs, Intermediates)
- **Rich Tooltips**: Detailed certificate information with validity periods, engine paths, and status
- **Timeline Axis**: Dynamic time scale with month/year markers and current time indicator
- **Certificate Hierarchy**: Visual distinction between Root CAs (📜), Intermediates (🔗), and Issuers (📄)

**Interactive Controls:**
- **Engine Cards**: Collapsible sections with visual expand/collapse indicators
- **Chart Filters**: Real-time filtering with visual feedback and active state indicators
- **Global Actions**: Expand All / Collapse All buttons for quick navigation
- **Hover Interactions**: Rich tooltips with comprehensive certificate details on chart hover

## SSL/TLS Security

The tool supports comprehensive SSL/TLS configuration for secure Vault connections:

### Certificate Verification
- **CA Certificate**: Verify Vault's SSL certificate against a specific CA
- **Client Certificates**: Use client certificate authentication
- **Skip Verification**: Disable SSL verification (not recommended for production)

### Priority Order
1. Command line arguments (highest priority)
2. Environment variables
3. Default settings (SSL verification enabled)

### Examples
```bash
# Production setup with proper certificates
export VAULT_ADDR="https://vault.company.com:8200"
export VAULT_CACERT="/etc/ssl/vault-ca.pem"
export VAULT_CLIENT_CERT="/etc/ssl/client.pem"
export VAULT_CLIENT_KEY="/etc/ssl/client-key.pem"
python main.py scan

# Development setup (less secure)
export VAULT_ADDR="https://vault-dev.company.com:8200"
python main.py scan --skip-verify
```

## Architecture

The tool is organized into several modules for maintainability:

- **main.py**: Entry point and Vault client configuration
- **cli_handlers.py**: Command-line interface and argument parsing
- **scan_functions.py**: PKI scanning, visualization, and HTML generation
- **root_ca_operations.py**: Root CA creation and rotation
- **intermediate_ca_operations.py**: Intermediate CA management
- **ca_helpers.py**: Common CA utilities and certificate operations
- **utils.py**: Shared utility functions

## Error Handling

The tool provides comprehensive error handling for common scenarios:

- **Connection Errors**: Clear messages for Vault connectivity issues
- **Authentication Errors**: Guidance for token and certificate problems
- **Namespace Errors**: Validation for Enterprise namespace features
- **Certificate Errors**: Detailed information about certificate parsing issues
- **SSL Errors**: Specific guidance for SSL/TLS configuration problems

## Enterprise Features

### Namespace Support
- **Single Namespace**: Scan specific namespace with `--namespace`
- **All Namespaces**: Scan across all namespaces with `--all-namespaces`
- **Automatic Detection**: Tool detects Vault Enterprise automatically

### Namespace-Aware Output
- Clear namespace identification in output
- Namespace-prefixed certificate names in multi-namespace scans
- Separate timeline visualization per namespace

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add your license information here]

## Support

For issues and questions:
1. Check the error messages for specific guidance
2. Verify Vault connectivity and authentication
3. Ensure proper SSL/TLS configuration
4. Check Vault logs for server-side issues

## Changelog

### Latest Version
- ✅ Added HTML report generation with professional styling
- ✅ Enhanced SSL/TLS support with comprehensive configuration options
- ✅ Improved namespace support for Vault Enterprise
- ✅ Added timeline visualization with hierarchy connections
- ✅ Comprehensive error handling and user guidance
- ✅ Modular architecture for maintainability
