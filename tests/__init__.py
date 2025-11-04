"""
OPNsense Security Test Suite

This test suite provides comprehensive security testing for OPNsense
firewall configurations.

Test Categories:
- System: System configuration and security settings
- Firewall: Firewall rules and policies
- Interfaces: Network interface configuration
- Certificates: SSL/TLS certificate validation
- Services: System services and daemon security
- VPN: VPN configuration security (IPsec, OpenVPN)
- Network: Network-level security (routing, NAT, ARP)
- DNS: DNS configuration and security
- Access Control: Administrative access and authentication

Usage:
    pytest                          # Run all tests
    pytest -m critical              # Run critical tests only
    pytest -m firewall              # Run firewall tests
    pytest tests/test_system.py     # Run specific test file
"""

__version__ = "1.0.0"
__author__ = "Your Name"

# Test categories and their descriptions
TEST_CATEGORIES = {
    'system': 'System configuration and security settings',
    'firewall': 'Firewall rules and security policies',
    'interfaces': 'Network interface configuration',
    'certificates': 'SSL/TLS certificate validation',
    'services': 'System services and daemon security',
    'vpn': 'VPN configuration security',
    'network': 'Network-level security',
    'dns': 'DNS configuration and security',
    'access_control': 'Administrative access controls',
}

# Test markers
MARKERS = {
    'critical': 'Critical security tests that must pass',
    'security': 'Security-related tests',
    'firewall': 'Firewall configuration tests',
    'system': 'System configuration tests',
    'network': 'Network configuration tests',
    'vpn': 'VPN configuration tests',
    'certificates': 'Certificate validation tests',
    'compliance': 'Compliance framework tests',
}
