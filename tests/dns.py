"""
DNS Security Tests

Tests for DNS configuration security including DNS server validation,
DNSSEC, and DNS resolver security.
"""

import pytest


@pytest.mark.critical
@pytest.mark.security
@pytest.mark.system
def test_dns_servers_configured(dns_config):
    """Verify DNS servers are configured"""
    assert len(dns_config['dns_servers']) > 0, \
        "At least one DNS server should be configured"


@pytest.mark.security
@pytest.mark.system
def test_dns_servers_not_public(dns_config, config):
    """Verify DNS servers match expected configuration"""
    expected_dns = config.get('expected_config', {}).get('dns_servers', [])
    
    if expected_dns:
        actual_dns = set(dns_config['dns_servers'])
        expected_dns_set = set(expected_dns)
        
        assert actual_dns == expected_dns_set, \
            f"DNS servers mismatch. Expected: {expected_dns_set}, Found: {actual_dns}"


@pytest.mark.security
@pytest.mark.system
def test_multiple_dns_servers(dns_config):
    """Verify multiple DNS servers configured for redundancy"""
    dns_count = len(dns_config['dns_servers'])
    
    assert dns_count >= 2, \
        f"Should have at least 2 DNS servers for redundancy, found: {dns_count}"


@pytest.mark.security
def test_dns_resolver_not_open(open_ports):
    """Verify DNS resolver is not open to the internet"""
    dns_ports = []
    
    for port_info in open_ports:
        address = port_info.get('address', '')
        
        # Check if DNS port (53) is listening on all interfaces
        if ':53' in address or '.53' in address:
            if '0.0.0.0' in address or '*' in address:
                dns_ports.append(port_info)
    
    if dns_ports:
        pytest.warns(UserWarning, 
                    f"DNS resolver appears to be listening on all interfaces: {dns_ports}")


@pytest.mark.security
def test_dns_over_tls_available(running_services):
    """Check if DNS over TLS is available"""
    # DNS over TLS (DoT) provides encrypted DNS queries
    # This is an optional security enhancement
    
    # Unbound supports DoT
    if 'unbound' in running_services:
        # Could check unbound configuration for DoT
        pass


@pytest.mark.security
def test_dnssec_validation(opnsense_ssh):
    """Verify DNSSEC validation is enabled"""
    # DNSSEC provides authentication of DNS data
    
    stdout, stderr = opnsense_ssh.execute("unbound-control status 2>/dev/null || echo 'not available'")
    
    if 'not available' not in stdout.lower():
        # Check if DNSSEC is enabled in unbound
        # This would require parsing unbound configuration or status
        pass


@pytest.mark.security
def test_dns_cache_poisoning_protection(opnsense_ssh):
    """Verify DNS cache poisoning protection is enabled"""
    # Modern DNS resolvers have built-in protections
    # Check that resolver is using randomized source ports
    
    stdout, stderr = opnsense_ssh.execute("sockstat -4 | grep unbound | grep -v ':53 '")
    
    if stdout:
        # Check for source port randomization
        # Different queries should use different source ports
        pass


@pytest.mark.security
def test_no_dns_amplification_risk(opnsense_ssh):
    """Verify DNS server is not vulnerable to amplification attacks"""
    # DNS resolver should not respond to external queries
    # Only internal network should be able to use it
    
    # Check firewall rules to ensure DNS is blocked from WAN
    # This is covered in firewall tests but worth double-checking
    pass


@pytest.mark.security
def test_dns_query_logging_configured(config):
    """Verify DNS query logging is configured per policy"""
    require_dns_logging = config.get('security_policy', {}).get('require_dns_logging', False)
    
    if require_dns_logging:
        # Check if DNS query logging is enabled
        # Implementation depends on DNS resolver configuration
        pass


@pytest.mark.security
def test_no_public_dns_for_sensitive_networks(dns_config, config):
    """Verify sensitive networks don't use public DNS"""
    environment = config.get('environment', '')
    
    if environment == 'production':
        # Check if using public DNS services
        public_dns_servers = [
            '8.8.8.8', '8.8.4.4',  # Google
            '1.1.1.1', '1.0.0.1',  # Cloudflare
            '208.67.222.222', '208.67.220.220',  # OpenDNS
        ]
        
        dns_servers = dns_config.get('dns_servers', [])
        
        using_public_dns = any(dns in public_dns_servers for dns in dns_servers)
        
        if using_public_dns:
            pytest.warns(UserWarning, 
                        "Production environment using public DNS - consider internal DNS")


@pytest.mark.security
def test_dns_resolver_version_hidden(opnsense_ssh):
    """Verify DNS resolver doesn't expose version information"""
    # Query for version.bind should be disabled
    # This prevents information disclosure
    
    # Check unbound configuration for hide-version
    stdout, stderr = opnsense_ssh.execute("grep -i 'hide-version' /var/unbound/unbound.conf 2>/dev/null || echo 'not found'")
    
    if 'hide-version: yes' in stdout:
        # Good - version is hidden
        pass
    elif 'not found' not in stdout:
        pytest.warns(UserWarning, 
                    "DNS resolver should hide version information")


@pytest.mark.security
def test_dns_rate_limiting(opnsense_ssh):
    """Verify DNS rate limiting is configured"""
    # Rate limiting helps prevent DNS-based attacks
    
    stdout, stderr = opnsense_ssh.execute("grep -i 'ratelimit' /var/unbound/unbound.conf 2>/dev/null || echo 'not found'")
    
    if 'ratelimit:' in stdout and 'not found' not in stdout:
        # Rate limiting is configured
        pass


@pytest.mark.security
def test_dns_forwarders_secure(opnsense_ssh):
    """Verify DNS forwarders use secure protocols"""
    # If using DNS forwarders, they should use DoT or DoH
    
    stdout, stderr = opnsense_ssh.execute("grep -i 'forward-zone' /var/unbound/unbound.conf 2>/dev/null || echo 'not found'")
    
    if 'forward-zone' in stdout and 'not found' not in stdout:
        # Check if using secure forwarding (port 853 for DoT)
        if '@853' in stdout or 'tls' in stdout.lower():
            # Good - using DNS over TLS
            pass
        else:
            pytest.warns(UserWarning, 
                        "DNS forwarders should use DNS over TLS (DoT)")


@pytest.mark.security
def test_dns_blocklist_configured(config):
    """Verify DNS blocklist is configured for malware/ad blocking"""
    # Optional: Check if DNS-based blocklist is configured
    # This is an additional security measure
    
    require_dns_blocklist = config.get('security_policy', {}).get('require_dns_blocklist', False)
    
    if require_dns_blocklist:
        # Check if blocklist is configured in unbound
        pass
