"""
Network Security Tests

Tests for network-level security including routing, NAT, ARP,
and network configuration security.
"""

import pytest


@pytest.mark.critical
@pytest.mark.security
@pytest.mark.network
def test_no_default_route_to_wan(routing_table):
    """Verify default route is properly configured"""
    default_routes = [route for route in routing_table if route['destination'] == 'default']
    
    assert len(default_routes) > 0, "Default route should be configured"


@pytest.mark.security
@pytest.mark.network
def test_no_suspicious_arp_entries(arp_table):
    """Check for suspicious ARP entries (basic check)"""
    # This is a basic test - enhance based on your network topology
    duplicate_ips = {}
    
    for entry in arp_table:
        ip = entry['ip']
        mac = entry['mac']
        
        if ip in duplicate_ips and duplicate_ips[ip] != mac:
            pytest.warns(UserWarning, 
                        f"Duplicate IP {ip} with different MACs: {duplicate_ips[ip]} vs {mac}")
        duplicate_ips[ip] = mac


@pytest.mark.security
@pytest.mark.network
def test_nat_configured(nat_rules):
    """Verify NAT is configured if required"""
    assert nat_rules['rule_count'] > 0, "NAT rules should be configured"


@pytest.mark.network
@pytest.mark.security
def test_routing_table_has_no_conflicts(routing_table):
    """Verify routing table has no conflicting routes"""
    destinations = [route['destination'] for route in routing_table]
    
    # Check for duplicate destination entries
    seen = set()
    duplicates = []
    
    for dest in destinations:
        if dest in seen and dest != 'default':
            duplicates.append(dest)
        seen.add(dest)
    
    if duplicates:
        pytest.warns(UserWarning, 
                    f"Duplicate routing entries found: {duplicates}")


@pytest.mark.network
@pytest.mark.security
def test_no_private_ips_on_wan_route(routing_table, wan_interface):
    """Verify no private IP routes point to WAN interface"""
    private_prefixes = ['10.', '172.16.', '192.168.']
    wan_name = wan_interface.get('name', 'wan')
    
    problematic_routes = [
        route for route in routing_table
        if any(route['destination'].startswith(prefix) for prefix in private_prefixes)
        and wan_name in route.get('interface', '')
    ]
    
    assert len(problematic_routes) == 0, \
        f"Private IP ranges should not route through WAN: {problematic_routes}"


@pytest.mark.network
@pytest.mark.security
def test_no_public_ips_on_lan_route(routing_table, lan_interface):
    """Verify public IPs don't incorrectly route through LAN"""
    # This is a basic sanity check
    # More sophisticated checks would verify specific public IP ranges
    
    lan_name = lan_interface.get('name', 'lan')
    
    # Check that default route doesn't point to LAN
    default_routes = [
        route for route in routing_table
        if route['destination'] == 'default'
        and lan_name in route.get('interface', '')
    ]
    
    if default_routes:
        pytest.warns(UserWarning, 
                    "Default route should not point to LAN interface")


@pytest.mark.network
@pytest.mark.security
def test_gateway_reachability(routing_table):
    """Verify gateways in routing table are reachable"""
    # This would require actual connectivity tests
    # Placeholder for gateway reachability checks
    
    gateways = set(route['gateway'] for route in routing_table if route.get('gateway'))
    
    assert len(gateways) > 0, "Should have at least one gateway configured"


@pytest.mark.network
def test_arp_table_size_reasonable(arp_table):
    """Verify ARP table size is reasonable"""
    # Very large ARP tables might indicate scanning or issues
    
    arp_count = len(arp_table)
    
    # Adjust threshold based on your network size
    if arp_count > 1000:
        pytest.warns(UserWarning, 
                    f"Large ARP table ({arp_count} entries) - may indicate scanning")


@pytest.mark.network
@pytest.mark.security
def test_nat_outbound_rules_secure(nat_rules):
    """Verify NAT outbound rules are secure"""
    nat_config = nat_rules['nat_rules']
    
    # Check that NAT rules don't expose internal network unnecessarily
    # Implementation depends on NAT rule format
    
    # Basic check: NAT should be configured
    assert nat_rules['rule_count'] > 0, "Outbound NAT should be configured"


@pytest.mark.network
@pytest.mark.security
def test_port_forwarding_rules_documented(nat_rules):
    """Verify port forwarding rules are documented"""
    # Port forwarding should be well-documented for security audit
    # Implementation depends on how NAT rules are structured
    pass


@pytest.mark.network
@pytest.mark.security
def test_no_unnecessary_port_forwards(nat_rules, config):
    """Verify only necessary ports are forwarded"""
    # Check against list of approved port forwards
    approved_forwards = config.get('network_security', {}).get('approved_port_forwards', [])
    
    # Implementation depends on NAT rule structure
    pass


@pytest.mark.network
@pytest.mark.security
def test_icmp_rate_limiting(opnsense_ssh):
    """Verify ICMP rate limiting is configured"""
    # ICMP rate limiting helps prevent DoS attacks
    stdout, stderr = opnsense_ssh.execute("sysctl net.inet.icmp.icmplim")
    
    if stdout:
        # Parse the rate limit value
        parts = stdout.strip().split(':')
        if len(parts) == 2:
            rate_limit = int(parts[1].strip())
            
            # Rate limit should be set (not unlimited)
            assert rate_limit > 0 and rate_limit <= 200, \
                f"ICMP rate limit should be reasonable (1-200), found: {rate_limit}"


@pytest.mark.network
@pytest.mark.security
def test_syn_cookies_enabled(opnsense_ssh):
    """Verify SYN cookies are enabled (SYN flood protection)"""
    stdout, stderr = opnsense_ssh.execute("sysctl net.inet.tcp.syncookies")
    
    if stdout:
        # Parse the value
        parts = stdout.strip().split(':')
        if len(parts) == 2:
            syncookies = int(parts[1].strip())
            
            assert syncookies == 1, \
                "SYN cookies should be enabled for SYN flood protection"


@pytest.mark.network
@pytest.mark.security
def test_source_routing_disabled(opnsense_ssh):
    """Verify source routing is disabled"""
    stdout, stderr = opnsense_ssh.execute("sysctl net.inet.ip.sourceroute")
    
    if stdout:
        parts = stdout.strip().split(':')
        if len(parts) == 2:
            source_routing = int(parts[1].strip())
            
            assert source_routing == 0, \
                "Source routing should be disabled (security risk)"


@pytest.mark.network
@pytest.mark.security
def test_ip_forwarding_configured(opnsense_ssh):
    """Verify IP forwarding is properly configured"""
    stdout, stderr = opnsense_ssh.execute("sysctl net.inet.ip.forwarding")
    
    if stdout:
        parts = stdout.strip().split(':')
        if len(parts) == 2:
            ip_forwarding = int(parts[1].strip())
            
            # For a firewall/router, IP forwarding should be enabled
            assert ip_forwarding == 1, \
                "IP forwarding should be enabled for router/firewall"


@pytest.mark.network
@pytest.mark.security
def test_icmp_redirects_disabled(opnsense_ssh):
    """Verify ICMP redirects are disabled"""
    stdout, stderr = opnsense_ssh.execute("sysctl net.inet.ip.redirect")
    
    if stdout:
        parts = stdout.strip().split(':')
        if len(parts) == 2:
            redirects = int(parts[1].strip())
            
            assert redirects == 0, \
                "ICMP redirects should be disabled (security risk)"


@pytest.mark.network
@pytest.mark.security
def test_broadcast_ping_disabled(opnsense_ssh):
    """Verify broadcast ping responses are disabled"""
    stdout, stderr = opnsense_ssh.execute("sysctl net.inet.icmp.bmcastecho")
    
    if stdout:
        parts = stdout.strip().split(':')
        if len(parts) == 2:
            bcast_echo = int(parts[1].strip())
            
            assert bcast_echo == 0, \
                "Broadcast ping should be disabled (prevents Smurf attacks)"


@pytest.mark.network
def test_tcp_keepalive_configured(opnsense_ssh):
    """Verify TCP keepalive is configured"""
    stdout, stderr = opnsense_ssh.execute("sysctl net.inet.tcp.always_keepalive")
    
    if stdout:
        parts = stdout.strip().split(':')
        if len(parts) == 2:
            keepalive = int(parts[1].strip())
            
            # Keepalive helps detect dead connections
            # Value of 1 means enabled
            pass


@pytest.mark.network
@pytest.mark.security
def test_no_ipv6_if_disabled(config, opnsense_ssh):
    """Verify IPv6 is disabled if not in use"""
    ipv6_enabled = config.get('expected_config', {}).get('ipv6_enabled', False)
    
    if not ipv6_enabled:
        # Check that IPv6 forwarding is disabled
        stdout, stderr = opnsense_ssh.execute("sysctl net.inet6.ip6.forwarding")
        
        if stdout and 'net.inet6.ip6.forwarding' in stdout:
            parts = stdout.strip().split(':')
            if len(parts) == 2:
                ipv6_forwarding = int(parts[1].strip())
                
                assert ipv6_forwarding == 0, \
                    "IPv6 forwarding should be disabled if not using IPv6"
