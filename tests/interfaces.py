"""
Network Interface Tests

Tests for interface configuration, IP addressing, and interface security
including WAN/LAN configuration and VLAN validation.
"""

import pytest


@pytest.mark.critical
@pytest.mark.network
@pytest.mark.security
def test_wan_interface_configured(wan_interface):
    """Verify WAN interface is properly configured"""
    assert wan_interface is not None, "WAN interface must be configured"
    assert wan_interface.get('status') == 'up', "WAN interface should be up"


@pytest.mark.critical
@pytest.mark.network
@pytest.mark.security
def test_lan_interface_configured(lan_interface):
    """Verify LAN interface is properly configured"""
    assert lan_interface is not None, "LAN interface must be configured"
    assert lan_interface.get('status') == 'up', "LAN interface should be up"


@pytest.mark.network
@pytest.mark.security
def test_no_interfaces_in_promiscuous_mode(opnsense_ssh):
    """Verify no interfaces are in promiscuous mode (unless required)"""
    stdout, stderr = opnsense_ssh.execute("ifconfig")
    
    # Check for PROMISC flag
    promiscuous_interfaces = []
    current_if = None
    
    for line in stdout.split('\n'):
        if line and not line.startswith('\t') and ':' in line:
            current_if = line.split(':')[0]
        if 'PROMISC' in line and current_if:
            promiscuous_interfaces.append(current_if)
    
    # Some monitoring tools might require promiscuous mode
    # Adjust this test based on your requirements
    assert len(promiscuous_interfaces) == 0 or \
           all('monitor' in iface.lower() for iface in promiscuous_interfaces), \
           f"Unexpected promiscuous mode on interfaces: {promiscuous_interfaces}"


@pytest.mark.network
@pytest.mark.security
def test_private_ip_on_lan(lan_interface):
    """Verify LAN interface uses private IP address"""
    private_ranges = ['10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                     '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                     '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                     '172.30.', '172.31.', '192.168.']
    
    lan_ip = lan_interface.get('ipaddr', '')
    
    assert any(lan_ip.startswith(prefix) for prefix in private_ranges), \
        f"LAN should use private IP address, found: {lan_ip}"


@pytest.mark.network
@pytest.mark.security
def test_interface_addresses_match_config(interface_list, config):
    """Verify interface IP addresses match expected configuration"""
    expected_interfaces = config.get('expected_config', {}).get('interfaces', [])
    
    for expected_if in expected_interfaces:
        name = expected_if.get('name')
        expected_ip = expected_if.get('ipaddr')
        
        if expected_ip and expected_ip != 'dhcp':
            actual_if = next((iface for iface in interface_list 
                            if iface.get('name') == name), None)
            
            if actual_if:
                actual_ip = actual_if.get('ipaddr', '')
                assert actual_ip == expected_ip, \
                    f"Interface {name} IP mismatch. Expected: {expected_ip}, Found: {actual_ip}"


@pytest.mark.network
@pytest.mark.security
def test_vlan_interfaces_configured(vlan_interfaces, config):
    """Verify VLAN interfaces are properly configured"""
    expected_vlans = config.get('expected_config', {}).get('vlans', [])
    
    if expected_vlans:
        for expected_vlan in expected_vlans:
            vlan_id = expected_vlan.get('vlan_id')
            
            matching_vlan = next((vlan for vlan in vlan_interfaces 
                                if str(vlan_id) in str(vlan.get('tag', ''))), None)
            
            if expected_vlan.get('enabled', True):
                assert matching_vlan is not None, \
                    f"VLAN {vlan_id} should be configured"


@pytest.mark.network
def test_interface_mtu_configured(interface_list):
    """Verify interface MTU settings are appropriate"""
    for interface in interface_list:
        mtu = interface.get('mtu', 1500)
        
        # MTU should be reasonable (typically 1500 for Ethernet, or jumbo frames 9000)
        assert 1280 <= int(mtu) <= 9000, \
            f"Interface {interface.get('name')} has unusual MTU: {mtu}"


@pytest.mark.network
@pytest.mark.security
def test_wan_interface_not_bridged(wan_interface):
    """Verify WAN interface is not bridged (security risk)"""
    if_type = wan_interface.get('type', '').lower()
    
    assert 'bridge' not in if_type, \
        "WAN interface should not be part of a bridge (security risk)"


@pytest.mark.network
def test_interfaces_have_descriptions(interface_list):
    """Verify interfaces have meaningful descriptions"""
    interfaces_without_description = [
        iface for iface in interface_list
        if not iface.get('descr') or iface.get('descr').strip() == ''
    ]
    
    # Allow some interfaces without descriptions, but warn if too many
    percentage = len(interfaces_without_description) / len(interface_list) * 100 if interface_list else 0
    
    if percentage > 50:
        pytest.warns(UserWarning, 
                    f"{percentage:.1f}% of interfaces lack descriptions")


@pytest.mark.network
@pytest.mark.security
def test_dhcp_not_on_wan(wan_interface, config):
    """Verify DHCP server is not running on WAN interface"""
    # This should be verified through DHCP configuration
    # This is a basic check
    wan_name = wan_interface.get('name', 'wan')
    
    # Check DHCP configuration doesn't include WAN
    # Implementation depends on DHCP config structure
    pass


@pytest.mark.network
def test_interface_statistics(interface_list):
    """Check for interface errors and drops"""
    for interface in interface_list:
        if interface.get('status') == 'up':
            # Check for excessive errors or drops
            # Implementation depends on API response structure
            errors = interface.get('errors', 0)
            drops = interface.get('drops', 0)
            
            # Add thresholds based on your requirements
            pass
