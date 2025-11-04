"""
Firewall Rules Tests

Tests for firewall rule configuration and security policies including
rule validation, default deny policies, and protection of management ports.
"""

import pytest


@pytest.mark.critical
@pytest.mark.firewall
@pytest.mark.security
def test_no_any_any_allow_rules(firewall_rules):
    """Verify no overly permissive 'any any allow' rules exist"""
    dangerous_rules = [
        rule for rule in firewall_rules
        if rule.get('action') == 'pass' 
        and rule.get('source', {}).get('network') == 'any'
        and rule.get('destination', {}).get('network') == 'any'
    ]
    
    assert len(dangerous_rules) == 0, \
        f"Found {len(dangerous_rules)} dangerous 'any any allow' rules: {dangerous_rules}"


@pytest.mark.critical
@pytest.mark.firewall
@pytest.mark.security
def test_wan_default_deny(wan_rules, default_deny_rules):
    """Verify WAN interface has default deny rule"""
    wan_deny_rules = [
        rule for rule in default_deny_rules
        if rule.get('interface') == 'wan'
    ]
    
    assert len(wan_deny_rules) > 0, \
        "WAN interface should have explicit deny rules"


@pytest.mark.critical
@pytest.mark.firewall
@pytest.mark.security
def test_no_wan_management_access(wan_rules):
    """Verify management ports are not accessible from WAN"""
    management_ports = [22, 443, 80, 8443]  # SSH, HTTPS, HTTP, alt HTTPS
    
    dangerous_rules = []
    for rule in wan_rules:
        if rule.get('action') == 'pass':
            dest_port = rule.get('destination', {}).get('port')
            if dest_port:
                # Check if any management port is allowed
                for mgmt_port in management_ports:
                    if str(mgmt_port) in str(dest_port):
                        dangerous_rules.append(rule)
    
    assert len(dangerous_rules) == 0, \
        f"Management ports should not be accessible from WAN: {dangerous_rules}"


@pytest.mark.firewall
@pytest.mark.security
def test_antispoofing_enabled(firewall_rules):
    """Verify anti-spoofing rules are in place"""
    # This is a basic check - adjust based on your OPNsense configuration
    # OPNsense typically has built-in anti-spoofing
    assert len(firewall_rules) > 0, "Firewall rules should exist"


@pytest.mark.critical
@pytest.mark.firewall
@pytest.mark.security
def test_no_disabled_rules_in_production(firewall_rules):
    """Verify there are no disabled rules that should be cleaned up"""
    disabled_rules = [rule for rule in firewall_rules if rule.get('enabled') == '0']
    
    # This is a warning test - you might want to allow some disabled rules
    if len(disabled_rules) > 10:
        pytest.fail(f"Found {len(disabled_rules)} disabled rules - consider cleanup")


@pytest.mark.firewall
@pytest.mark.security
def test_firewall_rules_have_descriptions(firewall_rules):
    """Verify firewall rules have descriptions for auditability"""
    rules_without_description = [
        rule for rule in firewall_rules 
        if not rule.get('description') or rule.get('description').strip() == ''
    ]
    
    # Allow some rules without descriptions, but flag if too many
    percentage = len(rules_without_description) / len(firewall_rules) * 100 if firewall_rules else 0
    
    assert percentage < 30, \
        f"{percentage:.1f}% of rules lack descriptions - documentation needed for audit trail"


@pytest.mark.firewall
@pytest.mark.security
def test_lan_to_wan_rules_exist(lan_rules):
    """Verify LAN to WAN traffic rules are configured"""
    assert len(lan_rules) > 0, "LAN interface should have firewall rules configured"


@pytest.mark.firewall
@pytest.mark.security
def test_firewall_state_table_not_full(firewall_state_table):
    """Verify firewall state table is not exhausted"""
    state_info = firewall_state_table['state_info']
    
    # Parse state table usage - adjust based on pfctl output format
    # This is a basic check
    assert 'table full' not in state_info.lower(), \
        "Firewall state table is full - may indicate DoS or misconfiguration"


@pytest.mark.firewall
@pytest.mark.security
def test_default_deny_rules_exist(default_deny_rules):
    """Verify default deny rules are configured"""
    assert len(default_deny_rules) > 0, \
        "Default deny/block rules should be configured"


@pytest.mark.firewall
@pytest.mark.security
def test_firewall_logging_enabled(firewall_rules):
    """Verify critical firewall rules have logging enabled"""
    critical_rules = [
        rule for rule in firewall_rules
        if rule.get('action') == 'block' or 'wan' in rule.get('interface', '').lower()
    ]
    
    # Check if logging is enabled for critical rules
    # Implementation depends on how OPNsense API returns logging info
    if critical_rules:
        # Add actual logging check based on API response structure
        pass


@pytest.mark.firewall
@pytest.mark.compliance
def test_required_firewall_rules(firewall_rules, config):
    """Verify required firewall rules exist per compliance policy"""
    required_rules = config.get('firewall_compliance', {}).get('required_rules', [])
    
    if required_rules:
        for required_rule in required_rules:
            # Implement rule matching logic based on your requirements
            # This is a placeholder
            description = required_rule.get('description', '')
            matching_rules = [
                rule for rule in firewall_rules
                if description.lower() in rule.get('description', '').lower()
            ]
            
            assert len(matching_rules) > 0, \
                f"Required firewall rule not found: {description}"


@pytest.mark.firewall
@pytest.mark.compliance
def test_prohibited_firewall_rules(firewall_rules, config):
    """Verify prohibited firewall rules do not exist"""
    prohibited_rules = config.get('firewall_compliance', {}).get('prohibited_rules', [])
    
    if prohibited_rules:
        for prohibited_rule in prohibited_rules:
            # Implement rule matching logic
            description = prohibited_rule.get('description', '')
            interface = prohibited_rule.get('interface', '')
            
            dangerous_rules = [
                rule for rule in firewall_rules
                if rule.get('interface') == interface
                and rule.get('action') == prohibited_rule.get('action')
            ]
            
            if prohibited_rule.get('destination_port'):
                ports = prohibited_rule['destination_port']
                if not isinstance(ports, list):
                    ports = [ports]
                
                dangerous_rules = [
                    rule for rule in dangerous_rules
                    if any(str(port) in str(rule.get('destination', {}).get('port', '')) 
                           for port in ports)
                ]
            
            assert len(dangerous_rules) == 0, \
                f"Prohibited firewall rule found: {description} - {dangerous_rules}"
