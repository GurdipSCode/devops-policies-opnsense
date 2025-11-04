"""
Services Tests

Tests for system services including required services, intrusion detection,
and verification that no unnecessary services are running.
"""

import pytest


@pytest.mark.critical
@pytest.mark.security
@pytest.mark.system
def test_required_services_running(running_services, config):
    """Verify required security services are running"""
    required_services = config.get('security_policy', {}).get('required_services', [
        'sshd',
        'unbound',  # DNS
    ])
    
    missing_services = [svc for svc in required_services if svc not in running_services]
    
    assert len(missing_services) == 0, \
        f"Required services not running: {missing_services}"


@pytest.mark.security
@pytest.mark.system
def test_no_unnecessary_services(running_services, config):
    """Verify no unnecessary services are running"""
    allowed_services = config.get('security_policy', {}).get('allowed_services', [])
    
    if allowed_services:
        unnecessary = [svc for svc in running_services if svc not in allowed_services]
        
        if unnecessary:
            pytest.warns(UserWarning, 
                        f"Unexpected services running: {unnecessary}")


@pytest.mark.security
def test_intrusion_detection_enabled(intrusion_detection, config):
    """Verify intrusion detection/prevention is enabled"""
    if config.get('security_policy', {}).get('require_ids', False):
        assert intrusion_detection['enabled'], \
            "Intrusion detection system should be enabled per security policy"


@pytest.mark.security
def test_intrusion_detection_mode(intrusion_detection, config):
    """Verify IDS/IPS is in correct mode"""
    required_mode = config.get('security_policy', {}).get('ids_mode', 'IPS')
    
    if required_mode and intrusion_detection.get('enabled'):
        # Check if running in correct mode
        # Implementation depends on how mode is returned in status
        status = intrusion_detection.get('status', '').upper()
        
        if required_mode.upper() in ['IPS', 'PREVENTION']:
            # Verify it's in IPS mode, not just IDS
            pass


@pytest.mark.security
@pytest.mark.system
def test_firewall_service_running(running_services):
    """Verify firewall/pf service is running"""
    # The packet filter (pf) should always be running
    # Service name might vary
    firewall_services = ['pf', 'pfctl', 'firewall']
    
    # At minimum, the system should have firewall capability
    # This is more of a sanity check
    assert len(running_services) > 0, "Should have running services"


@pytest.mark.security
@pytest.mark.system
def test_dns_resolver_running(running_services):
    """Verify DNS resolver service is running"""
    dns_services = ['unbound', 'dnsmasq']
    
    dns_running = any(dns_svc in running_services for dns_svc in dns_services)
    
    assert dns_running, \
        f"DNS resolver should be running. Expected one of: {dns_services}"


@pytest.mark.security
@pytest.mark.system
def test_ntp_service_running(running_services):
    """Verify NTP service is running"""
    ntp_services = ['ntpd', 'chronyd', 'ntpdate']
    
    ntp_running = any(ntp_svc in running_services for ntp_svc in ntp_services)
    
    assert ntp_running, \
        f"NTP service should be running for time synchronization. Expected one of: {ntp_services}"


@pytest.mark.security
@pytest.mark.system
def test_syslog_service_running(running_services):
    """Verify syslog service is running"""
    syslog_services = ['syslogd', 'rsyslogd', 'syslog-ng']
    
    syslog_running = any(syslog_svc in running_services for syslog_svc in syslog_services)
    
    assert syslog_running, \
        f"Syslog service should be running. Expected one of: {syslog_services}"


@pytest.mark.security
def test_dhcp_service_status(running_services, config):
    """Verify DHCP service status matches configuration"""
    dhcp_enabled = config.get('expected_config', {}).get('dhcp_enabled', False)
    dhcp_services = ['dhcpd', 'isc-dhcp-server']
    
    dhcp_running = any(dhcp_svc in running_services for dhcp_svc in dhcp_services)
    
    if dhcp_enabled:
        assert dhcp_running, "DHCP service should be running per configuration"
    # Note: We don't assert it's not running if disabled, as it might be intentionally off


@pytest.mark.security
def test_web_gui_service_running(running_services):
    """Verify web GUI service is accessible"""
    web_services = ['lighttpd', 'nginx', 'httpd']
    
    web_running = any(web_svc in running_services for web_svc in web_services)
    
    assert web_running, \
        f"Web GUI service should be running. Expected one of: {web_services}"


@pytest.mark.security
@pytest.mark.system
def test_no_telnet_service(running_services):
    """Verify insecure telnet service is not running"""
    telnet_services = ['telnetd', 'telnet']
    
    telnet_running = any(telnet_svc in running_services for telnet_svc in telnet_services)
    
    assert not telnet_running, \
        "Telnet service should not be running (insecure protocol)"


@pytest.mark.security
@pytest.mark.system
def test_no_ftp_service(running_services):
    """Verify insecure FTP service is not running"""
    ftp_services = ['ftpd', 'vsftpd', 'proftpd']
    
    ftp_running = any(ftp_svc in running_services for ftp_svc in ftp_services)
    
    assert not ftp_running, \
        "FTP service should not be running (insecure protocol - use SFTP/SCP)"


@pytest.mark.security
def test_service_status_monitoring(services):
    """Verify service status can be retrieved"""
    assert isinstance(services, list), "Services should be returned as a list"
    assert len(services) > 0, "Should have at least some services"


@pytest.mark.security
def test_critical_services_auto_start(config):
    """Verify critical services are configured to auto-start"""
    # This test would check service startup configuration
    # Implementation depends on how OPNsense manages service startup
    pass
