import argparse
import glob
import os
import re
import sys
import csv
from collections import defaultdict
from html import escape

# Define all checks here with enhanced patterns and context validation
CHECKS = [
    # Administrative Security Checks
    {
        "name": "Telnet Enabled",
        "pattern": r"set\s+admin-telnet\s+enable",
        "description": "Telnet is a cleartext protocol and should be disabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-telnet\s+enable"]  # Exclude commented lines
    },
    {
        "name": "SSHv1 Enabled",
        "pattern": r"set\s+admin-ssh-v1\s+enable",
        "description": "SSH version 1 is deprecated and insecure.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 9.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-ssh-v1\s+enable"]
    },
    {
        "name": "Admin Restriction Not Enabled",
        "pattern": r"set\s+admin-restrict-local\s+disable",
        "description": "Admins should be restricted to specific IPs or interfaces.",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:N",
        "score": 6.4,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-restrict-local\s+disable"]
    },
    {
        "name": "Admin Console Timeout Disabled",
        "pattern": r"set\s+admin-console-timeout\s+0",
        "description": "A timeout of 0 disables session expiry and increases risk of hijack.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "score": 6.5,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-console-timeout\s+0"]
    },
    {
        "name": "HTTP Admin Access Enabled",
        "pattern": r"set\s+admin-sport\s+80|set\s+admin-protocol\s+http",
        "description": "HTTP admin access is unencrypted and should be disabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-sport\s+80", r"#.*set\s+admin-protocol\s+http"]
    },
    {
        "name": "SNMP Community String Default",
        "pattern": r"set\s+community\s+(public|private)(\s|$)",
        "description": "Default SNMP community strings should be changed.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+community\s+(public|private)"]
    },
    {
        "name": "SNMPv1/v2c Enabled",
        "pattern": r"set\s+version\s+(v1|v2c)",
        "description": "SNMPv1 and v2c use cleartext community strings.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+version\s+(v1|v2c)"]
    },
    {
        "name": "Default Admin Password",
        "pattern": r"set\s+passwd\s+(\"\"|''|password|admin|fortinet)",
        "description": "Default or weak admin passwords detected.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "score": 10.0,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+passwd"]
    },
    
    # SSL/TLS Security Checks
    {
        "name": "SSL v3 or TLS v1.0/v1.1 Enabled",
        "pattern": r"set\s+admin-https-ssl-versions\s+.*(?:sslv3|tlsv1\.0|tlsv1\.1)",
        "description": "Deprecated SSL/TLS versions in use.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 9.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-https-ssl-versions"]
    },
    {
        "name": "Weak Ciphers Allowed",
        "pattern": r"set\s+admin-https-ssl-ciphersuites.*(?:3DES|RC4|MD5|DES|NULL)",
        "description": "Weak SSL ciphers such as 3DES, RC4, MD5, DES, or NULL are enabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.4,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-https-ssl-ciphersuites"]
    },
    {
        "name": "SSL Certificate Verification Disabled",
        "pattern": r"set\s+ssl-verify-peer\s+disable",
        "description": "SSL certificate verification is disabled.",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 7.4,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+ssl-verify-peer\s+disable"]
    },
    
    # Authentication and Access Control
    {
        "name": "No Two-Factor Auth Configured",
        "pattern": r"set\s+admin-forticloud-sso-login\s+disable|set\s+two-factor\s+disable",
        "description": "Two-Factor Authentication not configured.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N",
        "score": 6.4,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-forticloud-sso-login\s+disable", r"#.*set\s+two-factor\s+disable"]
    },
    {
        "name": "Guest User Account Enabled",
        "pattern": r"set\s+guest-auth\s+enable",
        "description": "Guest user accounts should be disabled for security.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "score": 7.3,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+guest-auth\s+enable"]
    },
    {
        "name": "Password Policy Weak",
        "pattern": r"set\s+min-password-length\s+[1-7](\s|$)|set\s+password-policy\s+disable",
        "description": "Password policy is too weak or disabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "score": 6.5,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+min-password-length", r"#.*set\s+password-policy\s+disable"]
    },
    
    # Firewall Policy Checks (Enhanced to minimize false positives)
    {
        "name": "Overly Permissive Firewall Rules",
        "pattern": r"(?:set\s+srcaddr\s+\"?all\"?|set\s+dstaddr\s+\"?all\"?|set\s+srcaddr\s+\"?any\"?|set\s+dstaddr\s+\"?any\"?)",
        "description": "Firewall rules with 'all' or 'any' source/destination are overly permissive.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
        "score": 8.5,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+(?:src|dst)addr"]
    },
    {
        "name": "Any Service in Firewall Rules",
        "pattern": r"set\s+service\s+\"?ALL\"?",
        "description": "Firewall rules allowing all services are overly permissive.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
        "score": 8.0,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+service"]
    },
    {
        "name": "Firewall Logging Disabled",
        "pattern": r"set\s+logtraffic\s+disable",
        "description": "Traffic logging is disabled for firewall rules.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
        "score": 3.1,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+logtraffic\s+disable"]
    },
    
    # Network Security Checks
    {
        "name": "ICMP Redirect Enabled",
        "pattern": r"set\s+send-redirects\s+enable",
        "description": "ICMP redirects can be used for routing attacks.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "score": 4.3,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+send-redirects\s+enable"]
    },
    {
        "name": "IP Source Routing Enabled",
        "pattern": r"set\s+ip-src-check\s+disable",
        "description": "IP source routing should be disabled to prevent spoofing.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "score": 7.5,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+ip-src-check\s+disable"]
    },
    {
        "name": "Anti-Spoofing Disabled",
        "pattern": r"set\s+anti-spoofing\s+disable",
        "description": "Anti-spoofing protection should be enabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "score": 7.5,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+anti-spoofing\s+disable"]
    },
    
    # VPN Security Checks
    {
        "name": "Weak VPN Encryption",
        "pattern": r"set\s+proposal\s+.*(?:des|3des|md5)",
        "description": "Weak VPN encryption algorithms detected.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "context_required": True,
        "context_check": r"config\s+vpn",
        "exclude_patterns": [r"#.*set\s+proposal"]
    },
    {
        "name": "VPN Split Tunneling Enabled",
        "pattern": r"set\s+split-tunneling\s+enable",
        "description": "VPN split tunneling can bypass security policies.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
        "score": 6.4,
        "context_required": True,
        "context_check": r"config\s+vpn",
        "exclude_patterns": [r"#.*set\s+split-tunneling\s+enable"]
    },
    
    # Resource and Performance Checks
    {
        "name": "Excessive SSH Grace Time",
        "pattern": r"set\s+admin-ssh-grace-time\s+([2-9][0-9]{2,}|[1-9][0-9]{3,})",
        "description": "SSH grace time is too high (>200 seconds).",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N",
        "score": 5.3,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-ssh-grace-time"]
    },
    {
        "name": "Too Many Admin Logins",
        "pattern": r"set\s+admin-login-max\s+(1[0-9]{2,}|[2-9][0-9]{2,})",
        "description": "Max concurrent admin logins too high (>100).",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N",
        "score": 6.5,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-login-max"]
    },
    
    # IPS and Security Services
    {
        "name": "IPS Disabled",
        "pattern": r"set\s+ips-sensor\s+\"\"|\bunset\s+ips-sensor",
        "description": "Intrusion Prevention System (IPS) is not configured.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.8,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+ips-sensor", r"#.*unset\s+ips-sensor"]
    },
    {
        "name": "Antivirus Disabled",
        "pattern": r"set\s+av-profile\s+\"\"|\bunset\s+av-profile",
        "description": "Antivirus scanning is not configured.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.8,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+av-profile", r"#.*unset\s+av-profile"]
    },
    {
        "name": "Web Filtering Disabled",
        "pattern": r"set\s+webfilter-profile\s+\"\"|\bunset\s+webfilter-profile",
        "description": "Web filtering is not configured.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "score": 4.3,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+webfilter-profile", r"#.*unset\s+webfilter-profile"]
    },
    
    # DNS and Time Security
    {
        "name": "DNS Over Unencrypted Channel",
        "pattern": r"set\s+dns-over-tls\s+disable",
        "description": "DNS over TLS should be enabled for privacy.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 5.3,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+dns-over-tls\s+disable"]
    },
    {
        "name": "NTP Authentication Disabled",
        "pattern": r"set\s+ntpsync\s+enable.*(?:\n.*)*?set\s+authentication\s+disable",
        "description": "NTP authentication should be enabled to prevent time attacks.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.8,
        "context_required": True,
        "context_check": r"config\s+system\s+ntp",
        "exclude_patterns": [r"#.*set\s+authentication\s+disable"]
    },
    
    # Additional Administrative Security Checks
    {
        "name": "Admin Lockout Disabled",
        "pattern": r"set\s+admin-lockout-threshold\s+0|set\s+admin-lockout-duration\s+0",
        "description": "Account lockout protection should be enabled to prevent brute force attacks.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": 6.1,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-lockout"]
    },
    {
        "name": "Admin GUI Timeout Too Long",
        "pattern": r"set\s+gui-idle-timeout\s+([6-9][0-9]{2,}|[1-9][0-9]{3,})",
        "description": "GUI idle timeout is too long (>600 seconds/10 minutes).",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "score": 4.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+gui-idle-timeout"]
    },
    {
        "name": "Insecure Admin Protocol",
        "pattern": r"set\s+admin-https-pki-required\s+disable",
        "description": "PKI certificate requirement for HTTPS admin access should be enabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "score": 7.1,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+admin-https-pki-required"]
    },
    
    # Interface and Network Security
    {
        "name": "Interface without IP Verification",
        "pattern": r"set\s+ip-verify-source\s+disable",
        "description": "IP source verification should be enabled on interfaces.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "score": 5.3,
        "context_required": True,
        "context_check": r"config\s+system\s+interface",
        "exclude_patterns": [r"#.*set\s+ip-verify-source\s+disable"]
    },
    {
        "name": "DHCP Relay Without Security",
        "pattern": r"set\s+dhcp-relay.*\n(?:(?!set\s+dhcp-relay-option82).*\n)*",
        "description": "DHCP relay without option 82 security features.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.4,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+dhcp-relay"]
    },
    {
        "name": "Broadcast Storm Control Disabled",
        "pattern": r"set\s+storm-control\s+disable",
        "description": "Broadcast storm control should be enabled to prevent DoS attacks.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "score": 6.5,
        "context_required": True,
        "context_check": r"config\s+system\s+interface",
        "exclude_patterns": [r"#.*set\s+storm-control\s+disable"]
    },
    
    # Certificate and PKI Security
    {
        "name": "Weak Certificate Key Size",
        "pattern": r"set\s+rsa-key-size\s+(512|1024)",
        "description": "RSA key size is too small, should be 2048 bits or higher.",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 7.4,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+rsa-key-size"]
    },
    {
        "name": "Certificate Verification Bypass",
        "pattern": r"set\s+ssl-insecure\s+enable",
        "description": "SSL insecure mode bypasses certificate verification.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.1,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+ssl-insecure\s+enable"]
    },
    
    # High Availability and Clustering Security
    {
        "name": "HA Heartbeat Unencrypted",
        "pattern": r"set\s+hb-lost-threshold\s+[1-9].*\n(?:(?!set\s+encryption).*\n)*set\s+encryption\s+disable",
        "description": "HA heartbeat traffic should be encrypted.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": 5.8,
        "context_required": True,
        "context_check": r"config\s+system\s+ha",
        "exclude_patterns": [r"#.*set\s+encryption\s+disable"]
    },
    {
        "name": "HA Sync Interface Insecure",
        "pattern": r"set\s+sync-config\s+enable.*\n(?:(?!set\s+encryption).*\n)*",
        "description": "HA configuration sync should use encryption.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 7.1,
        "context_required": True,
        "context_check": r"config\s+system\s+ha",
        "exclude_patterns": [r"#.*set\s+sync-config"]
    },
    
    # Email and Alert Security
    {
        "name": "Email Alerts Unencrypted",
        "pattern": r"set\s+server.*\n(?:(?!set\s+security).*\n)*set\s+port\s+25",
        "description": "Email alerts using unencrypted SMTP (port 25).",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 5.3,
        "context_required": True,
        "context_check": r"config\s+alertemail",
        "exclude_patterns": [r"#.*set\s+port\s+25"]
    },
    
    # Routing Security
    {
        "name": "Static Route Without Verification",
        "pattern": r"set\s+gateway\s+0\.0\.0\.0|set\s+device\s+\"any\"",
        "description": "Static routes with insecure gateway or device configuration.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L",
        "score": 4.7,
        "context_required": True,
        "context_check": r"config\s+router\s+static",
        "exclude_patterns": [r"#.*set\s+gateway", r"#.*set\s+device"]
    },
    {
        "name": "RIP Authentication Disabled",
        "pattern": r"config\s+router\s+rip.*\n(?:(?!set\s+auth-mode).*\n)*",
        "description": "RIP routing protocol should use authentication.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",
        "score": 6.8,
        "context_required": True,
        "context_check": r"config\s+router\s+rip",
        "exclude_patterns": [r"#.*config\s+router\s+rip"]
    },
    {
        "name": "OSPF Authentication Disabled",
        "pattern": r"config\s+router\s+ospf.*\n(?:(?!set\s+auth-type).*\n)*",
        "description": "OSPF routing protocol should use authentication.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",
        "score": 6.8,
        "context_required": True,
        "context_check": r"config\s+router\s+ospf",
        "exclude_patterns": [r"#.*config\s+router\s+ospf"]
    },
    
    # Application Control and DLP
    {
        "name": "Application Control Disabled",
        "pattern": r"set\s+application-list\s+\"\"|\bunset\s+application-list",
        "description": "Application control is not configured for traffic inspection.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "score": 4.3,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+application-list", r"#.*unset\s+application-list"]
    },
    {
        "name": "DLP Profile Missing",
        "pattern": r"set\s+dlp-sensor\s+\"\"|\bunset\s+dlp-sensor",
        "description": "Data Loss Prevention (DLP) is not configured.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 4.9,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+dlp-sensor", r"#.*unset\s+dlp-sensor"]
    },
    
    # UTM and Content Filtering
    {
        "name": "DNS Filter Disabled",
        "pattern": r"set\s+dnsfilter-profile\s+\"\"|\bunset\s+dnsfilter-profile",
        "description": "DNS filtering is not configured for malicious domain blocking.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "score": 4.3,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+dnsfilter-profile", r"#.*unset\s+dnsfilter-profile"]
    },
    {
        "name": "SSL/SSH Inspection Disabled",
        "pattern": r"set\s+ssl-ssh-profile\s+\"no-inspection\"",
        "description": "SSL/SSH traffic inspection is disabled, reducing security visibility.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "score": 5.1,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+ssl-ssh-profile"]
    },
    
    # Wireless Security (if applicable)
    {
        "name": "Wireless WEP Encryption",
        "pattern": r"set\s+security\s+wep",
        "description": "WEP encryption is deprecated and easily broken.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.8,
        "context_required": True,
        "context_check": r"config\s+wireless-controller",
        "exclude_patterns": [r"#.*set\s+security\s+wep"]
    },
    {
        "name": "Wireless WPS Enabled",
        "pattern": r"set\s+wps\s+enable",
        "description": "WiFi Protected Setup (WPS) is vulnerable to brute force attacks.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.8,
        "context_required": True,
        "context_check": r"config\s+wireless-controller",
        "exclude_patterns": [r"#.*set\s+wps\s+enable"]
    },
    
    # Advanced Threat Protection
    {
        "name": "Sandbox Analysis Disabled",
        "pattern": r"set\s+file-filter\s+disable|set\s+fortisandbox\s+disable",
        "description": "Advanced malware sandbox analysis is disabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+file-filter\s+disable", r"#.*set\s+fortisandbox\s+disable"]
    },
    {
        "name": "Botnet Protection Disabled", 
        "pattern": r"set\s+botnet\s+disable",
        "description": "Botnet C&C communication blocking is disabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+botnet\s+disable"]
    },
    
    # System Hardening
    {
        "name": "Console Output Unrestricted",
        "pattern": r"set\s+console-output\s+standard",
        "description": "Console output should be restricted to reduce information disclosure.",
        "cvss": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "score": 3.3,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+console-output"]
    },
    {
        "name": "USB Port Enabled",
        "pattern": r"set\s+usb-port\s+enable",
        "description": "USB ports should be disabled to prevent unauthorized data access.",
        "cvss": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 6.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+usb-port\s+enable"]
    },
    
    # Additional Network Security Checks
    {
        "name": "SIP ALG Enabled",
        "pattern": r"set\s+sip-helper\s+enable|set\s+sip-nat-trace\s+enable",
        "description": "SIP ALG can cause VoIP issues and should typically be disabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 4.6,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+sip-helper", r"#.*set\s+sip-nat-trace"]
    },
    {
        "name": "IPv6 Enabled Without Security",
        "pattern": r"set\s+ip6-mode\s+static|set\s+ipv6\s+.*(?:\n(?!.*set\s+ip6-.*security).*)*",
        "description": "IPv6 enabled without proper security configurations.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": 5.9,
        "context_required": True,
        "context_check": r"config\s+system\s+interface",
        "exclude_patterns": [r"#.*set\s+ip6-mode", r"#.*set\s+ipv6"]
    },
    {
        "name": "Ping Response Enabled",
        "pattern": r"set\s+ping\s+enable",
        "description": "ICMP ping responses can aid in reconnaissance attacks.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 3.7,
        "context_required": True,
        "context_check": r"config\s+system\s+interface",
        "exclude_patterns": [r"#.*set\s+ping\s+enable"]
    },
    {
        "name": "LLDP Enabled",
        "pattern": r"set\s+lldp-transmission\s+enable",
        "description": "LLDP broadcasts can disclose network topology information.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 4.3,
        "context_required": True,
        "context_check": r"config\s+system\s+interface",
        "exclude_patterns": [r"#.*set\s+lldp-transmission"]
    },
    
    # Load Balancing and High Availability
    {
        "name": "Load Balance Without Health Check",
        "pattern": r"set\s+load-balance\s+enable.*\n(?:(?!set\s+health-check).*\n)*",
        "description": "Load balancing without health checks can route to failed servers.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "score": 4.0,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+load-balance"]
    },
    {
        "name": "Session Sync Unencrypted",
        "pattern": r"set\s+session-sync-dev\s+.*(?:\n(?!.*set\s+session-sync-encrypt).*)*",
        "description": "Session synchronization should be encrypted.",
        "cvss": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": 5.8,
        "context_required": True,
        "context_check": r"config\s+system\s+session-sync",
        "exclude_patterns": [r"#.*set\s+session-sync-dev"]
    },
    
    # Traffic Shaping and QoS Security
    {
        "name": "Traffic Shaping Without Rate Limiting",
        "pattern": r"config\s+firewall\s+shaper.*\n(?:(?!set\s+maximum-bandwidth).*\n)*",
        "description": "Traffic shaping without proper rate limits can enable DoS attacks.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "score": 4.3,
        "context_required": True,
        "context_check": r"config\s+firewall\s+shaper",
        "exclude_patterns": [r"#.*config\s+firewall\s+shaper"]
    },
    
    # Database and Logging Security
    {
        "name": "Log Disk Full Action Unsafe",
        "pattern": r"set\s+diskfull\s+overwrite",
        "description": "Overwriting logs when disk is full can hide security incidents.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
        "score": 4.9,
        "context_required": True,
        "context_check": r"config\s+log",
        "exclude_patterns": [r"#.*set\s+diskfull"]
    },
    {
        "name": "Remote Logging Unencrypted",
        "pattern": r"set\s+server\s+.*\n(?:(?!set\s+enc-algorithm).*\n)*set\s+port\s+514",
        "description": "Remote syslog without encryption (port 514) exposes log data.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 5.3,
        "context_required": True,
        "context_check": r"config\s+log\s+syslogd",
        "exclude_patterns": [r"#.*set\s+server", r"#.*set\s+port\s+514"]
    },
    {
        "name": "Log Buffer Too Small",
        "pattern": r"set\s+buffer-size\s+([0-9]|[1-5][0-9]|6[0-3])(\s|$)",
        "description": "Log buffer size too small (<64 KB) may cause log loss.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
        "score": 3.8,
        "context_required": True,
        "context_check": r"config\s+log",
        "exclude_patterns": [r"#.*set\s+buffer-size"]
    },
    
    # FortiGuard and Security Updates
    {
        "name": "FortiGuard Updates Disabled",
        "pattern": r"set\s+update-schedule\s+disable|set\s+av-update\s+disable",
        "description": "Automatic security updates should be enabled for current threat protection.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+update-schedule", r"#.*set\s+av-update"]
    },
    {
        "name": "Weak FortiGuard Source",
        "pattern": r"set\s+source-ip\s+0\.0\.0\.0|set\s+use-fortiguard-anycast\s+disable",
        "description": "FortiGuard service configuration may not use secure sources.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 4.6,
        "context_required": True,
        "context_check": r"config\s+system\s+fortiguard",
        "exclude_patterns": [r"#.*set\s+source-ip", r"#.*set\s+use-fortiguard-anycast"]
    },
    
    # User Authentication and Identity
    {
        "name": "RADIUS Shared Secret Weak",
        "pattern": r"set\s+secret\s+(password|secret|123456|admin|test)",
        "description": "RADIUS shared secret appears to use weak/default value.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.1,
        "context_required": True,
        "context_check": r"config\s+user\s+radius",
        "exclude_patterns": [r"#.*set\s+secret"]
    },
    {
        "name": "LDAP Over Unencrypted Connection",
        "pattern": r"set\s+port\s+389(?:\s|$)|set\s+secure\s+disable",
        "description": "LDAP authentication over unencrypted connection (port 389).",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.1,
        "context_required": True,
        "context_check": r"config\s+user\s+ldap",
        "exclude_patterns": [r"#.*set\s+port\s+389", r"#.*set\s+secure\s+disable"]
    },
    {
        "name": "Local User Password Never Expires",
        "pattern": r"set\s+password-expire\s+0|unset\s+password-expire",
        "description": "Local user passwords should have expiration policies.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "score": 5.4,
        "context_required": True,
        "context_check": r"config\s+user\s+local",
        "exclude_patterns": [r"#.*set\s+password-expire", r"#.*unset\s+password-expire"]
    },
    
    # NAT and Port Forwarding Security
    {
        "name": "Unrestricted Port Forwarding",
        "pattern": r"set\s+portforward\s+enable.*\n(?:(?!set\s+srcaddr).*\n)*",
        "description": "Port forwarding without source address restrictions.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
        "score": 8.5,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+portforward"]
    },
    {
        "name": "NAT Without Logging",
        "pattern": r"set\s+nat\s+enable.*\n(?:(?!set\s+logtraffic).*\n)*",
        "description": "NAT translation without traffic logging reduces audit capability.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
        "score": 3.7,
        "context_required": True,
        "context_check": r"config\s+firewall\s+policy",
        "exclude_patterns": [r"#.*set\s+nat"]
    },
    
    # Certificate and PKI Additional Checks
    {
        "name": "Self-Signed Certificates",
        "pattern": r"set\s+type\s+regular.*\n(?:(?!set\s+ca).*\n)*",
        "description": "Self-signed certificates provide weaker trust validation.",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": 5.0,
        "context_required": True,
        "context_check": r"config\s+vpn\s+certificate\s+local",
        "exclude_patterns": [r"#.*set\s+type"]
    },
    {
        "name": "Certificate Validity Too Long",
        "pattern": r"set\s+end-date\s+.*(?:203[0-9]|204[0-9]|20[5-9][0-9])",
        "description": "Certificate validity period is excessively long (>10 years).",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": 4.4,
        "context_required": True,
        "context_check": r"config\s+vpn\s+certificate",
        "exclude_patterns": [r"#.*set\s+end-date"]
    },
    
    # Web Proxy and Content Filtering
    {
        "name": "Web Proxy Without Authentication",
        "pattern": r"set\s+status\s+enable.*\n(?:(?!set\s+auth).*\n)*",
        "description": "Web proxy enabled without user authentication.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "score": 6.9,
        "context_required": True,
        "context_check": r"config\s+web-proxy",
        "exclude_patterns": [r"#.*set\s+status"]
    },
    {
        "name": "Unsafe Content Types Allowed",
        "pattern": r"set\s+options\s+.*(?:activex|java|cookie|script)",
        "description": "Potentially unsafe web content types are allowed through proxy.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "score": 6.1,
        "context_required": True,
        "context_check": r"config\s+web-proxy",
        "exclude_patterns": [r"#.*set\s+options"]
    },
    
    # DoS Protection and Rate Limiting
    {
        "name": "DoS Protection Disabled",
        "pattern": r"set\s+anomaly\s+disable|set\s+tcp-syn-flood\s+disable",
        "description": "Denial of Service protection features are disabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "score": 7.5,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+anomaly", r"#.*set\s+tcp-syn-flood"]
    },
    {
        "name": "Connection Limits Too High",
        "pattern": r"set\s+tcp-session-without-syn\s+(allow|bypass)|set\s+tcp-half-open-timer\s+([6-9][0-9]|[1-9][0-9]{2,})",
        "description": "TCP connection limits are too permissive, enabling DoS attacks.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "score": 5.3,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+tcp-session-without-syn", r"#.*set\s+tcp-half-open-timer"]
    },
    
    # Firmware and System Security
    {
        "name": "Auto-Install Firmware Disabled",
        "pattern": r"set\s+auto-install\s+disable",
        "description": "Automatic firmware installation should be enabled for security patches.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L",
        "score": 4.9,
        "context_required": True,
        "context_check": r"config\s+system\s+auto-install",
        "exclude_patterns": [r"#.*set\s+auto-install"]
    },
    {
        "name": "Kernel Crash Dump Enabled",
        "pattern": r"set\s+kernel-crashlog\s+enable",
        "description": "Kernel crash dumps may contain sensitive information.",
        "cvss": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "score": 2.3,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+kernel-crashlog"]
    },
    
    # BGP and Routing Security
    {
        "name": "BGP Route Dampening Disabled",
        "pattern": r"set\s+dampening\s+disable",
        "description": "BGP route dampening is disabled - this can lead to route flapping issues.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "score": 4.3,
        "context_required": True,
        "context_check": r"config\s+router\s+bgp",
        "exclude_patterns": [r"#.*set\s+dampening\s+disable"]
    },
    {
        "name": "BGP Without Route Filtering",
        "pattern": r"set\s+neighbor\s+.*\n(?:(?!set\s+(?:route-map|prefix-list|filter-list)).*\n)*",
        "description": "BGP neighbor configured without route filtering.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.8,
        "context_required": True,
        "context_check": r"config\s+router\s+bgp",
        "exclude_patterns": [r"#.*set\s+neighbor"]
    },
    
    # Time Synchronization Security
    {
        "name": "No Time Synchronization Configured",
        "pattern": r"set\s+ntpsync\s+disable|unset\s+ntpsync",
        "description": "Time synchronization is not configured, affecting logging and certificate validation.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+ntpsync", r"#.*unset\s+ntpsync"]
    },
    {
        "name": "NTP Server Not Secured",
        "pattern": r"set\s+ntpserver\s+.*\n(?:(?!set\s+authentication).*\n)*",
        "description": "NTP server configured without authentication.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.8,
        "context_required": True,
        "context_check": r"config\s+system\s+ntp",
        "exclude_patterns": [r"#.*set\s+ntpserver"]
    },
    {
        "name": "NTP Sync Interval Too Long",
        "pattern": r"set\s+syncinterval\s+([3-9][0-9]{3,}|[1-9][0-9]{4,})",
        "description": "NTP sync interval is too long (>3600 seconds).",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
        "score": 3.7,
        "context_required": True,
        "context_check": r"config\s+system\s+ntp",
        "exclude_patterns": [r"#.*set\s+syncinterval"]
    },
    
    # SNMP Security Enhanced
    {
        "name": "Clear-Text SNMP In Use",
        "pattern": r"set\s+version\s+(v1|v2c)|set\s+security-level\s+noauth",
        "description": "Clear-text SNMP (v1/v2c) or unauthenticated SNMPv3 in use.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "context_required": True,
        "context_check": r"config\s+system\s+snmp",
        "exclude_patterns": [r"#.*set\s+version", r"#.*set\s+security-level"]
    },
    {
        "name": "SNMP Write Access Enabled",
        "pattern": r"set\s+status\s+enable.*\n(?:(?!set\s+trap-status).*\n)*",
        "description": "SNMP write access may be enabled without proper restrictions.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
        "score": 7.8,
        "context_required": True,
        "context_check": r"config\s+system\s+snmp\s+community",
        "exclude_patterns": [r"#.*set\s+status"]
    },
    {
        "name": "SNMP Default Location/Contact",
        "pattern": r"set\s+contact-info\s+(\"\"|admin|administrator)|set\s+location\s+(\"\"|unknown|default)",
        "description": "SNMP contact info or location contains default/empty values.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 3.1,
        "context_required": True,
        "context_check": r"config\s+system\s+snmp",
        "exclude_patterns": [r"#.*set\s+contact-info", r"#.*set\s+location"]
    },
    
    # Password Policy Security
    {
        "name": "Weak Password Age Policy Setting",
        "pattern": r"set\s+password-expire-days\s+([0-9]|[1-2][0-9]|3[0-9])(\s|$)|set\s+password-expire-days\s+0",
        "description": "Password expiration period is too short (<40 days) or disabled.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "score": 5.4,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+password-expire-days"]
    },
    {
        "name": "Weak Password Complexity Policy Setting",
        "pattern": r"set\s+strong-crypto\s+disable|set\s+password-policy\s+disable|set\s+min-password-length\s+[1-7](\s|$)",
        "description": "Password complexity requirements are disabled or too weak.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "score": 6.5,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+strong-crypto", r"#.*set\s+password-policy", r"#.*set\s+min-password-length"]
    },
    {
        "name": "Password History Not Enforced",
        "pattern": r"set\s+password-history\s+[0-2](\s|$)|unset\s+password-history",
        "description": "Password history is not enforced or set too low (<3 passwords).",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "score": 4.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+password-history", r"#.*unset\s+password-history"]
    },
    
    # Login Banner and Security Messaging
    {
        "name": "No Pre-Logon Banner Message",
        "pattern": r"unset\s+pre-login-banner|set\s+pre-login-banner\s+(\"\"|disable)",
        "description": "Pre-login banner is not configured to display security warnings.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "score": 3.1,
        "context_required": False,
        "exclude_patterns": [r"#.*unset\s+pre-login-banner", r"#.*set\s+pre-login-banner"]
    },
    {
        "name": "No Post-Login Banner Message",
        "pattern": r"unset\s+post-login-banner|set\s+post-login-banner\s+(\"\"|disable)",
        "description": "Post-login banner is not configured to display usage policies.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "score": 2.8,
        "context_required": False,
        "exclude_patterns": [r"#.*unset\s+post-login-banner", r"#.*set\s+post-login-banner"]
    },
    {
        "name": "Insecure Login Disclaimer",
        "pattern": r"set\s+login-disclaimer\s+disable",
        "description": "Login disclaimer is disabled, may affect legal compliance.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "score": 2.8,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+login-disclaimer"]
    },
    
    # Session and Connection Security
    {
        "name": "Excessive Login Retry Attempts",
        "pattern": r"set\s+login-retry\s+([1-9][0-9]|[1-9][0-9]{2,})",
        "description": "Login retry attempts are set too high (>10), enabling brute force attacks.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": 6.1,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+login-retry"]
    },
    {
        "name": "No Connection Rate Limiting",
        "pattern": r"unset\s+tcp-option|set\s+tcp-option\s+disable",
        "description": "TCP connection rate limiting is not configured.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "score": 4.3,
        "context_required": False,
        "exclude_patterns": [r"#.*unset\s+tcp-option", r"#.*set\s+tcp-option"]
    },
    
    # Certificate and Encryption Security
    {
        "name": "Weak Diffie-Hellman Parameters",
        "pattern": r"set\s+dh-group\s+[1-4](\s|$)|set\s+dhgrp\s+[1-4](\s|$)",
        "description": "Weak Diffie-Hellman groups (1-4) are vulnerable to attacks.",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 7.4,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+dh-group", r"#.*set\s+dhgrp"]
    },
    {
        "name": "Certificate Not Verified",
        "pattern": r"set\s+cert-validation\s+disable|set\s+check-ca-cert\s+disable",
        "description": "Certificate validation is disabled for connections.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.1,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+cert-validation", r"#.*set\s+check-ca-cert"]
    },
    
    # Management Interface Security
    {
        "name": "Management Interface Unrestricted",
        "pattern": r"set\s+allowaccess\s+.*(?:ping|http|telnet|ssh|snmp|https|ssh|fgfm).*\n(?:(?!set\s+ip).*\n)*",
        "description": "Management interface allows access without IP restrictions.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "context_required": True,
        "context_check": r"config\s+system\s+interface",
        "exclude_patterns": [r"#.*set\s+allowaccess"]
    },
    {
        "name": "Dedicated Management Interface Missing",
        "pattern": r"set\s+dedicated-to\s+management\s+disable|unset\s+dedicated-to",
        "description": "No dedicated management interface configured.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "score": 5.4,
        "context_required": True,
        "context_check": r"config\s+system\s+interface",
        "exclude_patterns": [r"#.*set\s+dedicated-to", r"#.*unset\s+dedicated-to"]
    },
    
    # System Information Disclosure
    {
        "name": "System Information Disclosure",
        "pattern": r"set\s+hostname\s+(fortigate|default|firewall|fw|test)|set\s+description\s+(\"\"|default)",
        "description": "System uses default hostname or empty description revealing device type.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 3.1,
        "context_required": False,
        "exclude_patterns": [r"#.*set\s+hostname", r"#.*set\s+description"]
    },
    {
        "name": "SNMP System Info Disclosure",
        "pattern": r"set\s+description\s+(\"\"|default|fortigate|firewall)",
        "description": "SNMP system description reveals default or sensitive information.",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 3.7,
        "context_required": True,
        "context_check": r"config\s+system\s+snmp",
        "exclude_patterns": [r"#.*set\s+description"]
    }
]

# CSV-specific checks for firewall policy analysis
CSV_POLICY_CHECKS = [
    {
        "name": "Overly Permissive Source (Any/All)",
        "description": "Firewall rule allows traffic from any source (all)",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
        "score": 8.5,
        "check_function": lambda row: row.get('Source', '').lower() in ['all', 'any', '0.0.0.0/0', '::/0']
    },
    {
        "name": "Overly Permissive Destination (Any/All)",
        "description": "Firewall rule allows traffic to any destination (all)",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
        "score": 8.5,
        "check_function": lambda row: row.get('Destination', '').lower() in ['all', 'any', '0.0.0.0/0', '::/0']
    },
    {
        "name": "Allow All Services",
        "description": "Firewall rule allows all services/ports",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L", 
        "score": 8.0,
        "check_function": lambda row: row.get('Service', '').upper() in ['ALL', 'ANY']
    },
    {
        "name": "Accept All Traffic Rule",
        "description": "Rule accepts traffic from all sources to all destinations with all services",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "score": 9.8,
        "check_function": lambda row: (
            row.get('Source', '').lower() in ['all', 'any'] and
            row.get('Destination', '').lower() in ['all', 'any'] and
            row.get('Service', '').upper() in ['ALL', 'ANY'] and
            row.get('Action', '').upper() == 'ACCEPT'
        )
    },
    {
        "name": "No Security Profiles Applied",
        "description": "Firewall rule has no security profiles (AV, IPS, web filtering) enabled",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 5.8,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'ACCEPT' and
            (not row.get('Security Profiles') or 
             row.get('Security Profiles', '').lower() in ['', 'no-inspection', 'none'])
        )
    },
    {
        "name": "Traffic Logging Disabled",
        "description": "Traffic logging is disabled for firewall rule",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
        "score": 3.1,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'ACCEPT' and
            row.get('Log', '').lower() in ['disabled', 'no', 'false', '']
        )
    },
    {
        "name": "High-Risk Service Allowed",
        "description": "Rule allows high-risk services like Telnet, FTP, SNMP",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.8,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'ACCEPT' and
            any(service.lower() in row.get('Service', '').lower() 
                for service in ['telnet', 'ftp', 'snmp', 'rsh', 'rlogin'])
        )
    },
    {
        "name": "RDP from External Sources",
        "description": "RDP access allowed from external/untrusted sources",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'ACCEPT' and
            'rdp' in row.get('Service', '').lower() and
            (row.get('Source', '').lower() in ['all', 'any', 'internet'] or
             'external' in row.get('Source', '').lower())
        )
    },
    {
        "name": "SSH from External Sources", 
        "description": "SSH access allowed from external/untrusted sources",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'ACCEPT' and
            'ssh' in row.get('Service', '').lower() and
            (row.get('Source', '').lower() in ['all', 'any', 'internet'] or
             'external' in row.get('Source', '').lower())
        )
    },
    {
        "name": "Database Access from DMZ/External",
        "description": "Database services accessible from DMZ or external networks",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.8,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'ACCEPT' and
            any(db_service in row.get('Service', '').lower() 
                for db_service in ['sql', 'mysql', 'postgres', 'oracle', 'mongodb']) and
            (row.get('Source', '').lower() in ['all', 'any', 'dmz', 'external'] or
             'dmz' in row.get('Source', '').lower() or 'external' in row.get('Source', '').lower())
        )
    },
    {
        "name": "Weak Security Profile",
        "description": "Rule uses weak security profiles or no-inspection",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "score": 5.1,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'ACCEPT' and
            row.get('Security Profiles', '').lower() in ['no-inspection', 'none', 'basic']
        )
    },
    {
        "name": "NAT Enabled Without Restriction",
        "description": "NAT is enabled on rule without proper source/destination restrictions",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": 6.1,
        "check_function": lambda row: (
            row.get('NAT', '').lower() in ['enabled', 'enable', 'yes', 'true'] and
            (row.get('Source', '').lower() in ['all', 'any'] or
             row.get('Destination', '').lower() in ['all', 'any'])
        )
    },
    {
        "name": "Deny Rule Without Logging",
        "description": "Deny rule without logging - security incidents may go unnoticed",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
        "score": 3.7,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'DENY' and
            row.get('Log', '').lower() in ['disabled', 'no', 'false', '']
        )
    },
    {
        "name": "Administrative Services Exposed",
        "description": "Administrative services (WMI, SNMP, etc.) exposed to wide networks",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.8,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'ACCEPT' and
            any(admin_service in row.get('Service', '').lower() 
                for admin_service in ['wmi', 'snmp', 'winrm', 'dcom']) and
            not any(trusted in row.get('Source', '').lower() 
                   for trusted in ['mgmt', 'admin', 'jump', 'bastion'])
        )
    },
    {
        "name": "Always Schedule Risk",
        "description": "Rule is always active - no time-based restrictions",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": 4.3,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'ACCEPT' and
            row.get('Schedule', '').lower() == 'always' and
            (row.get('Source', '').lower() in ['all', 'any'] or
             row.get('Destination', '').lower() in ['all', 'any'])
        )
    },
    {
        "name": "High Traffic Volume Rule",
        "description": "Rule has processed very high traffic volume - review for abuse",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "score": 4.6,
        "check_function": lambda row: (
            row.get('Action', '').upper() == 'ACCEPT' and
            parse_bytes(row.get('Bytes', '0')) > 1024 * 1024 * 1024 * 10  # >10GB
        )
    }
]

def extract_firewall_name_from_config(content):
    """
    Extract firewall hostname from configuration content.
    Looks for hostname settings in various formats.
    """
    if not content:
        return "Unknown"
    
    lines = content.splitlines()
    
    # Track if we're in a system global configuration context
    in_system_global = False
    
    for line in lines:
        line_stripped = line.strip()
        
        # Skip commented lines
        if line_stripped.startswith('#') or line_stripped.startswith('!'):
            continue
        
        # Check for system global configuration context
        if re.match(r'^config\s+system\s+global', line_stripped, re.IGNORECASE):
            in_system_global = True
            continue
        elif line_stripped.lower() == 'end' and in_system_global:
            in_system_global = False
            continue
        elif line_stripped.startswith('config ') and in_system_global:
            in_system_global = False
        
        # Look for hostname in system global context first (most reliable)
        if in_system_global:
            hostname_match = re.search(r'^\s*set\s+hostname\s+"([^"]+)"', line, re.IGNORECASE)
            if not hostname_match:
                hostname_match = re.search(r'^\s*set\s+hostname\s+([^\s]+)$', line, re.IGNORECASE)
            
            if hostname_match:
                hostname = hostname_match.group(1).strip()
                if (hostname and 
                    len(hostname) > 2 and  # At least 3 characters
                    hostname.lower() not in ['fortigate', 'firewall', 'fw', 'default', 'localhost', 'host', 
                                           'enable', 'disable', 'yes', 'no', 'true', 'false', 'logon'] and
                    not hostname.isdigit() and  # Not just a number
                    '"' not in hostname):       # No quote characters
                    return hostname
    
    # If no hostname found in system global, look for standalone hostname commands
    hostname_patterns = [
        r'^\s*hostname\s+"([^"]+)"',        # hostname "fw-name" (quoted)
        r'^\s*hostname\s+([^\s]+)$',        # hostname fw-name (unquoted)
    ]
    
    for line in lines:
        line_stripped = line.strip()
        
        # Skip commented lines and lines that look like they're in other contexts
        if (line_stripped.startswith('#') or line_stripped.startswith('!') or
            'edit ' in line_stripped or 'config ' in line_stripped):
            continue
            
        for pattern in hostname_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                hostname = match.group(1).strip()
                if (hostname and 
                    len(hostname) > 2 and
                    hostname.lower() not in ['fortigate', 'firewall', 'fw', 'default', 'localhost', 'host', 
                                           'enable', 'disable', 'yes', 'no', 'true', 'false', 'logon'] and
                    not hostname.isdigit() and
                    '"' not in hostname):
                    return hostname
    
    return "Unknown"

def extract_firewall_name_from_csv_filename(filename):
    """
    Extract firewall name from CSV filename (fallback for CSV files).
    Examples: 
    - "glo-fw-31802-01-1.csv" -> "glo-fw-31802-01-1"
    - "Azure UK South Firewall Config.csv" -> "Azure UK South Firewall"
    """
    basename = os.path.basename(filename)
    
    # Remove common file extensions
    name_without_ext = re.sub(r'\.(csv|txt|conf|cfg|config|log)$', '', basename, flags=re.IGNORECASE)
    
    # Clean up common suffixes
    name_cleaned = re.sub(r'\s+(Config|Configuration|Firewall|Rules?|Policy|Policies|Ruleset)$', '', name_without_ext, flags=re.IGNORECASE)
    
    # If the result is too short or generic, use the original basename without extension
    if len(name_cleaned) < 3 or name_cleaned.lower() in ['firewall', 'config', 'fw', 'policy', 'policies']:
        return name_without_ext
    
    return name_cleaned.strip()

def extract_firewall_name(filename):
    """
    Extract firewall name from filename.
    Examples: 
    - "glo-fw-31802-01-1.txt" -> "glo-fw-31802-01-1"
    - "Azure UK South Firewall Config.txt" -> "Azure UK South Firewall"
    - "fw-config.txt" -> "fw-config"
    """
    basename = os.path.basename(filename)
    
    # Remove common file extensions
    name_without_ext = re.sub(r'\.(txt|conf|cfg|config|log)$', '', basename, flags=re.IGNORECASE)
    
    # Clean up common suffixes
    name_cleaned = re.sub(r'\s+(Config|Configuration|Firewall|Rules?|Policy|Policies)$', '', name_without_ext, flags=re.IGNORECASE)
    
    # If the result is too short or generic, use the original basename without extension
    if len(name_cleaned) < 3 or name_cleaned.lower() in ['firewall', 'config', 'fw', 'policy']:
        return name_without_ext
    
    return name_cleaned.strip()

def parse_bytes(byte_str):
    """Parse byte string like '15.98 TB' into bytes"""
    if not byte_str or byte_str == '0 B':
        return 0
    
    # Remove commas and split
    byte_str = byte_str.replace(',', '').strip()
    if byte_str == '0':
        return 0
        
    # Extract number and unit
    parts = byte_str.split()
    if len(parts) != 2:
        return 0
        
    try:
        value = float(parts[0])
        unit = parts[1].upper()
        
        multipliers = {
            'B': 1,
            'KB': 1024,
            'MB': 1024**2,
            'GB': 1024**3,
            'TB': 1024**4
        }
        
        return int(value * multipliers.get(unit, 1))
    except (ValueError, KeyError):
        return 0

def analyze_csv_policies(csv_file):
    """Analyze firewall policies from CSV file"""
    issues = []
    
    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            # Try to detect delimiter
            sample = f.read(1024)
            f.seek(0)
            
            delimiter = ','
            if sample.count('\t') > sample.count(','):
                delimiter = '\t'
            
            reader = csv.DictReader(f, delimiter=delimiter)
            
            for row_num, row in enumerate(reader, start=2):  # Start at 2 because of header
                # Clean up the row data
                row = {k.strip(): v.strip() if v else '' for k, v in row.items()}
                
                # Skip empty rows or implicit deny (often at end)
                if not row.get('Name') or 'implicit deny' in row.get('Name', '').lower():
                    continue
                
                # Run each CSV check
                for check in CSV_POLICY_CHECKS:
                    try:
                        if check['check_function'](row):
                            issues.append({
                                "issue": check["name"],
                                "description": check["description"],
                                "cvss": check["cvss"],
                                "score": check["score"],
                                "filename": os.path.basename(csv_file),
                                "firewall_name": extract_firewall_name_from_csv_filename(csv_file),
                                "line": f"Policy: {row.get('Name', 'Unknown')}",
                                "lineno": row_num,
                                "occurrence_id": f"{check['name']}_{row_num}",  # Unique ID for each occurrence
                                "policy_details": {
                                    "name": row.get('Name', ''),
                                    "source": row.get('Source', ''),
                                    "destination": row.get('Destination', ''),
                                    "service": row.get('Service', ''),
                                    "action": row.get('Action', ''),
                                    "nat": row.get('NAT', ''),
                                    "security_profiles": row.get('Security Profiles', ''),
                                    "log": row.get('Log', ''),
                                    "bytes": row.get('Bytes', '')
                                }
                            })
                    except Exception as e:
                        # Skip checks that fail due to missing columns
                        continue
                        
    except Exception as e:
        print(f"❌ Error analyzing CSV file {csv_file}: {str(e)}")
        
    return issues

def find_issues(content, filename):
    """
    Enhanced issue detection with context validation and false positive reduction.
    """
    issues = []
    
    # Check if this is a CSV file
    if filename.lower().endswith('.csv'):
        return analyze_csv_policies(filename)
    
    # Extract firewall name from config content
    firewall_name = extract_firewall_name_from_config(content)
    
    # Original text-based analysis for config files
    lines = content.splitlines()
    
    for check in CHECKS:
        pattern = re.compile(check["pattern"], re.IGNORECASE | re.MULTILINE)
        exclude_patterns = [re.compile(ep, re.IGNORECASE) for ep in check.get("exclude_patterns", [])]
        
        # Check if this pattern requires context validation
        context_required = check.get("context_required", False)
        context_check = check.get("context_check", "")
        
        for idx, line in enumerate(lines, 1):
            # Skip if line matches any exclude pattern (e.g., commented lines)
            if any(ep.search(line) for ep in exclude_patterns):
                continue
                
            if pattern.search(line):
                # If context is required, validate the context
                if context_required and context_check:
                    if not validate_context(lines, idx - 1, context_check):
                        continue
                
                # Additional validation for specific checks
                if not additional_validation(check["name"], line, lines, idx - 1):
                    continue
                    
                issues.append({
                    "issue": check["name"],
                    "description": check["description"],
                    "cvss": check["cvss"],
                    "score": check["score"],
                    "filename": os.path.basename(filename),
                    "firewall_name": firewall_name,
                    "line": line.strip(),
                    "lineno": idx,
                    "occurrence_id": f"{check['name']}_{idx}"  # Unique ID for each occurrence
                })
    return issues

def validate_context(lines, line_idx, context_pattern):
    """
    Validate that a detected issue is within the correct configuration context.
    Looks backwards from the current line to find the context.
    """
    context_regex = re.compile(context_pattern, re.IGNORECASE)
    
    # Look backwards up to 50 lines for context
    for i in range(max(0, line_idx - 50), line_idx):
        if context_regex.search(lines[i]):
            # Check if we've entered a different config block
            for j in range(i + 1, line_idx):
                if lines[j].strip().startswith("config ") and not context_regex.search(lines[j]):
                    return False
            return True
    return False

def additional_validation(check_name, line, lines, line_idx):
    """
    Additional validation logic for specific checks to reduce false positives.
    """
    
    # For "Any Source/Destination" check, be more specific about firewall contexts
    if check_name == "Overly Permissive Firewall Rules":
        # Only flag if we're clearly in a firewall policy context
        if not any("firewall policy" in lines[max(0, line_idx - 10):line_idx + 1][i].lower() 
                  for i in range(len(lines[max(0, line_idx - 10):line_idx + 1]))):
            return False
    
    # For SSL/TLS version checks, ensure it's actually enabling weak versions
    if check_name == "SSL v3 or TLS v1.0/v1.1 Enabled":
        # Don't flag if the line is actually disabling these versions
        if "disable" in line.lower() or "off" in line.lower():
            return False
    
    # For cipher checks, ensure weak ciphers are actually being enabled
    if check_name == "Weak Ciphers Allowed":
        # Don't flag if the line is in a context that disables these ciphers
        if "disable" in line.lower() or "exclude" in line.lower():
            return False
    
    # For password policy checks, validate the actual value
    if check_name == "Password Policy Weak":
        if "min-password-length" in line:
            # Extract the number and validate it's actually weak
            match = re.search(r"min-password-length\s+(\d+)", line)
            if match and int(match.group(1)) >= 8:
                return False
    
    # For admin login limits, be more conservative about what's "too many"
    if check_name == "Too Many Admin Logins":
        match = re.search(r"admin-login-max\s+(\d+)", line)
        if match and int(match.group(1)) <= 50:  # More conservative threshold
            return False
    
    # For SSH grace time, be more conservative
    if check_name == "Excessive SSH Grace Time":
        match = re.search(r"admin-ssh-grace-time\s+(\d+)", line)
        if match and int(match.group(1)) <= 300:  # 5 minutes is reasonable
            return False
    
    # For log buffer size, ensure it's actually too small
    if check_name == "Log Buffer Too Small":
        match = re.search(r"buffer-size\s+(\d+)", line)
        if match and int(match.group(1)) >= 64:  # 64KB or more is acceptable
            return False
    
    # For certificate validity, check if date is actually in the far future
    if check_name == "Certificate Validity Too Long":
        # Only flag if it's genuinely a very long validity period
        current_year = 2025  # Update this as needed
        if str(current_year + 5) not in line:  # Less than 5 years is probably OK
            return False
    
    # For connection limits, validate actual values
    if check_name == "Connection Limits Too High":
        if "tcp-half-open-timer" in line:
            match = re.search(r"tcp-half-open-timer\s+(\d+)", line)
            if match and int(match.group(1)) <= 60:  # 60 seconds is reasonable
                return False
    
    # For RADIUS secret, only flag obvious weak passwords
    if check_name == "RADIUS Shared Secret Weak":
        # Don't flag if it looks like a placeholder or configuration reference
        if any(keyword in line.lower() for keyword in ["$", "var", "config", "reference"]):
            return False
    
    # For password expiration, validate the actual value
    if check_name == "Weak Password Age Policy Setting":
        if "password-expire-days" in line:
            match = re.search(r"password-expire-days\s+(\d+)", line)
            if match:
                days = int(match.group(1))
                # Consider 90+ days as acceptable
                if days >= 90:
                    return False
    
    # For login retry attempts, be more conservative
    if check_name == "Excessive Login Retry Attempts":
        match = re.search(r"login-retry\s+(\d+)", line)
        if match and int(match.group(1)) <= 10:  # 10 or fewer attempts is reasonable
            return False
    
    # For NTP sync interval, validate actual value
    if check_name == "NTP Sync Interval Too Long":
        match = re.search(r"syncinterval\s+(\d+)", line)
        if match and int(match.group(1)) <= 3600:  # 1 hour is reasonable
            return False
    
    # For hostname checks, don't flag if it's clearly customized
    if check_name == "System Information Disclosure":
        if "hostname" in line:
            # Don't flag if hostname contains organization-specific terms
            if any(term in line.lower() for term in ["corp", "company", "org", "ltd", "inc", "gmbh"]):
                return False
    
    return True

def generate_html_report(grouped_issues, all_issues, output_file="firewall_audit_report.html"):
    """
    Generate comprehensive HTML report with enhanced styling and analytics.
    """
    with open(output_file, "w") as f:
        f.write("""<html><head>
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; background-color: #f5f5f5; }
.container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
h2 { color: #34495e; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 15px; }
.summary { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
.risk-high { background-color: #e74c3c; color: white; }
.risk-medium { background-color: #f39c12; color: white; }
.risk-low { background-color: #27ae60; color: white; }
.risk-info { background-color: #3498db; color: white; }
table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
th, td { border: 1px solid #bdc3c7; padding: 12px; text-align: left; }
th { background-color: #34495e; color: white; font-weight: bold; }
tr:nth-child(even) { background-color: #f8f9fa; }
tr:hover { background-color: #e8f4f8; }
.score-critical { background-color: #c0392b; color: white; font-weight: bold; }
.score-high { background-color: #e74c3c; color: white; font-weight: bold; }
.score-medium { background-color: #f39c12; color: white; font-weight: bold; }
.score-low { background-color: #27ae60; color: white; font-weight: bold; }
.stats { display: flex; justify-content: space-around; margin: 20px 0; }
.stat-box { text-align: center; padding: 20px; border-radius: 5px; flex: 1; margin: 0 10px; }
.file-count { background: #3498db; color: white; }
.issue-count { background: #e74c3c; color: white; }
.avg-score { background: #f39c12; color: white; }
code { background: #ecf0f1; padding: 2px 5px; border-radius: 3px; font-family: 'Courier New', monospace; }
.cvss-vector { font-family: 'Courier New', monospace; font-size: 11px; color: #7f8c8d; word-break: break-all; }
</style>
</head><body><div class="container">""")
        
        f.write("<h1>🔒 Firewall Configuration Security Audit Report</h1>")
        
        # Calculate statistics
        total_issues = len(all_issues)
        total_files = len(set(issue["filename"] for issue in all_issues))
        avg_score = sum(issue["score"] for issue in all_issues) / total_issues if total_issues > 0 else 0
        
        critical_issues = [i for i in all_issues if i["score"] >= 9.0]
        high_issues = [i for i in all_issues if 7.0 <= i["score"] < 9.0]
        medium_issues = [i for i in all_issues if 4.0 <= i["score"] < 7.0]
        low_issues = [i for i in all_issues if i["score"] < 4.0]
        
        # Summary statistics
        f.write(f"""<div class="summary">
<h2>📊 Executive Summary</h2>
<div class="stats">
    <div class="stat-box file-count">
        <h3>{total_files}</h3>
        <p>Files Analyzed</p>
    </div>
    <div class="stat-box issue-count">
        <h3>{total_issues}</h3>
        <p>Total Issues</p>
    </div>
    <div class="stat-box avg-score">
        <h3>{avg_score:.1f}</h3>
        <p>Average CVSS Score</p>
    </div>
</div>
<p><strong>Risk Distribution:</strong> 
🔴 Critical: {len(critical_issues)} | 
🟠 High: {len(high_issues)} | 
🟡 Medium: {len(medium_issues)} | 
🟢 Low: {len(low_issues)}
</p>
</div>""")

        # Risk breakdown
        f.write("<h2>🎯 Risk Assessment by Severity</h2><table>")
        f.write("<tr><th>Severity</th><th>Count</th><th>CVSS Range</th><th>Issues</th></tr>")
        
        severity_data = [
            ("Critical", len(critical_issues), "9.0 - 10.0", "score-critical"),
            ("High", len(high_issues), "7.0 - 8.9", "score-high"),
            ("Medium", len(medium_issues), "4.0 - 6.9", "score-medium"),
            ("Low", len(low_issues), "0.0 - 3.9", "score-low")
        ]
        
        for severity, count, cvss_range, css_class in severity_data:
            f.write(f"<tr><td class='{css_class}'>{severity}</td><td>{count}</td><td>{cvss_range}</td><td>")
            issues_of_severity = [i for i in all_issues if 
                                (severity == "Critical" and i["score"] >= 9.0) or
                                (severity == "High" and 7.0 <= i["score"] < 9.0) or
                                (severity == "Medium" and 4.0 <= i["score"] < 7.0) or
                                (severity == "Low" and i["score"] < 4.0)]
            unique_issues = list(set(i["issue"] for i in issues_of_severity))
            f.write(", ".join(unique_issues[:3]))
            if len(unique_issues) > 3:
                f.write(f" (+{len(unique_issues) - 3} more)")
            f.write("</td></tr>")
        f.write("</table>")

        # Grouped issues by type with occurrence details
        f.write("<h2>📋 Issues Grouped by Type</h2><table>")
        f.write("<tr><th>Issue Type</th><th>Description</th><th>CVSS Score</th><th>Files Affected</th><th>Total Occurrences</th><th>Line Numbers</th></tr>")
        
        for issue_name, entries in sorted(grouped_issues.items(), key=lambda x: x[1][0]["score"], reverse=True):
            filenames = sorted(set(e["filename"] for e in entries))
            description = entries[0]["description"]
            score = entries[0]["score"]
            cvss = entries[0]["cvss"]
            
            # Group line numbers by firewall/file
            line_numbers_by_file = {}
            for entry in entries:
                file_key = f"{entry.get('firewall_name', 'Unknown')} ({entry['filename']})"
                if file_key not in line_numbers_by_file:
                    line_numbers_by_file[file_key] = []
                line_numbers_by_file[file_key].append(str(entry['lineno']))
            
            # Format line numbers display
            line_numbers_display = "<br>".join([
                f"<small><strong>{file_key}:</strong> Lines {', '.join(sorted(lines, key=int))}</small>"
                for file_key, lines in line_numbers_by_file.items()
            ])
            
            # Determine CSS class based on score
            css_class = ("score-critical" if score >= 9.0 else
                        "score-high" if score >= 7.0 else
                        "score-medium" if score >= 4.0 else
                        "score-low")
            
            f.write(f"""<tr>
<td><strong>{escape(issue_name)}</strong></td>
<td>{escape(description)}</td>
<td class='{css_class}'>{score}<br><span class='cvss-vector'>{escape(cvss)}</span></td>
<td>{', '.join(filenames)}</td>
<td><strong>{len(entries)}</strong></td>
<td>{line_numbers_display}</td>
</tr>""")
        f.write("</table>")

        # Detailed findings
        f.write("<h2>🔍 Detailed Findings</h2><table>")
        f.write("<tr><th>Firewall</th><th>File</th><th>Line #</th><th>Issue</th><th>Configuration Line</th><th>CVSS Score</th></tr>")
        
        # Sort by score descending, then by filename
        sorted_issues = sorted(all_issues, key=lambda x: (x["score"], x["filename"]), reverse=True)
        
        for entry in sorted_issues:
            score = entry["score"]
            css_class = ("score-critical" if score >= 9.0 else
                        "score-high" if score >= 7.0 else
                        "score-medium" if score >= 4.0 else
                        "score-low")
            
            # Handle CSV policy details
            if 'policy_details' in entry:
                policy = entry['policy_details']
                line_display = f"""Policy: {escape(policy['name'])}<br>
                <small>Source: {escape(policy['source'])}<br>
                Destination: {escape(policy['destination'])}<br>
                Service: {escape(policy['service'])}<br>
                Action: {escape(policy['action'])}</small>"""
            else:
                line_display = f"<code>{escape(entry['line'])}</code>"
            
            firewall_name = entry.get('firewall_name', 'Unknown')
            
            f.write(f"""<tr>
<td><strong>{escape(firewall_name)}</strong></td>
<td>{escape(entry['filename'])}</td>
<td>{entry['lineno']}</td>
<td>{escape(entry['issue'])}</td>
<td>{line_display}</td>
<td class='{css_class}'>{score}<br><span class='cvss-vector'>{escape(entry['cvss'])}</span></td>
</tr>""")
        
        f.write("</table>")
        
        # Recommendations section
        f.write("""<h2>💡 Remediation Recommendations</h2>
<div class="summary">
<h3>Priority Actions (Critical & High Risk)</h3>
<ul>
<li><strong>Disable Telnet:</strong> Use SSH exclusively for remote administration</li>
<li><strong>Update SSL/TLS:</strong> Disable SSLv3, TLS 1.0/1.1, use TLS 1.2+ only</li>
<li><strong>Enable 2FA:</strong> Implement two-factor authentication for all admin accounts</li>
<li><strong>Review Firewall Rules:</strong> Replace overly permissive 'any/all' rules with specific addresses</li>
<li><strong>Update Encryption:</strong> Replace weak ciphers with strong alternatives</li>
</ul>

<h3>Security Hardening (Medium Risk)</h3>
<ul>
<li><strong>Password Policies:</strong> Enforce minimum 12-character passwords with complexity</li>
<li><strong>Session Management:</strong> Set appropriate timeouts and login limits</li>
<li><strong>Enable Security Services:</strong> Configure IPS, antivirus, and web filtering</li>
<li><strong>Network Security:</strong> Enable anti-spoofing and disable unnecessary services</li>
</ul>

<h3>Monitoring & Compliance (Low Risk)</h3>
<ul>
<li><strong>Enable Logging:</strong> Ensure all traffic is logged for compliance and forensics</li>
<li><strong>DNS Security:</strong> Enable DNS over TLS for encrypted queries</li>
<li><strong>Time Synchronization:</strong> Secure NTP with authentication</li>
</ul>
</div>""")
        
        f.write(f"""<div style="margin-top: 30px; padding: 20px; background: #ecf0f1; border-radius: 5px;">
<p><strong>Report Generated:</strong> {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><strong>Audit Tool Version:</strong> Enhanced Firewall Security Auditor v2.0</p>
</div>""")
        
        f.write("</div></body></html>")

def generate_json_report(grouped_issues, all_issues, output_file="firewall_audit_report.json"):
    """
    Generate JSON report for programmatic analysis and integration.
    """
    import json
    from datetime import datetime
    
    report_data = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool_version": "Enhanced Firewall Security Auditor v2.0",
            "total_issues": len(all_issues),
            "total_files": len(set(issue["filename"] for issue in all_issues)),
            "average_cvss_score": sum(issue["score"] for issue in all_issues) / len(all_issues) if all_issues else 0
        },
        "risk_summary": {
            "critical": len([i for i in all_issues if i["score"] >= 9.0]),
            "high": len([i for i in all_issues if 7.0 <= i["score"] < 9.0]),
            "medium": len([i for i in all_issues if 4.0 <= i["score"] < 7.0]),
            "low": len([i for i in all_issues if i["score"] < 4.0])
        },
        "grouped_issues": {
            issue_name: {
                "description": entries[0]["description"],
                "cvss_score": entries[0]["score"],
                "cvss_vector": entries[0]["cvss"],
                "affected_files": sorted(set(e["filename"] for e in entries)),
                "occurrence_count": len(entries)
            }
            for issue_name, entries in grouped_issues.items()
        },
        "detailed_findings": all_issues
    }
    
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=2)

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Firewall Configuration Security Auditor - Supports both config files and CSV policy exports",
        epilog="""
Examples:
  python audit.py --files "*.txt"                    # Analyze text config files
  python audit.py --files "*.csv"                    # Analyze CSV policy exports
  python audit.py --files "config/*.conf" --json    # Generate JSON report
  python audit.py --files "*" --output full_audit   # Analyze all files
  
Supported Formats:
  - Text configuration files (.txt, .conf, .cfg)
  - CSV policy exports (.csv) with columns: Name,Source,Destination,Schedule,Service,Action,NAT,Security Profiles,Log,Bytes,Type
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--files", required=True, 
                       help="Glob pattern to match files, e.g., '*.txt' or 'configs/*.conf'")
    parser.add_argument("--output", default="firewall_audit_report",
                       help="Output file prefix (default: firewall_audit_report)")
    parser.add_argument("--json", action="store_true",
                       help="Also generate JSON report for programmatic analysis")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    
    args = parser.parse_args()

    # Find files matching the pattern
    files = glob.glob(args.files)
    if not files:
        print(f"❌ No files found matching pattern: {args.files}")
        return 1
    
    if args.verbose:
        print(f"🔍 Found {len(files)} files to analyze:")
        for file in files:
            print(f"  - {file}")
        print()

    all_issues = []
    grouped_issues = defaultdict(list)
    processed_files = 0
    
    for file in files:
        try:
            if args.verbose:
                print(f"📁 Analyzing: {file}")
            
            # Handle CSV files differently
            if file.lower().endswith('.csv'):
                issues = analyze_csv_policies(file)
                all_issues.extend(issues)
                
                for issue in issues:
                    grouped_issues[issue["issue"]].append(issue)
                
                if args.verbose and issues:
                    print(f"  ⚠️  Found {len(issues)} policy issues")
                elif args.verbose:
                    print(f"  ✅ No policy issues found")
            else:
                # Handle text-based config files
                with open(file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    issues = find_issues(content, file)
                    all_issues.extend(issues)
                    
                    for issue in issues:
                        grouped_issues[issue["issue"]].append(issue)
                    
                    if args.verbose and issues:
                        print(f"  ⚠️  Found {len(issues)} issues")
                    elif args.verbose:
                        print(f"  ✅ No issues found")
                    
            processed_files += 1
                
        except Exception as e:
            print(f"❌ Error processing {file}: {str(e)}")
            continue

    if not all_issues:
        print("🎉 No security issues found in the analyzed files!")
        return 0

    # Generate reports
    html_output = f"{args.output}.html"
    try:
        generate_html_report(grouped_issues, all_issues, html_output)
        print(f"📄 HTML report written to '{html_output}'")
    except Exception as e:
        print(f"❌ Error generating HTML report: {str(e)}")
        return 1

    if args.json:
        json_output = f"{args.output}.json"
        try:
            generate_json_report(grouped_issues, all_issues, json_output)
            print(f"📊 JSON report written to '{json_output}'")
        except Exception as e:
            print(f"❌ Error generating JSON report: {str(e)}")
            return 1

    # Print summary
    print(f"\n📋 Summary:")
    print(f"  Files processed: {processed_files}")
    print(f"  Total issues found: {len(all_issues)}")
    print(f"  Unique issue types: {len(grouped_issues)}")
    
    critical_count = len([i for i in all_issues if i["score"] >= 9.0])
    high_count = len([i for i in all_issues if 7.0 <= i["score"] < 9.0])
    
    if critical_count > 0:
        print(f"  🔴 Critical issues: {critical_count}")
    if high_count > 0:
        print(f"  🟠 High risk issues: {high_count}")
    
    if critical_count > 0 or high_count > 0:
        print(f"\n⚠️  Immediate attention required for critical and high-risk issues!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
