"""
Local vulnerability database for VulnScan Pro.

Contains known CVEs, insecure protocol detections, and configuration
warnings mapped to service banners and version strings.
"""
from __future__ import annotations

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFORMATIONAL"

VULNERABILITY_DATABASE: dict[str, dict] = {
    "openssh": {
        "display_name": "OpenSSH",
        "service_patterns": ["openssh", "ssh-"],
        "default_port": 22,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2023-38408",
                "name": "OpenSSH Remote Code Execution via ssh-agent",
                "affected_max_version": "9.3.1",
                "severity": CRITICAL,
                "cvss_score": 9.8,
                "description": (
                    "A critical vulnerability in OpenSSH's forwarded ssh-agent allows remote "
                    "attackers to execute arbitrary code. The ssh-agent in OpenSSH before 9.3p2 "
                    "has an insufficiently trustworthy search path that can be abused by a "
                    "compromised remote server."
                ),
                "remediation": (
                    "Upgrade OpenSSH to version 9.3p2 or later. As an immediate workaround, "
                    "disable ssh-agent forwarding by setting 'AllowAgentForwarding no' in "
                    "sshd_config and avoid using 'ssh -A'."
                ),
            },
            {
                "cve_id": "CVE-2021-41617",
                "name": "OpenSSH Privilege Escalation via Supplemental Groups",
                "affected_max_version": "8.8.0",
                "severity": HIGH,
                "cvss_score": 7.0,
                "description": (
                    "sshd in OpenSSH 6.2 through 8.x before 8.9 fails to initialize "
                    "supplemental groups when executing an AuthorizedKeysCommand or "
                    "AuthorizedPrincipalsCommand, potentially allowing privilege escalation "
                    "if those commands are run by a less-privileged user."
                ),
                "remediation": "Upgrade OpenSSH to version 8.9 or later.",
            },
            {
                "cve_id": "CVE-2020-14145",
                "name": "OpenSSH Observable Timing Discrepancy",
                "affected_max_version": "8.3.0",
                "severity": MEDIUM,
                "cvss_score": 5.9,
                "description": (
                    "OpenSSH through 8.3p1 allows observable timing discrepancy that "
                    "may allow remote attackers to determine whether a particular connection "
                    "hint (preferred encryption algorithm) was accepted."
                ),
                "remediation": "Upgrade OpenSSH to version 8.4 or later.",
            },
            {
                "cve_id": "CVE-2018-15473",
                "name": "OpenSSH Username Enumeration",
                "affected_max_version": "7.7.0",
                "severity": MEDIUM,
                "cvss_score": 5.3,
                "description": (
                    "OpenSSH through 7.7 is prone to a user enumeration vulnerability "
                    "due to not delaying bailout for an invalid authenticating user until "
                    "after the packet has been fully parsed, resulting in observable timing "
                    "differences."
                ),
                "remediation": "Upgrade OpenSSH to version 7.8 or later.",
            },
        ],
    },
    "apache": {
        "display_name": "Apache HTTP Server",
        "service_patterns": ["apache", "httpd"],
        "default_port": 80,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2021-41773",
                "name": "Apache HTTP Server Path Traversal and RCE",
                "affected_exact_version": "2.4.49",
                "severity": CRITICAL,
                "cvss_score": 9.8,
                "description": (
                    "A path traversal and remote code execution vulnerability exists in Apache "
                    "HTTP Server 2.4.49. An attacker can map URLs to files outside the configured "
                    "document root. If CGI scripts are enabled, this can lead to remote code "
                    "execution. This vulnerability was actively exploited in the wild."
                ),
                "remediation": (
                    "Upgrade Apache HTTP Server immediately to version 2.4.51 or later. "
                    "Ensure 'Require all denied' is configured for all directories."
                ),
            },
            {
                "cve_id": "CVE-2021-42013",
                "name": "Apache HTTP Server Path Traversal (Bypass)",
                "affected_max_version": "2.4.50",
                "severity": CRITICAL,
                "cvss_score": 9.8,
                "description": (
                    "It was found that the fix for CVE-2021-41773 in Apache HTTP Server "
                    "2.4.50 was insufficient. An attacker could use a path traversal attack "
                    "to map URLs to files outside the document root. If CGI scripts are "
                    "enabled for these aliased paths, this allows for remote code execution."
                ),
                "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or later.",
            },
            {
                "cve_id": "CVE-2021-40438",
                "name": "Apache HTTP Server mod_proxy SSRF",
                "affected_max_version": "2.4.48",
                "severity": CRITICAL,
                "cvss_score": 9.0,
                "description": (
                    "A crafted request uri-path can cause mod_proxy to forward the request "
                    "to an origin server of the attacker's choice. This server-side request "
                    "forgery (SSRF) affects Apache HTTP Server 2.4.48 and earlier."
                ),
                "remediation": "Upgrade Apache HTTP Server to version 2.4.49 or later.",
            },
            {
                "cve_id": "CVE-2022-22720",
                "name": "Apache HTTP Server HTTP Request Smuggling",
                "affected_max_version": "2.4.52",
                "severity": HIGH,
                "cvss_score": 7.3,
                "description": (
                    "Apache HTTP Server 2.4.52 and earlier fails to close inbound connections "
                    "when errors are encountered discarding the request body, exposing the "
                    "server to HTTP Request Smuggling attacks."
                ),
                "remediation": "Upgrade Apache HTTP Server to version 2.4.53 or later.",
            },
            {
                "cve_id": "CVE-2022-31813",
                "name": "Apache HTTP Server IP/Hostname Spoofing via Hop-by-Hop Headers",
                "affected_max_version": "2.4.54",
                "severity": HIGH,
                "cvss_score": 7.3,
                "description": (
                    "Apache HTTP Server 2.4.54 may not send the X-Forwarded-* headers to "
                    "the origin server based on client-side Connection header hop-by-hop "
                    "mechanism, allowing IP spoofing attacks."
                ),
                "remediation": "Upgrade Apache HTTP Server to version 2.4.55 or later.",
            },
        ],
    },
    "nginx": {
        "display_name": "Nginx",
        "service_patterns": ["nginx"],
        "default_port": 80,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2021-23017",
                "name": "Nginx DNS Resolver Buffer Overflow",
                "affected_max_version": "1.21.0",
                "severity": HIGH,
                "cvss_score": 7.7,
                "description": (
                    "A security issue in the nginx resolver was identified that might allow "
                    "an attacker who can forge UDP packets from the DNS server to cause a "
                    "1-byte memory overwrite, resulting in denial of service or potentially "
                    "arbitrary code execution."
                ),
                "remediation": "Upgrade Nginx to version 1.21.1 or later.",
            },
            {
                "cve_id": "CVE-2022-41741",
                "name": "Nginx Memory Corruption in ngx_http_mp4_module",
                "affected_max_version": "1.23.1",
                "severity": HIGH,
                "cvss_score": 7.8,
                "description": (
                    "NGINX Open Source before versions 1.23.2 and 1.22.1 have a vulnerability "
                    "in the ngx_http_mp4_module. A local attacker with the ability to trigger "
                    "processing of a specially crafted MP4 file could corrupt NGINX worker "
                    "memory, causing a worker process crash or potential code execution."
                ),
                "remediation": "Upgrade Nginx to version 1.23.2 or 1.22.1 (stable) or later.",
            },
            {
                "cve_id": "CVE-2022-41742",
                "name": "Nginx Memory Disclosure in ngx_http_mp4_module",
                "affected_max_version": "1.23.1",
                "severity": MEDIUM,
                "cvss_score": 5.5,
                "description": (
                    "NGINX Open Source before versions 1.23.2 and 1.22.1 have a vulnerability "
                    "that allows a local attacker to read NGINX worker memory by using specially "
                    "crafted MP4 files, leading to information disclosure."
                ),
                "remediation": "Upgrade Nginx to version 1.23.2 or 1.22.1 (stable) or later.",
            },
        ],
    },
    "mysql": {
        "display_name": "MySQL",
        "service_patterns": ["mysql"],
        "default_port": 3306,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2023-21980",
                "name": "MySQL Server Privilege Escalation",
                "affected_max_version": "8.0.32",
                "severity": HIGH,
                "cvss_score": 7.1,
                "description": (
                    "Vulnerability in MySQL Server component (Client programs) affecting "
                    "versions 5.7.41 and prior and 8.0.32 and prior. A low-privileged attacker "
                    "with logon access to the infrastructure where MySQL executes can compromise "
                    "MySQL Server, enabling takeover."
                ),
                "remediation": "Upgrade MySQL to version 8.0.33 or 5.7.42 or later.",
            },
            {
                "cve_id": "CVE-2022-21589",
                "name": "MySQL Server Unauthorized Data Access",
                "affected_max_version": "5.7.39",
                "severity": MEDIUM,
                "cvss_score": 4.9,
                "description": (
                    "Vulnerability in the MySQL Server (Server: Security: Privileges) component. "
                    "A high privileged attacker with network access via multiple protocols can "
                    "cause MySQL Server to unauthorized read access to a subset of data."
                ),
                "remediation": "Upgrade MySQL to version 5.7.40 or 8.0.x or later.",
            },
            {
                "cve_id": "CVE-2021-2471",
                "name": "MySQL Connector/J Man-in-the-Middle Attack",
                "affected_max_version": "8.0.26",
                "severity": MEDIUM,
                "cvss_score": 4.2,
                "description": (
                    "Vulnerability in MySQL Connector/J affecting versions 8.0.26 and prior. "
                    "A high privileged attacker with network access via multiple protocols can "
                    "compromise MySQL Connectors, enabling man-in-the-middle attacks."
                ),
                "remediation": "Upgrade MySQL Connector/J to version 8.0.27 or later.",
            },
        ],
    },
    "postgresql": {
        "display_name": "PostgreSQL",
        "service_patterns": ["postgresql", "postgres"],
        "default_port": 5432,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2022-1552",
                "name": "PostgreSQL Autovacuum Privilege Escalation",
                "affected_max_version": "14.2",
                "severity": HIGH,
                "cvss_score": 8.8,
                "description": (
                    "A flaw was found in PostgreSQL. There is an issue with incomplete efforts "
                    "to operate safely when a privileged user is maintaining another user's "
                    "objects. The Autovacuum, REINDEX, CREATE INDEX, REFRESH MATERIALIZED VIEW, "
                    "CLUSTER, and pg_amcheck commands activated relevant protections too late or "
                    "not at all, allowing privilege escalation."
                ),
                "remediation": (
                    "Upgrade PostgreSQL to versions 14.3, 13.7, 12.11, 11.16, or 10.21 or later."
                ),
            },
            {
                "cve_id": "CVE-2022-41862",
                "name": "PostgreSQL Memory Disclosure in Extended Query Protocol",
                "affected_max_version": "15.1",
                "severity": LOW,
                "cvss_score": 3.7,
                "description": (
                    "In PostgreSQL, a modified unauthenticated server can send an unterminated "
                    "string during Kerberos transport encryption establishment. Under certain "
                    "conditions, a libpq client can over-read and include uninitialized bytes "
                    "in an error message."
                ),
                "remediation": (
                    "Upgrade PostgreSQL to versions 15.2, 14.7, 13.10, 12.14, or 11.19 or later."
                ),
            },
        ],
    },
    "vsftpd": {
        "display_name": "vsftpd",
        "service_patterns": ["vsftpd"],
        "default_port": 21,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2011-2523",
                "name": "vsftpd 2.3.4 Backdoor Command Execution",
                "affected_exact_version": "2.3.4",
                "severity": CRITICAL,
                "cvss_score": 10.0,
                "description": (
                    "vsftpd 2.3.4 downloaded between June 30 and July 3, 2011 contains a "
                    "malicious backdoor. A smiley face in the username ':)' triggers the backdoor "
                    "and opens a shell on port 6200/tcp. This is one of the most famous supply "
                    "chain compromises in open-source history."
                ),
                "remediation": (
                    "Replace vsftpd 2.3.4 immediately with a clean version from official sources. "
                    "Block port 6200 at the firewall immediately."
                ),
            },
        ],
    },
    "proftpd": {
        "display_name": "ProFTPD",
        "service_patterns": ["proftpd"],
        "default_port": 21,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2020-9273",
                "name": "ProFTPD Use-After-Free Vulnerability",
                "affected_max_version": "1.3.6",
                "severity": HIGH,
                "cvss_score": 8.8,
                "description": (
                    "In ProFTPD through 1.3.7, it is possible to corrupt the data pool by "
                    "interrupting the data transfer channel. This triggers a use-after-free "
                    "in alloc_pool in pool.c, and also in config_lineno in confpars.c, "
                    "potentially allowing remote code execution."
                ),
                "remediation": "Upgrade ProFTPD to version 1.3.7 or later.",
            },
        ],
    },
    "redis": {
        "display_name": "Redis",
        "service_patterns": ["redis"],
        "default_port": 6379,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2021-32626",
                "name": "Redis Heap Buffer Overflow via Lua Scripting",
                "affected_max_version": "6.2.5",
                "severity": HIGH,
                "cvss_score": 8.8,
                "description": (
                    "In affected versions of Redis, specially crafted Lua scripts can cause the "
                    "heap-based Lua stack to overflow, due to incomplete boundary checks. An "
                    "attacker with the ability to execute Lua code in Redis can exploit this to "
                    "execute arbitrary code."
                ),
                "remediation": "Upgrade Redis to version 6.2.6, 6.0.16, or 5.0.14 or later.",
            },
            {
                "cve_id": "CVE-2022-24736",
                "name": "Redis Denial of Service via Lua Script",
                "affected_max_version": "6.2.7",
                "severity": MEDIUM,
                "cvss_score": 5.5,
                "description": (
                    "Redis before version 7.0 is vulnerable to Denial of Service. An attacker "
                    "can send a specially crafted Lua script that causes the Redis server to "
                    "crash, resulting in a denial of service."
                ),
                "remediation": "Upgrade Redis to version 7.0 or later.",
            },
        ],
    },
    "mongodb": {
        "display_name": "MongoDB",
        "service_patterns": ["mongodb"],
        "default_port": 27017,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2021-20328",
                "name": "MongoDB Client TLS Certificate Validation Bypass",
                "affected_max_version": "4.4.2",
                "severity": HIGH,
                "cvss_score": 6.8,
                "description": (
                    "Specific versions of the Java driver that support client-side field level "
                    "encryption may not perform correct certificate validation of the KMS provider "
                    "server. This could allow a man-in-the-middle attack against the KMS provider "
                    "during key material provisioning."
                ),
                "remediation": "Upgrade MongoDB to version 4.4.3 or later.",
            },
        ],
    },
    "smb": {
        "display_name": "SMB",
        "service_patterns": ["microsoft-ds", "smb", "netbios-ssn", "samba"],
        "default_port": 445,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2017-0144",
                "name": "EternalBlue - SMBv1 Remote Code Execution",
                "affected_max_version": "1.0",
                "severity": CRITICAL,
                "cvss_score": 9.3,
                "description": (
                    "The SMBv1 server in Microsoft Windows allows remote attackers to execute "
                    "arbitrary code via crafted packets. This vulnerability was weaponized as "
                    "'EternalBlue' and used by WannaCry ransomware and NotPetya to cause "
                    "billions of dollars in damage globally."
                ),
                "remediation": (
                    "Apply Microsoft security update MS17-010 immediately. Disable SMBv1 via "
                    "PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false. "
                    "Block TCP port 445 at the network perimeter firewall."
                ),
            },
        ],
    },
    "rdp": {
        "display_name": "Remote Desktop Protocol",
        "service_patterns": ["ms-wbt-server", "microsoft terminal services"],
        "default_port": 3389,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2019-0708",
                "name": "BlueKeep - RDP Pre-Auth Remote Code Execution",
                "affected_max_version": "7.1",
                "severity": CRITICAL,
                "cvss_score": 9.8,
                "description": (
                    "A remote code execution vulnerability exists in Remote Desktop Services. "
                    "An unauthenticated attacker can exploit this by connecting to the target "
                    "via RDP and sending specially crafted requests. This is wormable and "
                    "requires no user interaction."
                ),
                "remediation": (
                    "Apply Microsoft security patch KB4499175. Enable Network Level "
                    "Authentication (NLA). Restrict RDP access via firewall to trusted IPs only."
                ),
            },
        ],
    },
    "telnet": {
        "display_name": "Telnet",
        "service_patterns": ["telnet"],
        "default_port": 23,
        "vulnerabilities": [
            {
                "cve_id": "INSECURE-PROTO-TELNET",
                "name": "Telnet - Cleartext Protocol in Use",
                "affected_max_version": "999.0.0",
                "severity": CRITICAL,
                "cvss_score": 9.0,
                "description": (
                    "Telnet transmits all data — including usernames and passwords — in "
                    "plaintext. Any network observer can intercept and read all traffic. "
                    "Telnet has no encryption, integrity checking, or strong authentication. "
                    "This is a fundamental design flaw of the protocol."
                ),
                "remediation": (
                    "Disable Telnet immediately. Replace with SSH (port 22) which provides "
                    "encrypted communication, strong authentication, and integrity verification."
                ),
            },
        ],
    },
    "ftp": {
        "display_name": "FTP",
        "service_patterns": ["ftp", "pure-ftpd", "wu-ftpd", "filezilla"],
        "default_port": 21,
        "vulnerabilities": [
            {
                "cve_id": "INSECURE-PROTO-FTP",
                "name": "FTP - Credentials Transmitted in Cleartext",
                "affected_max_version": "999.0.0",
                "severity": HIGH,
                "cvss_score": 7.5,
                "description": (
                    "FTP (File Transfer Protocol) transmits authentication credentials and "
                    "file data in cleartext. Any network observer with packet capture "
                    "capability can steal credentials and intercept transferred files. "
                    "FTP also has inherent vulnerabilities to bounce attacks."
                ),
                "remediation": (
                    "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS "
                    "(FTP over TLS/SSL). Both provide encryption for credentials and data."
                ),
            },
        ],
    },
    "elasticsearch": {
        "display_name": "Elasticsearch",
        "service_patterns": ["elasticsearch"],
        "default_port": 9200,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2021-22145",
                "name": "Elasticsearch Memory Disclosure",
                "affected_max_version": "7.13.3",
                "severity": MEDIUM,
                "cvss_score": 6.5,
                "description": (
                    "A memory disclosure vulnerability was identified in Elasticsearch versions "
                    "before 7.13.4. If a malformed request is sent to an Elasticsearch node, "
                    "the node's response may include previously used portion of a data buffer "
                    "that could contain sensitive information."
                ),
                "remediation": "Upgrade Elasticsearch to version 7.13.4 or 7.14.0 or later.",
            },
        ],
    },
}

# Informational and configuration-based checks triggered by open ports
PORT_RISK_CHECKS: list[dict] = [
    {
        "id": "RISK-RDP-EXPOSED",
        "name": "RDP Directly Exposed to Network",
        "ports": [3389],
        "severity": HIGH,
        "cvss_score": 7.0,
        "description": (
            "Remote Desktop Protocol (RDP) is directly accessible on this host. "
            "RDP is a frequent target for brute-force attacks, credential stuffing, "
            "and exploitation of RDP-specific vulnerabilities. "
            "Exposing RDP directly to untrusted networks significantly increases attack surface."
        ),
        "remediation": (
            "Restrict RDP access using firewall rules to specific trusted IP addresses only. "
            "Consider deploying a VPN gateway and requiring VPN connection before RDP access. "
            "Enable Network Level Authentication (NLA) and use strong, unique passwords."
        ),
    },
    {
        "id": "RISK-TELNET-EXPOSED",
        "name": "Telnet Service Directly Accessible",
        "ports": [23],
        "severity": CRITICAL,
        "cvss_score": 9.0,
        "description": (
            "Telnet is running and accessible. All Telnet traffic including passwords "
            "is transmitted in plaintext. This allows passive eavesdropping by any "
            "network observer between the client and server."
        ),
        "remediation": "Disable Telnet. Deploy SSH as the secure remote access replacement.",
    },
    {
        "id": "RISK-MONGODB-EXPOSED",
        "name": "MongoDB Database Directly Accessible",
        "ports": [27017, 27018, 27019],
        "severity": CRITICAL,
        "cvss_score": 9.5,
        "description": (
            "A MongoDB port is accessible from the network. Many MongoDB instances "
            "run without authentication by default. Exposed unauthenticated MongoDB "
            "databases have led to millions of records being stolen or ransomed."
        ),
        "remediation": (
            "Enable MongoDB authentication immediately. Bind MongoDB to localhost "
            "or an internal interface. Use firewall rules to block external access."
        ),
    },
    {
        "id": "RISK-REDIS-EXPOSED",
        "name": "Redis Cache Directly Accessible",
        "ports": [6379],
        "severity": CRITICAL,
        "cvss_score": 9.5,
        "description": (
            "Redis is accessible from the network without authentication. "
            "Unauthenticated Redis instances allow full data access and can be "
            "exploited to write arbitrary files to the server, enabling persistence "
            "or privilege escalation."
        ),
        "remediation": (
            "Configure Redis with a strong authentication password (requirepass). "
            "Bind Redis to 127.0.0.1 only. Use iptables/firewall to block port 6379."
        ),
    },
    {
        "id": "RISK-ELASTICSEARCH-EXPOSED",
        "name": "Elasticsearch Directly Accessible",
        "ports": [9200, 9300],
        "severity": HIGH,
        "cvss_score": 8.5,
        "description": (
            "Elasticsearch is accessible from the network. Unauthenticated Elasticsearch "
            "instances expose all indexed data to unauthorized access. This has resulted "
            "in major data breaches affecting millions of records."
        ),
        "remediation": (
            "Enable Elasticsearch security features (X-Pack). Configure authentication "
            "and TLS. Bind to internal interfaces only and use firewall rules."
        ),
    },
    {
        "id": "RISK-DOCKER-EXPOSED",
        "name": "Docker API Exposed Without Authentication",
        "ports": [2375, 2376],
        "severity": CRITICAL,
        "cvss_score": 9.8,
        "description": (
            "The Docker daemon API is accessible on the network. An unauthenticated "
            "Docker API allows full control of all containers, host filesystem access, "
            "and trivial privilege escalation to root on the host system."
        ),
        "remediation": (
            "Immediately disable the Docker TCP listener if not required. If remote "
            "access is needed, use port 2376 with TLS client certificate authentication. "
            "Use SSH tunneling to access the Docker socket securely."
        ),
    },
    {
        "id": "RISK-SMB-EXPOSED",
        "name": "SMB Port Exposed to Network",
        "ports": [445, 139],
        "severity": HIGH,
        "cvss_score": 7.5,
        "description": (
            "SMB (Server Message Block) is exposed on this host. SMB has a history of "
            "critical vulnerabilities including EternalBlue (WannaCry). SMB should never "
            "be exposed to untrusted networks."
        ),
        "remediation": (
            "Block SMB ports (445, 139) at the network perimeter firewall. "
            "Only allow SMB access from trusted internal network segments that require it. "
            "Disable SMBv1 protocol entirely."
        ),
    },
    {
        "id": "RISK-FTP-EXPOSED",
        "name": "FTP Service Exposed",
        "ports": [21],
        "severity": MEDIUM,
        "cvss_score": 6.0,
        "description": (
            "FTP is running and accessible. FTP transmits credentials and file data "
            "in cleartext and is susceptible to bounce attacks and brute force. "
            "Modern secure alternatives exist."
        ),
        "remediation": "Replace FTP with SFTP or FTPS to encrypt data in transit.",
    },
    {
        "id": "RISK-VNC-EXPOSED",
        "name": "VNC Remote Desktop Exposed",
        "ports": [5900, 5901],
        "severity": HIGH,
        "cvss_score": 7.5,
        "description": (
            "VNC (Virtual Network Computing) remote desktop is accessible. VNC is "
            "frequently targeted for brute-force attacks and has had numerous "
            "authentication bypass vulnerabilities. Many VNC servers have no "
            "authentication configured."
        ),
        "remediation": (
            "Restrict VNC access to trusted IPs only. Require strong passwords. "
            "Consider using VPN access instead of direct VNC exposure. "
            "Use VNC with TLS encryption."
        ),
    },
    {
        "id": "RISK-MEMCACHED-EXPOSED",
        "name": "Memcached Exposed to Network",
        "ports": [11211],
        "severity": HIGH,
        "cvss_score": 8.6,
        "description": (
            "Memcached is accessible from the network. Unauthenticated Memcached instances "
            "allow reading and writing of all cached data. Additionally, Memcached has been "
            "abused for DDoS amplification attacks with amplification factors up to 51,000x."
        ),
        "remediation": (
            "Bind Memcached to localhost only. Use firewall rules to block port 11211. "
            "Use SASL authentication if external access is required."
        ),
    },
]
