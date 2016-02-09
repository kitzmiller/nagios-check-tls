# A remote Nagios check for SSL/TLS protocols and cipher suites

This is a remote nagios check written in php to check SSL/TLS protocols and cipher suites

* Checks for SSLv2, SSLv3
* Checks for deprecated encryption types (RC2, RC4, DES, 3DES)
* Checks for "national" encryption types (Camellia, IDEA, SEED)
* Checks for deprecated HMAC types (MD5)
* Checks for export level encryption
* Checks for perfect forward secrecy (PFS)
* Sane defaults for warning and critical levels

##Compatibility
* Tested on Debian 6, 7, and 8; RHEL 7

##Requirements
* php
* openssl
* https://github.com/kitzmiller/tlsscan

##Defaults
Critical on SSLv2, SSLv3; null, deprecated, export, and "national" encryption; MD5 HMAC; null authentication
Warning on missing PFS

##Usage
    ./check_tls.php [ OPTIONS ] -H host
    
      Nagios check to scan for SSL/TLS protocols and cipher suites
    
    OPTIONS:
      -H                 Hostname or IP address
      -h, --help         This message
      --no-warn-pfs      Skip warning on missing PFS
      -p                 Port, defaults to 443
      -v, --version      Show version information
    
      Note: Because this program is dependent on OpenSSL its results will vary
            with the version and capabilities of OpenSSL.
