# Demo Data for ULPF
# ====================
# This folder contains sample log files in various formats for testing.
# 
# Usage:
#   python -m ulpf.main process --files demo_data/firewall_cef.log
#   python -m ulpf.main process --files demo_data/mixed_formats.log
#   python -m ulpf.main process --files demo_data/*.log
#
# Files:
#   firewall_cef.log    - Check Point / Palo Alto style CEF firewall logs
#   ids_leef.log        - IBM QRadar LEEF IDS/IPS alerts
#   router_syslog.log   - Cisco router syslog messages
#   waf_json.log        - ModSecurity / AWS WAF JSON events
#   proxy_w3c.log       - Squid / Blue Coat W3C proxy logs
#   fortigate_kv.log    - FortiGate key=value firewall logs
#   dns_xml.log         - DNS query logs in XML format
#   mixed_formats.log   - Mix of all formats for auto-detection demo
#
# You can also add your own log files here and ULPF will auto-detect their format.
# For truly unknown formats, use:
#   python -m ulpf.main learn --file demo_data/your_custom.log
