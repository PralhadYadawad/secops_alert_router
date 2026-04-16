"""DDoS scenario templates for SecOps Alert Router V2."""

DDOS_SCENARIOS: list[dict] = [
    # ddos-001 — Benign: traffic spike from marketing campaign
    {
        "id": "ddos-001",
        "category": "ddos",
        "difficulty": "easy-medium",
        "is_true_threat": False,
        "severity": "medium",
        "mitre": {"tactic": "Impact", "technique": "T1498", "name": "Network Denial of Service"},
        "alert": {
            "rule": "NET-DDOS-VOLUMETRIC-001",
            "description": "Anomalous inbound traffic volume on web front-end cluster exceeding baseline by 380%.",
        },
        "source": {"ip": "203.0.113.0/24", "domain": "various-residential-isps.net", "email": "", "geo": "US, Europe, APAC (mixed)"},
        "target": {"host": "web-fe-prod-01.corp.local", "ip": "198.51.100.10", "user": "", "email": "", "department": "Infrastructure", "role": "Web Front-End Load Balancer", "criticality": "critical"},
        "indicators": {
            "peak_bps": "4.7 Gbps", "peak_pps": "820K pps",
            "protocol_mix": "93% HTTPS, 4% HTTP, 3% DNS",
            "source_count": "38,400 unique IPs",
            "geo_distribution": "Matches ad-campaign target demographics",
            "uri_pattern": "/promo/summer-sale, /products/*, /cart",
            "http_methods": "GET 88%, POST 12%",
            "session_behavior": "Normal session durations, valid cookies",
        },
        "raw_log": (
            "2026-04-14T08:15:22Z web-fe-prod-01 haproxy[4821]: 198.51.100.10:443 conn_rate=14200/s sess_rate=9800/s queue_cur=87 status=200 avg_resp=42ms\n"
            "2026-04-14T08:15:23Z web-fe-prod-01 haproxy[4821]: 198.51.100.10:443 conn_rate=14850/s sess_rate=10200/s queue_cur=112 status=200 avg_resp=58ms\n"
            "2026-04-14T08:16:01Z netflow-collector: top-talker 203.0.113.47 -> 198.51.100.10:443 1.2Gbps (residential ISP)\n"
            "2026-04-14T08:16:01Z netflow-collector: top-talker 203.0.113.112 -> 198.51.100.10:443 0.9Gbps (mobile carrier)"
        ),
        "investigate": {
            "analyze_headers": "TCP handshake completion rate 99.2%. SYN/ACK ratio normal. TLS negotiation succeeds on all sampled flows. HTTP/2 multiplexing observed, consistent with modern browsers. No malformed headers detected.",
            "query_siem": "2026-04-14T06:00Z Marketing blast email sent to 2.1M subscribers for Summer Sale launch. 07:45Z Social-media posts went live. 08:10Z Traffic ramp began correlating with email open-rate peak. 08:15Z Volumetric alert triggered (threshold 2 Gbps).",
            "check_reputation": "Top 50 source IPs checked against AbuseIPDB, OTX, VirusTotal: 0 flagged. All resolve to residential ISPs and mobile carriers. No IPs in any botnet C2 feed. Geo-IP matches campaign target regions.",
            "check_asset": "web-fe-prod-01 is HAProxy LB fronting 12 app pods. Auto-scaling at 9/12 pods. CPU 72%, memory 61%. No error rate spike; 200-status ratio 98.4%. CDN cache-hit ratio 74%.",
            "analyze_payload": "Sampled 500 requests: all carry valid session tokens or new session establishment. Referrer headers match marketing email tracking links and social-media redirects. User-Agent strings are diverse modern browsers. No payload anomalies.",
            "correlate_alerts": "No IDS/IPS alerts. No firewall drops. WAF block rate normal (0.3%). Marketing Ops ticket MKT-4821 confirms Summer Sale campaign launched today. Previous campaign (Black Friday 2025) showed similar 350% spike.",
        },
        "optimal_actions": [5, 2, 3, 10],
        "impact_if_missed": "Unnecessary DDoS scrubbing activation would add latency to legitimate shoppers during a revenue-critical marketing window, potentially costing $120K+ in lost sales.",
    },
    # ddos-002 — Benign: CDN misconfiguration causing alerts
    {
        "id": "ddos-002",
        "category": "ddos",
        "difficulty": "medium",
        "is_true_threat": False,
        "severity": "medium",
        "mitre": {"tactic": "Impact", "technique": "T1499", "name": "Endpoint Denial of Service"},
        "alert": {
            "rule": "NET-DDOS-APPFLOOD-002",
            "description": "Sustained high request rate to origin servers after CDN cache-miss ratio spiked to 97%.",
        },
        "source": {"ip": "104.16.0.0/12", "domain": "cdn-edge-nodes.cloudflare.net", "email": "", "geo": "Global CDN edge PoPs"},
        "target": {"host": "origin-api-prod-03.corp.local", "ip": "10.200.1.53", "user": "", "email": "", "department": "Infrastructure", "role": "API Origin Server", "criticality": "critical"},
        "indicators": {
            "request_rate": "28,000 req/s to origin (normal: 3,000 req/s)",
            "cache_hit_ratio": "3% (normal: 89%)", "origin_cpu": "94%",
            "origin_response_time": "1,800ms (normal: 120ms)",
            "error_rate": "12% 502/503 responses",
            "source_ips": "All from CDN edge-node IP ranges",
            "uri_pattern": "/api/v2/catalog/* with Cache-Control: no-store",
        },
        "raw_log": (
            "2026-04-14T11:32:10Z origin-api-prod-03 nginx[2091]: 104.16.48.172 \"GET /api/v2/catalog/items?page=1\" 200 rt=1.82s upstream_cache=MISS\n"
            "2026-04-14T11:32:10Z origin-api-prod-03 nginx[2091]: 104.16.52.88 \"GET /api/v2/catalog/items?page=2\" 502 rt=30.0s upstream_cache=MISS\n"
            "2026-04-14T11:32:11Z cdn-monitor: cache_hit_ratio=0.031 origin_req_rate=28412 edge_req_rate=29100\n"
            "2026-04-14T11:32:15Z alertmanager: origin-api-prod-03 CPU_CRITICAL 94.2% (threshold 85%)"
        ),
        "investigate": {
            "analyze_headers": "All requests from verified CDN edge-node IPs (Cloudflare AS13335). X-Forwarded-For shows diverse legitimate end-user IPs. Origin response headers include Cache-Control: no-store — NEW header added in today's deploy.",
            "query_siem": "2026-04-14T10:45Z Deploy pipeline pushed catalog-service v2.14.0 to production. 10:48Z CDN cache-hit ratio began declining. 11:15Z Cache-hit ratio below 10%. 11:32Z DDoS alert triggered due to origin overload.",
            "check_reputation": "All source IPs belong to Cloudflare CDN edge infrastructure. No malicious reputation. Same edge nodes have served traffic for 18 months.",
            "check_asset": "origin-api-prod-03 runs catalog-service v2.14.0 (deployed 47 min ago). K8s HPA hit resource quota. Pod restarts: 3 (OOM). Previous v2.13.2 had Cache-Control: public, max-age=300.",
            "analyze_payload": "Request patterns identical to normal catalog browsing. No amplification vectors. Volume is the normal edge rate (29K/s) now passing through to origin instead of being served from cache.",
            "correlate_alerts": "Related: origin-api-prod-03 CPU_CRITICAL, OOM_KILL x3, catalog-service 502 rate >10%. Change ticket CHG-7842 shows v2.14.0 deployment. No IDS/IPS alerts.",
        },
        "optimal_actions": [1, 3, 5, 10],
        "impact_if_missed": "Activating DDoS scrubbing would not help since the traffic is legitimate. The fix is rolling back the cache-header regression. Delay risks extended origin outage for all catalog API consumers.",
    },
    # ddos-003 — True threat: volumetric SYN flood
    {
        "id": "ddos-003",
        "category": "ddos",
        "difficulty": "medium",
        "is_true_threat": True,
        "severity": "critical",
        "compliance": {
            "framework": "PCI-DSS",
            "data_type": "PCI",
            "data_classification": "Payment Processing Infrastructure",
            "breach_notification_hours": 72,
            "data_volume": "bulk",
            "mandatory_escalation": True,
        },
        "mitre": {"tactic": "Impact", "technique": "T1498", "name": "Network Denial of Service"},
        "alert": {
            "rule": "NET-DDOS-SYNFLOOD-001",
            "description": "Massive SYN flood targeting primary DNS and web infrastructure from botnet-distributed sources.",
        },
        "source": {"ip": "Multiple (45,000+ unique IPs)", "domain": "Spoofed and botnet-controlled hosts", "email": "", "geo": "Brazil, Vietnam, Indonesia, India, Nigeria (botnet hotspots)"},
        "target": {"host": "edge-gw-01.corp.local", "ip": "198.51.100.1", "user": "", "email": "", "department": "Infrastructure", "role": "Edge Gateway / Border Router", "criticality": "critical"},
        "indicators": {
            "peak_bps": "38 Gbps", "peak_pps": "14.2M pps",
            "protocol_mix": "99.7% TCP SYN, 0.3% other",
            "syn_ack_ratio": "SYN:ACK = 142:1 (normal ~1:1)",
            "source_count": "45,200 unique IPs across 1,800 ASNs",
            "ttl_distribution": "Irregular — suggests IP spoofing",
            "tcp_window_size": "Uniform 65535 across all sources",
            "target_ports": "80, 443, 53",
        },
        "raw_log": (
            "2026-04-14T03:22:01Z edge-gw-01 kernel: TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies.\n"
            "2026-04-14T03:22:01Z edge-gw-01 kernel: nf_conntrack: table full, dropping packet. entries=2097152\n"
            "2026-04-14T03:22:02Z netflow-collector: syn_flood detected 14.2Mpps -> 198.51.100.1 ports=80,443,53\n"
            "2026-04-14T03:22:03Z edge-gw-01 snmpd: ifInOctets.2 delta=4750000000 (38Gbps) ifOutErrors.2 delta=894201\n"
            "2026-04-14T03:22:05Z dns-auth-01: SERVFAIL rate 94% — unable to process legitimate queries"
        ),
        "investigate": {
            "analyze_headers": "TCP SYN packets show uniform window size (65535) and identical TCP options across 45K+ sources — hallmark of packet-crafting tools (hping3/Scapy). TTL values cluster around 3-4 distinct values despite 1,800 ASNs indicating spoofed source IPs. No completed TCP handshakes from flood IPs.",
            "query_siem": "2026-04-14T03:20Z Baseline 1.2 Gbps. 03:21:44Z Sudden ramp 8->22 Gbps in 16s. 03:22:01Z Peak 38 Gbps, SYN cookie activation, conntrack table full. 03:22:05Z DNS SERVFAIL rate 94%. 03:22:30Z HTTP error rate 78%.",
            "check_reputation": "Sampled 200 source IPs: 142 in Spamhaus DROP/EDROP lists. 67 flagged in Emerging Threats botnet C2 feed. 31 known Mirai-variant IoT devices. Remaining IPs likely spoofed (no rDNS, some unroutable).",
            "check_asset": "edge-gw-01 is primary border router (Juniper MX480, 40Gbps licensed). Uplink at 95%. Conntrack exhausted at 2M entries. dns-auth-01 and web-fe-prod-01 both degraded. BGP sessions stable but interface errors incrementing.",
            "analyze_payload": "Packets contain no payload (SYN-only). Source ports sequentially incrementing per source IP — automated generation. IP ID fields zero across all packets (raw socket). No legitimate traffic produces this signature.",
            "correlate_alerts": "Correlated: dns-auth-01 SERVFAIL spike, web-fe-prod-01 timeouts, edge-gw-01 conntrack exhaustion, BGP flap warnings. Threat Intel: coordinated DDoS campaign targeting financial sector this week (FS-ISAC bulletin TLP:AMBER-2026-0414).",
        },
        "optimal_actions": [0, 2, 3, 6, 9],
        "impact_if_missed": "Complete loss of internet-facing services: DNS, web, and API endpoints. Estimated downtime cost $45K/min. Potential BGP session drops causing extended recovery. Customer SLA violations across all tiers.",
    },
    # ddos-004 — True threat: application-layer HTTP flood
    {
        "id": "ddos-004",
        "category": "ddos",
        "difficulty": "medium",
        "is_true_threat": True,
        "severity": "critical",
        "compliance": {
            "framework": "PCI-DSS",
            "data_type": "PCI",
            "data_classification": "Cardholder Data Environment",
            "breach_notification_hours": 72,
            "data_volume": "massive",
            "mandatory_escalation": True,
        },
        "mitre": {"tactic": "Impact", "technique": "T1499", "name": "Endpoint Denial of Service"},
        "alert": {
            "rule": "NET-DDOS-APPFLOOD-001",
            "description": "Application-layer HTTP flood targeting auth and search endpoints causing backend resource exhaustion.",
        },
        "source": {"ip": "Multiple (12,000+ unique residential proxy IPs)", "domain": "Rotating residential proxies", "email": "", "geo": "US, Germany, UK (proxy exit nodes)"},
        "target": {"host": "api-gateway-prod-01.corp.local", "ip": "198.51.100.20", "user": "", "email": "", "department": "Infrastructure", "role": "API Gateway", "criticality": "critical"},
        "indicators": {
            "request_rate": "85,000 req/s (normal: 6,000 req/s)",
            "protocol_mix": "100% HTTPS (valid TLS handshakes)",
            "target_endpoints": "/api/v1/auth/login, /api/v1/search?q=*",
            "http_methods": "POST 62%, GET 38%",
            "avg_response_time": "12,400ms (normal: 180ms)",
            "db_connections": "Pool exhausted — 500/500 active",
            "unique_user_agents": "Only 4 distinct User-Agent strings",
            "request_pattern": "No session cookies, no referrer, uniform timing",
        },
        "raw_log": (
            "2026-04-14T14:05:33Z api-gateway-prod-01 envoy[1082]: POST /api/v1/auth/login 429 rt=12.4s ua=\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) rv:121.0\" src=172.58.91.204 x-fwd=68.42.117.33\n"
            "2026-04-14T14:05:33Z api-gateway-prod-01 envoy[1082]: GET /api/v1/search?q=SELECT+*+FROM 502 rt=30.0s ua=\"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2)\" src=172.58.92.17 x-fwd=91.203.44.112\n"
            "2026-04-14T14:05:34Z postgres-primary: LOG: remaining connection slots reserved for superuser\n"
            "2026-04-14T14:05:35Z redis-sentinel: SDOWN master auth-cache 10.200.2.10 6379"
        ),
        "investigate": {
            "analyze_headers": "All requests complete valid TLS 1.3 handshakes but connection reuse is zero — each opens a new TCP+TLS session maximizing server overhead. Only 4 User-Agent strings rotating across 12K IPs. No Accept-Language, no Referer, no cookies. Syntactically valid but behaviorally anomalous.",
            "query_siem": "2026-04-14T13:55Z Baseline 6,200 req/s, 180ms. 14:00Z Ramp begins 15K req/s from new IP cohort. 14:03Z 45K req/s, auth latency >2s. 14:05Z 85K req/s, DB pool exhausted, Redis sentinel down. 14:06Z Legitimate login success rate 3%, search API 100% 502.",
            "check_reputation": "Source IPs are residential proxy exit nodes (Luminati/Bright Data, Oxylabs). Individual IPs have clean reputation by design. However, IP rotation pattern (each IP sends exactly 7 requests then disappears) is characteristic of commercial proxy-driven attack tools.",
            "check_asset": "api-gateway-prod-01 (Envoy) CPU 89%. Auth-service pods 8/8 at CPU limit, OOMKilled x2. PostgreSQL: 500/500 connections, 2,100 queued. Redis auth-cache: failover in progress. Elasticsearch cluster yellow (JVM heap 97%).",
            "analyze_payload": "POST /auth/login payloads contain randomized valid credential pairs — credential-stuffing combined with DDoS. Search queries include DB-probing patterns (SELECT *, UNION SELECT, OR 1=1) suggesting concurrent SQLi recon. Payload entropy confirms automated generation.",
            "correlate_alerts": "Correlated: WAF SQLi detection on /search (4,200 blocks/min), auth brute-force alert, PostgreSQL connection exhaustion, Redis failover, ES heap pressure. Same residential proxy ASN set used in attack on competitor (INC-2026-0398) last week.",
        },
        "optimal_actions": [0, 2, 4, 6, 9],
        "impact_if_missed": "Complete auth outage preventing all logins. DB exhaustion cascading to all API services. Credential-stuffing may cause account takeovers. SQLi probes risk data exfiltration if WAF bypass achieved. Blast radius: 2.4M active users.",
    },
]
