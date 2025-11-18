🛡️ Vulnerability Report – Resource Exhaustion via Unprotected WordPress Cron Endpoint
📌 Affected Asset
WordPress-based Subdomain – *.example-client.com

🔍 Vulnerable Endpoint
/wp-cron.php

🧠 Executive Summary

A Denial of Service (DoS) vector was discovered on a publicly accessible WordPress installation. The script wp-cron.php, used for handling scheduled tasks in WordPress, is exposed without any form of rate limiting, authentication, or abuse protection.
Each HTTP request to this endpoint triggers backend logic, consuming CPU and other server resources. At scale, this can cause performance degradation or complete service unavailability.
Although wp-cron.php is a standard WordPress component, when publicly accessible without protection, it becomes a resource exhaustion vector. This issue falls under availability-based threats, one of the core pillars of information security (CIA triad).

🎯 Proof of Concept (PoC)
🔎 Endpoint Tested
GET https://www.example-client.com/wp-cron.php

📋 Reproduction Steps

Open the target URL in a browser or with curl:

curl -I https://www.example-client.com/wp-cron.php


✅ Response: 200 OK

Note: Although the response is blank, each request triggers background cron tasks.

Use a tool like Burp Suite Intruder to automate requests:
Configure a numeric payload (1–50) in a dummy parameter.
Launch requests to simulate attacker behavior.

Server impact:

Backend processes are triggered on every request.
Multiple requests per second begin to consume CPU and PHP worker threads.
Extended testing leads to 500 Internal Server Errors.

📸 Screenshot (attached) shows the endpoint returning 200 OK and the tool used to flood the server.

💥 Impact Analysis
🎯 Exploitable Scenarios
Attack Vector	Impact
❌ No Authentication	Anyone can access and trigger the cron script
🔁 Repeatable Abuse	Requests can be automated easily
💻 Server Resource Drain	PHP workers and CPU used by background tasks
⛔ Service Degradation	Under load, server responds with HTTP 500
🔓 Publicly Accessible	Attack can be launched remotely with no auth
🛠️ Low Barrier to Entry	No custom exploit needed; uses default WordPress logic
📉 Security Category: Availability

This vulnerability impacts service availability, with potential secondary effects such as:

Delayed scheduled tasks (cache cleanup, plugin updates)
Timeouts in backend processes
Full or partial downtime under sustained abuse

⚙️ Root Cause

WordPress triggers wp-cron.php automatically when a page is loaded, and by default, this endpoint is publicly accessible. In this setup:

The site has not disabled WordPress's web-based cron trigger.
There is no rate limiting, IP restriction, or authentication.
The server accepts and processes every request to /wp-cron.php.
This configuration exposes an amplification vector for attackers to trigger costly backend tasks with minimal input.

📈 Severity Assessment
Factor	Value
Unauthenticated exploitation	✅ Yes
Remote abuse possible	✅ Yes
Server resources affected	✅ CPU, I/O
Error messages observed	✅ HTTP 500
Automated abuse risk	✅ High
CVSS v3.1 (estimated)	6.5 – Medium (up to 7.5 – High if public-critical server)
✅ Recommended Remediation
🔒 1. Disable Web-Based wp-cron

In wp-config.php, disable the internal trigger:

define('DISABLE_WP_CRON', true);

🕒 2. Use System Cron Instead

Configure a server-level cron job (example: every 5 minutes):

*/5 * * * * wget -q -O - https://www.example-client.com/wp-cron.php?doing_wp_cron >/dev/null 2>&1


Offloads execution to a predictable and controlled environment.

🔐 3. Add Rate Limiting or Authentication

Use WAF rules to rate-limit or restrict access:

Block by IP reputation
Throttle repeated access to /wp-cron.php

Use .htaccess or Nginx directives to:

Require authentication
Allow access only to known IP ranges

📜 4. Monitor Usage

Set alerts for unusual spikes in access to /wp-cron.php
Monitor for HTTP 500/503 patterns via logs

📚 References

WordPress Cron Overview
Malcare: wp-cron.php Abuse
Hardening WordPress – OWASP

📓 Report Metadata
Field	Description
Vulnerability Type	Resource Exhaustion / Denial of Service
Affected File	/wp-cron.php
Exploitation Level	Remote, unauthenticated
Affected Platform	WordPress
Severity Estimate	Medium to High (6.5 – 7.5)
Tools Used	curl, Burp Suite Intruder
Status	Confirmed
Disclosure Type	Responsible, anonymized for demonstration
✍️ Methodology

This vulnerability was identified via:

Manual exploration of default WordPress paths (/wp-cron.php)
Testing server behavior using automated GET requests
Observing repeated 200 OK responses and backend CPU load
Scaling up attack simulation using Intruder to test real impact
Confirming potential DoS via server-side 500 responses and slowdowns

This demonstrates how even default features of popular CMS platforms like WordPress can be weaponized when misconfigured or exposed without restrictions.

✅ Conclusion

This is a clear case of a low-effort, high-impact DoS vector resulting from the default behavior of WordPress cron tasks. The exposure of /wp-cron.php without controls enables attackers to drain server resources using automated requests.

By implementing the server-side cron alternative, rate limiting, and hardening configurations, the vulnerability can be fully mitigated.

📢 Note: This report is fully anonymized and shared for educational and professional demonstration purposes only. No proprietary or undisclosed information is included.
