🛡️ Vulnerability Report – Unauthenticated REST API Exposure of Sensitive User Data via WordPress
📌 Affected Technology
WordPress (REST API - /wp/v2/users endpoint)

🔍 Vulnerable Endpoint Pattern
/?rest_route=/wp/v2/users

🧠 Executive Summary

A high-severity data exposure was discovered on a public WordPress-based platform. The endpoint /?rest_route=/wp/v2/users is accessible without authentication and leaks user profile metadata, including a corporate email address associated with known data breaches.
Although the exposed email is also found in the site's HTML (author page), its inclusion in a structured JSON response makes it far more susceptible to automated harvesting and abuse. When correlated with third-party breach databases, the leaked address is confirmed to exist in multiple historical breach datasets.

🎯 Proof of Concept (PoC)
1. Accessing the Vulnerable Endpoint
curl -s 'https://[REDACTED]/?rest_route=/wp/v2/users' | jq .

2. Observed JSON Response
{
  "id": 667,
  "name": "Example Author",
  "description": "Example Author ... You can reach them at example.email@corporate.com.",
  "link": "https://[REDACTED]/author/example/",
  "slug": "example-2-2"
}


The description field contains a corporate email address.

The email was verified via HaveIBeenPwned to appear in:

DemandScience (2024)
Gravatar (2020)
People Data Labs (2019)

📸 Multiple screenshots (not included here) confirm the leak and public breach status.

💥 Impact Analysis
📉 Potential Exploitation
Threat Scenario	Description
Credential Stuffing	The email is associated with previous breaches, raising the risk of reused password attacks.
Phishing & Social Engineering	Attackers can craft personalized messages based on name, employer, and email.
Privacy Violation	The API exposes personally identifiable information (PII) in violation of best practices and possibly regulatory frameworks (e.g., GDPR, CCPA).
Automated Harvesting	Structured JSON enables large-scale scraping far more efficiently than parsing HTML.
⚙️ Root Cause

REST API /wp/v2/users is enabled and accessible without authentication.
The API returns author metadata containing PII in the description field.
WordPress does not sanitize or strip sensitive data from this field by default.

📈 Severity Assessment
Factor	Severity Justification
Public exposure of PII	Corporate email + full name
Prior breach correlation	Increases phishing/credential stuffing potential
Structured JSON format	Enables automation and scaling
Unauthenticated access	No rate limiting, no CAPTCHA, fully public
CVSS v3.1 (estimated)	7.1 – High
✅ Recommended Remediation
🔒 Short-Term Mitigations

Block unauthenticated access to /wp/v2/users via WAF or CDN rules.

Example (Cloudflare expression):

(http.request.uri.query contains "rest_route=/wp/v2/users")


Rate-limit or CAPTCHA-protect REST API access for non-logged-in users.

🧼 Long-Term Fixes (Permanent Solutions)
1. Strip PII from API Output

Apply a filter to remove description or other sensitive fields from public REST responses.

add_filter( 'rest_prepare_user', function( $response, $user, $request ) {
    if ( isset( $response->data['description'] ) ) {
        unset( $response->data['description'] );
    }
    return $response;
}, 10, 3 );

2. Restrict API Access with Permissions

Require authentication to access user data in the API using the permission_callback.

3. Audit User Meta

Remove or sanitize sensitive fields (emails, phone numbers, payment IDs) from user bios.

4. Replace Emails in Bios

Replace static email addresses with:

Contact forms
Obfuscated mailto: links
Rotated aliases or server-side form processors

5. Monitor and Rate-Limit REST Endpoints

Use log analysis tools to identify API scraping
Apply bot protection mechanisms on sensitive API paths

✅ Verification

After applying the fix, re-run:

curl -s 'https://[REDACTED]/?rest_route=/wp/v2/users' | jq .


Ensure that:

The description field is empty or does not contain sensitive identifiers.
Email addresses are no longer returned in the API response.

📚 References

WordPress REST API Developer Handbook
HaveIBeenPwned – API
OWASP Privacy Risks
GDPR Article 32 – Data Protection by Design
WP REST API: rest_prepare_user

📓 Report Metadata
Field	Description
Vulnerability Type	Sensitive Data Exposure via REST API
Affected Component	WordPress /wp/v2/users endpoint
Authentication Needed	❌ No
Severity (CVSS v3.1)	7.1 – High
Confirmed Breach Correlation	✅ Yes (HIBP datasets)
Data Format Exposed	JSON / RESTful
Detection Method	Manual Testing + API enumeration
✍️ Methodology

This vulnerability was identified using responsible OSINT and API enumeration. Manual inspection of JSON REST responses revealed unexpected sensitive data, which was correlated against public breach data sources to assess risk impact.

The validation methodology included:

HTTP enumeration of unauthenticated REST endpoints
Parsing JSON output using jq
Verifying personal data leakage against HIBP
Impact mapping via real-world abuse scenarios

✅ Conclusion

This issue demonstrates how even minor misconfigurations in modern CMS frameworks like WordPress can lead to high-impact privacy and security issues. While WordPress offers flexible REST API capabilities, care must be taken to sanitize output, restrict access, and prevent PII leakage.

By implementing the recommended remediations, organizations can:

Avoid becoming a phishing or credential-stuffing vector
Reduce compliance and privacy risk exposure
Enhance public trust in their platform’s data handling practices

📢 Note: This report is fully anonymized and provided for educational, demonstrative, and portfolio purposes. No confidential assets or non-public vulnerabilities are disclosed.
