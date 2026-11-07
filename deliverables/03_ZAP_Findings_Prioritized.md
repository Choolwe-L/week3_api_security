# Week 3 — ZAP Automated Scan: Prioritized Findings

Generated from the OWASP ZAP traditional-json report (`zap_fitness_api_report.json`) by `scripts/analyze_report.py`.

## Risk summary

| Risk | Distinct alerts |
|------|-----------------|
| High | 1 |
| Medium | 1 |
| Low | 3 |
| Informational | 4 |

## Findings (highest risk first)

| # | Risk | Confidence | Alert | CWE | Instances |
|---|------|-----------|-------|-----|-----------|
| 1 | High | Low | SQL Injection | 89 | 3 |
| 2 | Medium | High | Content Security Policy (CSP) Header Not Set | 693 | 5 |
| 3 | Low | Low | Cross Site Scripting Weakness (Persistent in JSON Response) | 79 | 5 |
| 4 | Low | High | Server Leaks Version Information via "Server" HTTP Response Header Field | 497 | 4 |
| 5 | Low | Medium | X-Content-Type-Options Header Missing | 693 | 5 |
| 6 | Informational | High | Authentication Request Identified | -1 | 1 |
| 7 | Informational | Medium | Information Disclosure - Sensitive Information in URL | 598 | 1 |
| 8 | Informational | Medium | Session Management Response Identified | -1 | 1 |
| 9 | Informational | Medium | User Agent Fuzzer | 0 | 5 |

## Detail

### 1. SQL Injection  _(High / Low)_

- **CWE:** 89  **WASC:** 19  **Instances:** 3
- **Example URLs:**
  - `http://127.0.0.1:5000/api/search?activity=%27`
  - `http://127.0.0.1:5000/api/login`
  - `http://127.0.0.1:5000/api/login`
- **Description:** SQL injection may be possible.
- **Remediation:** Do not trust client side input, even if there is client side validation in place.In general, type check all data on the server side.If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.If database Stored Procedures can be used, use them.Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or equivalent functionality!Do not create dynamic SQL queries using simple string concatenation.Escape all data received from the client.Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in user input.Apply the principle of least privilege by using the least privileged database user possible.In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but minimizes its impact.Grant the minimum database access that is necessary for the application.

### 2. Content Security Policy (CSP) Header Not Set  _(Medium / High)_

- **CWE:** 693  **WASC:** 15  **Instances:** 5
- **Example URLs:**
  - `http://127.0.0.1:5000/api`
  - `http://127.0.0.1:5000/api/login`
  - `http://127.0.0.1:5000/api/register`
  - `http://127.0.0.1:5000/robots.txt`
  - `http://127.0.0.1:5000/sitemap.xml`
- **Description:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
- **Remediation:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### 3. Cross Site Scripting Weakness (Persistent in JSON Response)  _(Low / Low)_

- **CWE:** 79  **WASC:** 8  **Instances:** 5
- **Example URLs:**
  - `http://127.0.0.1:5000/api/workouts`
  - `http://127.0.0.1:5000/api/workouts`
  - `http://127.0.0.1:5000/api/workouts`
  - `http://127.0.0.1:5000/api/workouts?user_id=1`
  - `http://127.0.0.1:5000/api/workouts?user_id=1`
- **Description:** A XSS attack was found in a JSON response, this might leave content consumers vulnerable to attack if they don't appropriately handle the data (response).
- **Remediation:** Phase: Architecture and DesignUse a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.Phases: Implementation; Architecture and DesignUnderstand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.Phase: Architecture and DesignFor any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.Phase: ImplementationFor every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.

### 4. Server Leaks Version Information via "Server" HTTP Response Header Field  _(Low / High)_

- **CWE:** 497  **WASC:** 13  **Instances:** 4
- **Example URLs:**
  - `http://127.0.0.1:5000/`
  - `http://127.0.0.1:5000/api/users/1`
  - `http://127.0.0.1:5000/api/users/2`
  - `http://127.0.0.1:5000/api/login`
- **Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
- **Remediation:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

### 5. X-Content-Type-Options Header Missing  _(Low / Medium)_

- **CWE:** 693  **WASC:** 15  **Instances:** 5
- **Example URLs:**
  - `http://127.0.0.1:5000/`
  - `http://127.0.0.1:5000/api/users/1`
  - `http://127.0.0.1:5000/api/users/2`
  - `http://127.0.0.1:5000/api/users/3`
  - `http://127.0.0.1:5000/api/login`
- **Description:** The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.
- **Remediation:** Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### 6. Authentication Request Identified  _(Informational / High)_

- **CWE:** -1  **WASC:** -1  **Instances:** 1
- **Example URLs:**
  - `http://127.0.0.1:5000/api/login`
- **Description:** The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.
- **Remediation:** This is an informational alert rather than a vulnerability and so there is nothing to fix.

### 7. Information Disclosure - Sensitive Information in URL  _(Informational / Medium)_

- **CWE:** 598  **WASC:** 13  **Instances:** 1
- **Example URLs:**
  - `http://127.0.0.1:5000/api/workouts?user_id=1`
- **Description:** The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.
- **Remediation:** Do not pass sensitive information in URIs.

### 8. Session Management Response Identified  _(Informational / Medium)_

- **CWE:** -1  **WASC:** -1  **Instances:** 1
- **Example URLs:**
  - `http://127.0.0.1:5000/api/login`
- **Description:** The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.
- **Remediation:** This is an informational alert rather than a vulnerability and so there is nothing to fix.

### 9. User Agent Fuzzer  _(Informational / Medium)_

- **CWE:** 0  **WASC:** 0  **Instances:** 5
- **Example URLs:**
  - `http://127.0.0.1:5000/api/search?activity=Running`
  - `http://127.0.0.1:5000/api/search?activity=Running`
  - `http://127.0.0.1:5000/api/search?activity=Running`
  - `http://127.0.0.1:5000/api/search?activity=Running`
  - `http://127.0.0.1:5000/api/search?activity=Running`
- **Description:** Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.
