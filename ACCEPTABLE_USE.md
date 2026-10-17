# Acceptable use

Exposure Desk looks at a website the way an anonymous visitor would and reports secrets the site serves by mistake. It is built for owners and authorized assessors. By using it you agree to the rules below.

## 1. Own or authorized websites only

- Scan only websites you own or that you are explicitly authorized to assess. Authorization should be in writing and cover the domains, the time window and the kind of testing.
- You are responsible for having that authorization and for complying with the law that applies to you and to the website (for example computer-misuse and data-protection law) and with the website's own terms.
- If in doubt, do not scan. Exposure Desk cannot check whether you are authorized; the scope you enter is your declaration that you are.

## 2. Government, military and intelligence websites are blocked

Exposure Desk never sends any request to a government, military, intelligence or security-service, law-enforcement, judiciary or intergovernmental-organization website. A scan that names such a host is refused as a whole, and such hosts discovered during a scan are skipped before any DNS lookup or connection. No setting, flag, environment variable, preset or dashboard control turns this off ([USER_GUIDE.md](USER_GUIDE.md#hard-rule-protected-hosts) lists what is blocked and the known limits).

Do not try to get around this rule, for example by entering an IP address, an alternative host name or a mirror of such a site, by routing traffic through other tools, or by changing the code. The block is a minimum: it does not make any other website fair game.

## 3. No evasion or abuse

- Do not use Exposure Desk to hide who you are or to evade a website's protections. It sends an honest product token, keeps per-website rate limits, ignores proxy settings and has no spoofing, evasion timing, proxy rotation or rate-limit bypass. Do not add these.
- Do not use it to overload a website. Choose the Low-impact traffic option for fragile or shared hosting, and stop a scan if the website owner asks you to.
- Do not use it to collect personal data, to attack third parties, or as part of any unauthorized access.

## 4. Found secrets are not validated during a scan

No scan ever sends a discovered credential to its provider, logs in with it or triggers paid usage; findings say "validity not established". Exposure Desk can check whether one found key is still live only when a person explicitly starts a per-finding live key check — off by default, enabled per program. It makes a single read-only identity request to that key's own provider and never signs in, writes or triggers paid usage; the verdict does not change "validity not established". Many bug-bounty programs forbid using or testing found credentials at all, and it is your responsibility to confirm the program permits an active check before you run one. Apart from that explicit check, you must not test, use or share credentials you find. The acceptable action with a found secret is to make sure its owner revokes or rotates it: yourself, if it is yours, or the website owner through a responsible disclosure.

## 5. Handle results as sensitive

Findings are masked by default. A full-value export, a revealed value or the vault contains real secrets: store them like passwords, share them only with the people responsible for fixing the issue, and delete them when you no longer need them.

## 6. Responsibility

You are solely responsible for how you use Exposure Desk, for the scans you run and for how you handle what you find. The author does not monitor, control or approve individual scans and gives no legal advice; nothing in Exposure Desk or its documentation tells you that a particular scan is lawful.

Using Exposure Desk in breach of these rules is outside the permission granted in [LICENSE](LICENSE): that permission ends automatically for you, and you must stop using the software and delete your copies. The software comes as is, without warranty, and the author is not liable for any use or misuse of it (see [LICENSE](LICENSE), sections 6 to 8).

Report security problems in Exposure Desk itself as described in [SECURITY.md](SECURITY.md).
