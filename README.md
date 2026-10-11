# Relay — 26-flag CTF box

A free static learning game for GitHub Pages. Follow one fictional target through 26 distinct security exercises, arranged from beginner discovery to advanced exploit chains. Difficulty is a designed learning progression, not an external certification or benchmark.

Open `index.html` through an HTTPS site or a localhost static server. For example, run `python -m http.server 8790 --bind 127.0.0.1` in this directory and visit http://127.0.0.1:8790.

## How to play

1. Start with the simulated homepage and its Source tab.
2. Use the simulated terminal and target browser to discover flags.
3. Submit exact `CTF{...}` values in the corresponding challenge cards.
4. Reveal hints when needed, read the lessons, and repeat tests in Patched mode.
5. Keep evidence in the notebook and export a Markdown copy.

Progress and notes are saved only in the current browser. Shell and exercise state reset on reload. Switching target mode resets exercise state so vulnerable results do not carry into a patched run. Hints do not reduce points. The 26 flags total 18,850 points, increasing from 100 to 1,350 points in steps of 50.

The **Request** tab accepts a method, JSON headers and JSON body for the path above it. JSON here is simulator input: it can wrap a modelled cross-site form, XML document, or uploaded file. It is not a wire-format HTTP client. Go always makes a modelled GET; changing Page/Source tabs only displays the last response, without repeating state changes. Terminal `request POST /path JSON` uses the same target state. `reset-model` / Reset exercise state clears the collector, cache, profile, archive and coupons while preserving captured flags.

## The progression

| Stage | Exercise | Difficulty |
|---|---|---|
| 01 | Secret in delivered HTML source | Beginner |
| 02 | Unprotected maintenance route | Beginner |
| 03 | Exposed Base64 backup | Beginner |
| 04 | Exposed Git release history | Beginner |
| 05 | Diagnostic trace leaks environment data | Beginner |
| 06 | Path traversal file read | Beginner |
| 07 | Open redirect leaks a login ticket | Apprentice |
| 08 | Client-controlled role escalation | Apprentice |
| 09 | IDOR across invoice owners | Apprentice |
| 10 | Mass assignment of a protected plan field | Apprentice |
| 11 | SQL injection query model | Apprentice |
| 12 | Reflected XSS output-context model | Apprentice |
| 13 | CSRF state-change model | Intermediate |
| 14 | Credentialed CORS data-read model | Intermediate |
| 15 | Upload extension/content mismatch | Intermediate |
| 16 | SSRF into an internal service | Intermediate |
| 17 | XXE configuration read model | Intermediate |
| 18 | Server-side template injection model | Intermediate |
| 19 | NoSQL operator injection | Advanced |
| 20 | JWT unsigned-token acceptance | Advanced |
| 21 | Leaked credential to simulated SSH foothold | Advanced |
| 22 | Linux capability bypasses read permissions | Advanced |
| 23 | Archive extraction traversal overwrites a manifest | Advanced |
| 24 | Overlapping coupon check/commit race | Expert |
| 25 | Unkeyed-header cache poisoning and victim consumption | Expert |
| 26 | Release-ticket chain plus privileged PATH hijack | Expert |

## What this is

This is a browser simulation, not a hosted Linux VM. No scan, SSH connection, database, shell command, or target HTTP request runs. All target data and credentials are fictional. The game has no analytics, accounts, backend, external dependencies, or competitive leaderboard. Client-side flags and scores are inspectable and editable; SHA-256 flag checks are a convenience, not a trust boundary.

All exploit handling is deliberately bounded and simplified. Payloads are recognised by a teaching model; they do not run in real SQL, XML, template, JavaScript, SSH or Linux engines. The race exercise deterministically separates check and commit instead of depending on actual timing. The cache victim and collector are fictional state machines. Use external testing techniques only on systems you own or have explicit permission to test.

## Verification and development

With Node.js installed, run `node build.mjs` to regenerate the 26 SHA-256 checks and `node --test engine.test.cjs` to verify every vulnerable and patched route, duplicate scoring, stateful chains, and boundary checks. The tests contain solutions; avoid reading them before playing if you want to preserve the challenge.

## GitHub Pages

Publish this directory at the repository root. In Settings → Pages choose **Deploy from a branch**, `main`, `/ (root)`. All asset URLs are relative. `.nojekyll` selects plain static publishing.

## References

- [GitHub Pages overview](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger access control](https://portswigger.net/web-security/access-control)
- [PortSwigger SQL injection](https://portswigger.net/web-security/sql-injection)
- [MDN Base64](https://developer.mozilla.org/en-US/docs/Glossary/Base64)

Original training content and code licensed under MIT; see LICENSE.
