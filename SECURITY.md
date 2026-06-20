# Security Policy & Responsible Use

## Authorized use only

scopehound is built for **authorized** security testing — penetration-testing
engagements, bug-bounty programs, and assessments of systems **you own or have
explicit, written permission to test**.

Running active reconnaissance (port scanning, service probing, screenshotting)
against systems without authorization is illegal in most jurisdictions and is
not a use this project supports. The built-in scope gate exists to help you
*stay* within an authorized scope — it is a safety aid, **not** a substitute
for having authorization in the first place.

By using scopehound you accept sole responsibility for ensuring your activity
is lawful and authorized. The software is provided "as is" under the
[MIT License](LICENSE), without warranty of any kind.

## Good-practice checklist

- Keep a signed scope/authorization document for every engagement.
- Encode that scope in a `scope.yaml` and pass it with `--scope`; review the
  `subdomains` phase output to confirm out-of-scope hosts were dropped.
- Treat the `output/` directory as sensitive — it contains recon data about a
  client's infrastructure. It is git-ignored by default; store and dispose of
  it according to your engagement's data-handling rules.
- Mind rate limits and the impact of active scans on production systems.

## Reporting a vulnerability in scopehound

If you discover a security issue **in scopehound itself** (for example, a way
the scope gate can be bypassed, or a command-injection risk in how external
tools are invoked), please report it privately rather than opening a public
issue:

- Use GitHub's **Report a vulnerability** (Security → Advisories) on this repo, or
- Email the maintainer listed on the GitHub profile: https://github.com/OctagonIntel

Please include reproduction steps and the affected version. We aim to
acknowledge reports promptly and will credit reporters who wish to be named.

## Supported versions

scopehound is pre-1.0; security fixes are applied to the latest `main`.
