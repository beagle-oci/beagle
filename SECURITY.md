# Security Policy

## Supported versions

Security fixes are made for the latest release. Please update to the newest
version before reporting an issue.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/beagle-oci/beagle/security/advisories/new).
Include the beagle version (`beagle --version`), the registry type you were
using and steps to reproduce.

You will get a first response within a few days. Once a fix is available, it
is released and the advisory is published, crediting the reporter unless you
prefer otherwise.

## Scope

beagle is a read-only client. Relevant issues include, for example:

- leaking registry credentials (logs, screen, clipboard, requests to other hosts)
- following redirects or links from a registry or vendor API to unexpected hosts
- crashes or excessive resource use caused by malicious registry responses
- problems in the release artifacts or the install script

## Verifying releases

Release archives come with SBOMs, a keyless cosign signature of
`checksums.txt` and SLSA build provenance. See
[Verifying releases](README.md#verifying-releases) in the README.
