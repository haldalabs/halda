# Security policy

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-security-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository.

Tell us what you found, how to reproduce it, and what it lets someone do. A failing test is ideal.

We read every report, tell you what we plan to do, and agree a disclosure date with you. We credit you unless you prefer otherwise.

## What we want to hear about

- An add-on with a real risk that `halda scan` reports as low or misses
- A secret value that reaches the output, JSON, SARIF or anything written to disk
- `halda exposure` reaching a real credential, or sending anything off the machine
- Any network request the tool makes that this README does not describe

## Safe harbour

We will not pursue anyone who researches in good faith, avoids harming other people's data and systems, and gives us reasonable time to fix what they find.
