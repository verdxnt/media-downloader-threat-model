# media-downloader-threat-model

A security review of a Flask web application I built as part of my role at a university IT department. The app lets students and staff download media from a submitted URL using a background job system. Before deploying it to a shared Kubernetes cluster, I audited my own code for vulnerabilities.

My goal wasn't just to ship something that worked. I wanted to practice finding, tracking, and fixing real security issues in code I built myself. Building something and attacking it are two completely different mindsets, and writing this forced me into the second one.

**[Read the full threat model →](video-downloader-threat-model.md)**

## Summary

The review covers 14 findings: 1 Critical, 4 High, 4 Medium, and 5 Low. The most serious was an argument injection vulnerability that would have allowed unauthenticated remote code execution on the shared cluster. Each finding explains what the issue was, why it existed, and how to fix it.

Some of the most interesting findings only appeared when I thought about the deployment environment, not just the code in isolation. An SSRF that's harmless on a laptop becomes a real threat inside a cluster where internal services are reachable.

**Status:** [F-01 through F-0X fixed; F-07 and F-13 pending SSO]. The fixes are covered by a pytest suite with regression tests, run in GitHub Actions CI on every push.

**Topics:** argument injection, SSRF, path traversal, OAuth credential hygiene, debug mode exposure, PII disclosure, rate limiting, regex anchoring, and container deployment risks.

## Demo

https://github.com/user-attachments/assets/7a2c2f6f-f22a-419e-b372-9673e133e3fd

## About the source code

The source code is held in a private institutional repository. This threat model is the public artifact, shared with my supervisor's permission.
