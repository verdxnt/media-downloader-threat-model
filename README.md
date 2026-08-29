# media-downloader-threat-model
This is a detailed and descriptive Threat Model for my DLMC Video Downloader Project. The purpose of this is to share my progress on how I not only built but focused on searching, tracking , and fixing critical vulnerabilities in my code, Improving my capability to write strong, clean and safe code.# Media Downloader — Pre-Deployment Threat Model

A pre-deployment security review I wrote for a Flask web application I built as part of my role at a university IT department. The app lets users download media via a background job system; before shipping it to a shared Kubernetes cluster, I stopped and audited my own code.

The goal was not just to ship something that worked — it was to practice searching for, tracking, and fixing real vulnerabilities in production code I owned end to end. Writing this threat model pushed me to shift posture entirely: from thinking like a builder to thinking like an attacker.

This document covers 14 findings across severity levels, including a **critical argument-injection vulnerability that would have allowed unauthenticated remote code execution** on a shared cluster. Each finding includes the root cause, severity rating, and concrete remediation steps — not just what was wrong, but why it was wrong and how to close it.

Writing this improved my ability to build strong, clean, and secure code. It also changed how I think about security: several findings only became apparent when I reasoned about the *deployment environment*, not just the code itself. An SSRF that is harmless on a laptop becomes an internal-network oracle inside a cluster. That kind of context-dependent thinking is what this document is really about.

The application source code is held in a private institutional repository. This threat model is the public artifact.

---

**Topics covered:** argument injection, SSRF, path traversal, OAuth credential hygiene, debug mode exposure, PII disclosure, rate limiting, in-memory state durability, regex anchoring, and container deployment risks.


<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/84b8fc53-fff1-40d9-aaf0-e4c11117479b" />
