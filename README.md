# media-downloader-threat-model
This is a security review I wrote for a Flask web application I built as part of my role at a university IT department. The app lets students and staff download media from a submitted URL using a background job system. Before pushing it to a shared Kubernetes cluster, I audited my own code for vulnerabilities.

My goal was not just to ship something that worked. I wanted to practice finding, tracking, and fixing real security issues in code I built myself. It also pushed me to think differently. Building something and attacking it are two completely different mindsets, and writing this document forced me into the second one.

The review covers 14 findings including a critical argument injection vulnerability that would have allowed unauthenticated remote code execution on a shared cluster. Each finding includes what the issue was, why it existed, and how to fix it. Some of the most interesting findings only appeared when I thought about the deployment environment specifically, not just the code in isolation. An SSRF that is harmless on a laptop becomes a real threat inside a cluster where internal services are reachable.

Writing this made me a better and more security-conscious developer. The source code is held in a private institutional repository. This threat model is the public artifact.

Topics covered include argument injection, SSRF, path traversal, OAuth credential hygiene, debug mode exposure, PII disclosure, rate limiting, regex anchoring, and container deployment risks.


<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/84b8fc53-fff1-40d9-aaf0-e4c11117479b" />
