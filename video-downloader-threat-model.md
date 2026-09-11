# Threat Model: Media Downloader Web Service

A pre-deployment security review of a Flask application I built and then audited before shipping it to a shared container platform. I wrote this to practice threat modeling on real code I owned end to end, rather than on a textbook example.

The app lets authenticated users download media from a submitted URL using `yt-dlp` and `ffmpeg` behind a background-job system. It replaces a desktop application that was deployed across multiple lab machines and available for download by students and staff, moving that functionality to a browser-accessible web service. This document records the security posture before deployment: what the system is, what I found, what I fixed, and the new risks introduced by moving from a local desktop application to a shared cluster.

---

## 1. System description

A Flask web application that downloads media from a user-submitted URL.

**Flow:** the user submits a URL, format, and optional email. The server assigns a UUID and creates a per-job folder. A background thread runs `yt-dlp` as a subprocess. The frontend polls `/status/<id>` every 2s. On completion the file is served from `/file/<id>` and, if an email was given, a notification is sent via an email API.

**Trust boundaries**
1. Browser to server (fully untrusted input)
2. Server to `yt-dlp` subprocess (argv construction, see F-01)
3. `yt-dlp` to arbitrary remote hosts (see F-02)
4. Server to email API (holds a long-lived OAuth refresh token)
5. Server to local filesystem

**Assets worth protecting**
- The email OAuth credentials, which can send mail as an official address
- The reputation of the sending mail domain
- The host or pod the app runs on, and its network position inside the cluster
- Submitter email addresses and the URLs they requested
- Cluster resources (CPU, disk, bandwidth)

**Assumed adversaries**
- **A1.** Any authenticated user, motivated by curiosity, mischief, or free compute.
- **A2.** An unauthenticated outsider, if the app is ever exposed beyond its intended network.
- **A3.** A legitimate user causing accidental harm through huge playlists or repeated submissions.

---

## 2. Findings already fixed during development

**FIXED-01. Filename collisions between concurrent users.** Early versions wrote all downloads into one shared folder, so two users downloading videos with the same title could overwrite each other's files. Fix: every job gets a UUID4 and its own folder. The UUID also acts as an unguessable capability for retrieval.

**FIXED-02. Path traversal via user-controlled filenames.** User-influenced strings built filesystem paths without sanitization, allowing `../` to escape the intended directory. Fix: `secure_filename()` on every user-controlled path segment, plus `--restrict-filenames` on `yt-dlp` so remote titles cannot introduce separators. What I learned: sanitizing the filename is not enough. Every user-controlled segment that touches the filesystem must be sanitized.

**FIXED-03. Unvalidated email string reaching the filesystem and mailer.** Fix: a validation gate that rejects malformed addresses with a 400 before any write or send. This fix was later found incomplete, see F-06.

---

## 3. Current findings

Severity levels: **Critical** for unauthenticated code execution or credential loss, **High** for data disclosure, significant abuse, or serious escalation on deployment, **Medium** for availability, integrity, or defense-in-depth, **Low** for hardening.

### F-01. Argument injection into `yt-dlp`, leading to remote code execution. **Critical**

The submitted URL is appended to the argv list with no validation. Using `subprocess.Popen` with a list prevents *shell* injection, but it does not stop `yt-dlp`'s own option parser from interpreting the string. Any submission beginning with `-` or `--` is read as a flag rather than a URL, and `yt-dlp` exposes flags that run external commands, write files to arbitrary paths, and load config from disk. A single unauthenticated POST therefore yields command execution as the application user.

**Remediation:**
1. Parse with `urllib.parse.urlparse` and reject any scheme that is not `http` or `https`, and any empty netloc, before the job is created.
2. Insert a bare `--` argv element immediately before the URL so option parsing stops there.
3. Do both. The `--` separator alone still permits `file://` and `ftp://`, and the allowlist alone is fragile if it is ever bypassed.

**Verification:** submit `--exec=id` and `-o/tmp/pwned.%(ext)s` as URLs and confirm both are rejected with a 400 and that no subprocess starts.

### F-02. Server-side request forgery. **High**

`yt-dlp` fetches whatever host it is pointed at, from the server's network position. After deployment that is the inside of the cluster, where internal services and the node metadata endpoint are reachable without authentication. An attacker cannot read the full response body directly, but `yt-dlp`'s error output is streamed verbatim into the job log and returned by `/status/<id>`, which makes it an oracle for internal network mapping.

**Remediation:** apply the scheme allowlist from F-01. Resolve the hostname and reject RFC 1918, loopback, and link-local (`169.254.0.0/16`) ranges. Request an egress NetworkPolicy on the pod, which is stronger than app-level filtering and is not bypassable by DNS rebinding. Consider a domain allowlist as a policy decision.

### F-03. `/status/<id>` discloses the full job record. **High**

The endpoint serializes the entire internal job object, including the submitter's email (PII) and the absolute server file path (reconnaissance). The frontend only consumes `status`, `log`, and `subtitle_path`. **Remediation:** return an explicit field whitelist. Never serialize an internal state object directly to a client.

### F-04. Flask debug mode. **High**

Setting `debug=True` enables the interactive debugger, which offers a Python console on any unhandled exception. That is direct code execution if anyone but the developer can trigger an error. **Remediation:** run under a WSGI server such as `gunicorn`, drive debug from an environment variable defaulting to off, and confirm the deployment manifest does not set it.

### F-05. OAuth credentials at risk on repository push. **High**

The OAuth client secret and long-lived refresh token grant the ability to send mail as an official address, which is a convincing phishing vector. **Remediation:** confirm both files are in `.gitignore`. Check git *history*, not just the working tree, with `git log --all -- token.json credentials.json`. If either was ever committed, deleting it now does not remove it, so rotate the OAuth client and re-authenticate. Mount credentials as a platform Secret and never bake them into the image.

### F-06. Email validation regex is bypassable. **Medium**

The pattern anchored with `$`, which in Python matches before a trailing newline, so `victim@example.edu\n` passes. Newlines in a recipient field are the classic vector for mail header injection. **Remediation:** anchor with `\A` and `\Z`, or use `re.fullmatch` on a stripped value. Restrict the domain if the use case allows.

### F-07. No proof of email ownership. **Medium, resolved by SSO**

Nothing verifies that the submitter owns the address they enter. I confirmed this empirically: a request submitted with a colleague's address, with their knowledge, delivered a notification to them for a job they never started. Combined with F-08, this is a usable spam and phishing-pretext amplifier. **Remediation:** take the recipient from the authenticated session once SSO lands, rather than from a form field.

### F-08. No rate limiting or resource ceilings. **Medium**

Every POST unconditionally creates a folder, spawns a thread, and starts a process. There is no cap on concurrent jobs, request rate, download size, or playlist length. **Remediation:** add a global concurrent-job, per-user rate limiting, `--max-filesize` and `--no-playlist` on the command, and platform resource requests and limits on the pod.

### F-09. In-memory job registry grows unbounded and is not durable. **Medium**

Entries are never removed, so memory grows until restart, and a restart discards all job state while files remain on disk. Under multiple replicas this also breaks correctness: a user may be routed to a pod with no record of their job and receive a 404. **Remediation:** remove old entries in the cleanup sweep. Longer term, move state to shared storage such as Redis or SQLite.

### F-10. Retention window mismatch. **Low**

The notification says files are kept 24 hours, but cleanup deletes after one hour. Users are being told something untrue. **Remediation:** define retention as one named constant and reconcile the copy.

### F-11. Hardcoded developer path in cleanup. **Low**

An absolute local path will not exist in a container, so cleanup silently does nothing and disk fills. It also leaks the developer's local layout. **Remediation:** read the path from an environment variable with a sensible default, and run cleanup as a scheduled.

### F-12. No containment check before `send_file`. **Low, defense in depth**

The served path derives from a directory listing rather than user input, so it is not currently exploitable. But there is no check that it resolves inside the downloads root. **Remediation:** assert `os.path.realpath(path).startswith(os.path.realpath(ROOT))` before serving.

### F-13. Job URLs are unguessable capabilities, not authorization. **Low, informational**

`/file/<uuid>` is protected only by 122 bits of UUID4 entropy. That is reasonable before authentication exists, but the ID appears in browser history and anyone who obtains it gets the file. Once SSO exists, bind jobs to the user and check ownership.

### F-14. Missing transport and browser-hardening headers. **Low**

There is no HSTS, CSP, `X-Content-Type-Options`, or `Referrer-Policy`. The frontend uses `textContent` rather than `innerHTML`, so there is no current XSS sink. A CSP is defense in depth against future changes.

---

## 4. Risks introduced by the move to a shared cluster

| Change | New risk | Mitigation |
|---|---|---|
| Pod sits inside the cluster network | F-02 SSRF reaches internal services | Egress NetworkPolicy, private-IP blocklist |
| Secrets must reach the container | Credentials in image layers or in the repo | Platform Secrets, verify git history (F-05) |
| Ephemeral container filesystem | Downloads lost on restart | Persistent volume, cron becomes a scheduled job |
| Possible multiple replicas | In-memory registry breaks (F-09) | Single replica, or externalize state |
| Publicly routable hostname | Wider exposure of every finding | Resolve F-01 and F-04 before exposure, add SSO |

---

## 5. Remediation order

**Before pushing to the repo:** F-05 (verify and rotate secrets), F-11 (remove local path).

**Before any deployment reachable by others:** F-01 (blocking), F-04, F-03, F-02.

**Before general release:** F-08, F-06, F-10, F-09, F-12.

**With SSO:** F-07, F-13.

---

## 6. What I took away from this

Passing a list to `subprocess` stops shell injection but not the called program's own option parsing. The `--` separator and input validation are separate controls, and both are necessary.

The most dangerous findings change severity based on where they are deployed. An SSRF that has low impact on a local laptop becomes a pivotal entry point to the private network once it is inside a cluster. Threat models must be run against the actual target environment, not just the raw code.

Some vulnerabilities aren't tied to a single line of code. They happen because application the state lives in one replica (my computer) These issues only become visible when you look at how multiple replicas interact with each other.

Auditing my own code forced a different posture than building it. I had to assume every input was hostile, including the ones I wrote the happy path for.
