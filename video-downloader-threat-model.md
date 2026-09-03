# Threat Model - Video Downloader Web App

**Author:** Tobi Onabanjo
**Context:** Internal media tool built for a university digital media center
**Status:** Pre-deployment security review
**Last updated:** 2026-09-02

> **Note on scope.** This is a sanitized version of an internal threat model, published with permission. Institutional identifiers, colleague names, deployment specifics, and the exploitation details of findings that are not yet remediated have been removed. Findings marked **Resolved** are documented in full. Findings still open are listed by category and severity only.

---

## 1. Purpose

I wrote this before the app was containerized and handed to our IT department for hosting. The goal was to answer one question honestly: what is the worst thing someone could make this code do, and have I actually closed those paths.

It covers:

- What the system is and who can reach it
- Issues found and fixed earlier in development
- Findings from a formal review of the current code, with severity and remediation
- Risks introduced specifically by moving from a single laptop to shared infrastructure

---

## 2. System description

A Flask web app that lets students and staff download media from a pasted URL for coursework, using `yt-dlp` and `ffmpeg`. It replaced a single shared machine that one administrator had to operate on everyone's behalf.

**Flow:** user submits a URL, format choice, and optional email. Flask assigns a UUID and creates a per-job folder. A background worker runs `yt-dlp` as a subprocess. The frontend polls a status endpoint every 2 seconds. On completion the file is served from a download endpoint, and if an email was given, a notification goes out via the Gmail API.

**Components**

| File | Role |
|---|---|
| `app.py` | Flask routes, in-memory job registry, background job dispatch |
| `downloader.py` | Builds the `yt-dlp` argv list, runs and monitors the subprocess |
| `mailer.py` | Gmail API notification (OAuth2) |
| `cleanup.py` | Cron-driven deletion of expired job folders |
| `static/js/app.js` | Vanilla JS frontend, polling |

**Trust boundaries**

1. Browser to Flask (fully untrusted input)
2. Flask to `yt-dlp` subprocess (argv construction, see F-01)
3. `yt-dlp` to arbitrary remote hosts
4. Flask to Gmail API (holds a long-lived OAuth refresh token)
5. Flask to local filesystem

**Assets worth protecting**

- OAuth credentials for the sending mailbox (can send mail as the department)
- The reputation of the institutional mail domain
- The host the app runs on, and its network position
- Submitter email addresses and the URLs they requested
- Compute, disk, and bandwidth

**Assumed adversaries**

- **A1** - Any student on the network. Authenticated to nothing today; the app is open to anyone who can reach the URL. Motivated by curiosity, mischief, or free compute.
- **A2** - An unauthenticated outsider, if the app is ever exposed beyond the campus network.
- **A3** - A legitimate user causing accidental harm (huge playlists, repeated submissions).

---

## 3. Findings fixed prior to this document

These predate the F-numbering in Section 4 and were fixed earlier in development. Recorded because they explain why several current design choices exist.

### FIXED-01 - Filename collisions between concurrent users

Early versions wrote all downloads into one shared folder. Two users downloading videos with the same title could overwrite each other's files, and a user could get served a file they never requested. **Fix:** every job gets a UUID4 and its own folder. The UUID also acts as an unguessable capability for retrieval.

### FIXED-02 - Path traversal via user-controlled filenames and folder paths

User-influenced strings were used to build filesystem paths with no sanitization, so `../` sequences could escape the intended directory. **Fix:** `secure_filename()` applied to both the filename and any folder component derived from user input. `--restrict-filenames` passed to `yt-dlp` so titles pulled from remote sites can't introduce separators or shell-significant characters.

**Lesson:** sanitizing just the filename isn't enough. Every user-controlled segment that touches the filesystem needs it.

### FIXED-03 - Unvalidated email string reaching the filesystem and mailer

The submitted email was used with no format check. **Fix:** a regex validation gate that rejects malformed addresses with a 400 before any filesystem write or mail send. *(This fix turned out to be incomplete, see F-06.)*

### FIXED-04 - Silent codec mismatch producing unplayable files

Not a security issue, noted for completeness. `.mp4` files were coming out with AV1 video, which a lot of campus machines can't play. Diagnosed with `ffprobe`, fixed by forcing H.264 with an explicit codec selector.

---

## 4. Findings

Severity scale: **Critical** (unauthenticated code execution or credential loss), **High** (data disclosure, significant abuse, or serious escalation on deployment), **Medium** (availability, integrity, or defense-in-depth), **Low** (hardening).

---

### F-01 - Argument injection into `yt-dlp`, leading to remote code execution

**Severity: Critical. Status: Resolved.**

The submitted URL was appended to the argv list with no validation:

```python
command.extend([... , "-o", output_template, url])
```

Using `subprocess.Popen` with a list prevents shell injection, since the OS calls `execve` directly and no shell interprets metacharacters like `;` or `|`. That part was already correct.

What it does not prevent is `yt-dlp`'s own option parser interpreting the string. That parser is entirely separate from the shell, and like most CLI argument parsers it decides what is a flag by checking whether a token starts with `-`. Any submission beginning with `-` or `--` gets read as a flag, not a URL. `yt-dlp` exposes flags that run external commands, write files to arbitrary paths, and load configuration from disk. A single unauthenticated POST could therefore mean command execution as the application user.

Shell injection was closed. Argument injection was open. Different mechanism, same outcome.

This was the highest priority finding. On shared infrastructure it would mean an unauthenticated user executing code inside a pod on institutional hardware.

**Remediation implemented**

1. `validate_url()` added, called before any job is created. Uses `urllib.parse.urlparse` and rejects anything whose scheme is not `http`/`https`, or whose `netloc` is empty.
2. A bare `--` is inserted immediately before the URL in the argv list. This is a POSIX convention used by `git`, `ffmpeg`, and most `argparse`-based tools, meaning "everything after this point is positional data, regardless of what it looks like."
3. Both layers stay in place. The scheme allowlist blocks the obvious case; the `--` separator is the structural backstop that does not depend on anticipating every dangerous string.

**A subtlety worth recording:** the `--` fix only works if the URL is genuinely the last thing in the list. My first attempt broke the subtitle feature, because the URL was being appended mid-list and subtitle flags were added *after* it, meaning those flags would have been swallowed as positional data too. The working fix required restructuring the command builder so every possible flag is appended first and the `--`/URL pair is unconditionally last, regardless of which format or subtitle branch runs.

**Verification:** sent `--exec=id` and a non-http scheme as the URL field directly via `curl`, bypassing the frontend entirely. Both rejected with a 400 before the command builder was reached. Confirmed a valid URL still completes an end-to-end download after the change.

---

### F-02 - Server-side request forgery

**Severity: High. Status: Open, mitigation pending infrastructure decision.**

The download tool will attempt to fetch whatever host it is pointed at, from the server's network position. That position changes meaningfully when the app moves from a laptop to shared infrastructure, where internal services may be reachable that are not reachable from the public internet.

Partial mitigation is already in place via the URL scheme allowlist from F-01. Full remediation depends on a combination of application-level address filtering and a network-level egress policy, the latter of which is an infrastructure decision rather than a code change. Details omitted pending remediation.

---

### F-03 - Status endpoint returns more than the client needs

**Severity: High. Status: Open.**

The job status endpoint serializes an internal state object directly to the client rather than returning an explicit whitelist of fields, exposing data the frontend never consumes.

**Remediation:** return an explicit field whitelist. Never serialize an internal state object straight to a client.

---

### F-04 - Flask debug mode hardcoded on

**Severity: High. Status: Resolved.**

```python
app.run(debug=True)
```

Flask's debug mode enables the Werkzeug interactive debugger, which opens a Python console in the browser on any unhandled exception. In any environment where someone other than the developer can trigger an error, that is direct code execution. It also leaks stack traces containing file paths and in-scope variable state to anyone who can crash the app deliberately.

Manually flipping this to `False` before each deploy is not a control. It relies on remembering, every time, under deadline pressure, in a pipeline where this file may be built into an image without a final manual check.

**Remediation implemented:**

```python
is_production = os.environ.get("ENV") == "production"
app.run(debug=not is_production)
```

Debug mode now derives from an environment variable set at the deployment level rather than a hardcoded literal.

**Still outstanding:** running under a production WSGI server (`gunicorn`) rather than Flask's built-in development server.

---

### F-05 - OAuth credentials at risk of exposure via git history

**Severity: High. Status: Verified clean.**

The app sends completion notifications through the Gmail API, which means an OAuth client secret and a long-lived refresh token exist as files on disk. Anyone holding them could send mail from an official institutional address, which is a convincing phishing primitive.

Those files being `.gitignore`'d today says nothing about whether they were ever committed. Deleting a file from the working tree does not remove it from history; anyone who clones the repo can check out an old commit and recover it.

**Verification performed:**

```bash
git log --all -- token.json credentials.json
```

`--all` searches every branch rather than just the current one. Output was empty, confirming neither file has ever been committed. No rotation was necessary.

Had it not been empty, deletion alone would have been insufficient. A leaked credential does not become safe because the file is gone; it requires rotating the OAuth client secret at the provider and scrubbing history with a tool like `git filter-repo`.

**Remaining action:** on deployment, mount these as secrets rather than baking them into the container image.

---

### F-06 - Email validation regex is bypassable

**Severity: Medium. Status: Open.**

The email validation pattern uses anchors that do not behave the way they appear to in Python, permitting input the validator was intended to reject. Rated Medium rather than High because the mail library downstream is reasonably defensive, but a validator should not be the weak link.

Separately, the pattern accepts any domain, so the tool can currently be used to send mail to arbitrary external addresses.

**Remediation:** correct the anchoring, and restrict the accepted domain.

---

### F-07 - No proof of email ownership

**Severity: Medium. Status: Open, resolved by SSO rollout.**

Nothing verifies that the submitter owns the address they enter. Confirmed empirically, with consent, by submitting a job under a colleague's address and observing that they received a notification for a job they never started. The app is effectively an unauthenticated mail relay that sends from an official address.

**Remediation:** take the recipient address from the authenticated session once SSO is in place, rather than from a form field. Not validating a form field against the session, but removing the field entirely, since keeping both invites them to drift apart.

---

### F-08 - No rate limiting or resource ceilings

**Severity: Medium. Status: Partially resolved.**

Every submission unconditionally created a folder, spawned an OS thread, and started a subprocess, with no cap on concurrent jobs or request rate. A script, or one user pasting a very large playlist, could exhaust threads, fill the disk, saturate the uplink, or burn the mail API quota.

Worth separating two distinct controls here, because they solve different failure modes:

- **Rate limiting** bounds requests per unit time. It stops a tight scripted loop.
- **Concurrency limiting** bounds how many jobs are running simultaneously. It stops slow, steady submissions from piling up faster than they complete, which rate limiting alone does not catch: a request every 20 seconds never trips a per-minute limit, but if each job takes 10 minutes, dozens end up running at once.

**Remediation implemented:**

- **Concurrency ceiling:** raw per-request threads replaced with a `ThreadPoolExecutor` with a fixed worker count. Submissions beyond that queue automatically rather than spawning unbounded threads.
- **Rate limiting:** `Flask-Limiter` added, keyed by remote address, applied to the submission endpoint. Set generously for the expected usage pattern (students on personal devices during a class session, submitting a handful of downloads each, rather than scripted bursts).

**Still outstanding:** per-job size and playlist-length bounds on the download command, and container-level resource limits.

---

### F-09 - In-memory job registry grows without bound and is not durable

**Severity: Medium. Status: Open.**

Job entries are never evicted, so memory grows monotonically until restart. Conversely a restart discards all job state while the files remain on disk, leaving the cleanup cron as the only thing that reclaims them.

This also breaks under horizontal scaling: a user polling for status could be routed to an instance with no record of their job and receive a 404.

**Remediation:** short term, evict entries older than the retention window during the same sweep as file cleanup. Longer term, move job state out of process memory.

---

### F-10 - Retention window mismatch between code and user-facing copy

**Severity: Low (integrity and user trust). Status: Resolved.**

The notification email told users their files would be kept for 24 hours. The cleanup script was deleting folders older than `3600` seconds, which is one hour. Users were being told something untrue and could lose files they had been promised a full day to retrieve.

**A second bug surfaced while verifying this one.** Checking whether cleanup was running at all revealed that the cron entry's script path did not match its Python interpreter path, differing by one directory segment. The job had been failing silently on every hourly run, with nothing to indicate it.

**Remediation implemented:** retention threshold corrected to `86400` to match the promise made in the notification email. Cron path corrected and verified by manually executing the exact command cron runs.

**One open dependency:** this promise only holds if files survive the full window, which requires persistent storage attached to the container. Container filesystems are ephemeral by default; a restart or redeploy would wipe pending downloads regardless of age, breaking the promise even with the code fix in place. Flagged as an infrastructure requirement.

---

### F-11 - Hardcoded developer path in the cleanup script

**Severity: Low. Status: Resolved.**

```python
folder = "/home/<user>/Desktop/<project>/video_downloads"
```

This path would not exist in a container. Because the script guards its work behind `os.path.exists()`, it would not crash: it would simply do nothing, forever, while the disk filled up. It also leaked a local filesystem layout into a shared repository.

**Why this class of bug is worth calling out:** hardcoded absolute paths cause a disproportionate share of "works on my machine" failures precisely because they fail *silently*. A missing file usually raises something you notice immediately. A path that simply does not exist, sitting behind an existence guard, produces no error and no log line. It surfaces months later as "why is the disk full," with no trail back to the cause. In a containerized deployment, where the filesystem layout is guaranteed to differ from any developer's machine, every hardcoded path is a latent outage waiting for the next environment change.

**Remediation implemented:**

```python
base_dir = os.path.dirname(os.path.abspath(__file__))
folder = os.path.join(base_dir, "video_downloads")
```

The path is now derived from the script's own location at runtime, making it portable across machines and containers without code changes.

---

### F-12 - No containment check before serving a file

**Severity: Low (defense in depth). Status: Open.**

The served path is derived from a directory listing rather than from user input, so this is not currently exploitable. But the file is served with no assertion that the resolved path falls inside the intended download root. Any future change that lets user data influence that value turns this into arbitrary file read.

**Remediation:** assert that the real path of the file resolves inside the download root before serving.

---

### F-13 - Job URLs are unguessable capabilities, not authorization

**Severity: Low, informational. Status: Open, resolved by SSO rollout.**

Retrieval endpoints are protected only by the unguessability of a UUID4. That is a reasonable pre-authentication design and 122 bits of entropy is not brute-forceable, so this is not a "guess the ID" finding.

The real question is not whether an attacker can guess an ID, but every place a valid ID travels: the response body, the URL bar during polling, browser history, and server logs. Anyone who obtains one through those channels gets the file, because possession of the identifier is currently the only check.

**Remediation:** once authentication exists, bind jobs to the authenticated user and verify ownership on retrieval rather than treating knowledge of the ID as sufficient.

---

### F-14 - Missing transport and browser-hardening headers

**Severity: Low. Status: Open, depends on deployment configuration.**

No HSTS, CSP, `X-Content-Type-Options`, or `Referrer-Policy`. The frontend correctly uses `textContent` rather than `innerHTML` when rendering subprocess output, so there is no current XSS sink; a CSP would be defense in depth against future changes.

**Remediation:** determine whether the ingress layer terminates TLS and injects standard headers, or whether the application must set them itself.

---

## 5. Risks introduced by containerized deployment

| Change | New risk | Mitigation |
|---|---|---|
| App sits inside a private network | SSRF (F-02) can reach internal services | Egress policy, address filtering |
| Secrets must reach the container | Credentials baked into image layers | Mount as secrets, verify git history (F-05) |
| Ephemeral container filesystem | Downloads lost on restart, breaking F-10's promise | Persistent volume |
| Possible multiple replicas | In-memory job registry breaks (F-09) | Single replica, or externalize state |
| Publicly routable hostname | Wider exposure of every finding above | Resolve F-02 and F-03 before exposure, then SSO |

---

## 6. Remediation order

**Before pushing to source control**

1. ~~F-05, verify secrets are not in git history.~~ **Done, verified clean.**
2. ~~F-11, remove the hardcoded local path.~~ **Done.**

**Before any deployment reachable by others**

3. ~~F-01, URL scheme validation and `--` separator.~~ **Done.**
4. ~~F-04, debug mode driven by environment.~~ **Done.** *(Still to do: run under gunicorn.)*
5. F-03, whitelist the status response. *Open.*
6. F-02, address filtering and egress policy. *Open.*

**Before general release**

7. F-08, rate limiting and resource caps. **Partially done.**
8. F-06, correct the regex anchoring and restrict domain. *Open.*
9. ~~F-10, reconcile the retention window.~~ **Done.** *(Depends on persistent storage.)*
10. F-09, F-12, state eviction and path containment. *Open.*

**With authentication**

11. F-07, take the recipient from the session. *Open.*
12. F-13, bind jobs to users and verify ownership. *Open.*

---

## 7. Out of scope

- Copyright and terms-of-service considerations around downloading third-party media. Not a technical vulnerability, but raised separately with my supervisor.
- Vulnerabilities in `yt-dlp` and `ffmpeg` themselves. Mitigated by pinning versions and rebuilding on upstream security releases.

---

## 8. Resolution log

| Finding | Severity | Status |
|---|---|---|
| F-01, Argument injection RCE | Critical | Resolved |
| F-04, Flask debug mode | High | Resolved |
| F-05, Secrets in git history | High | Verified clean |
| F-08, Rate limiting and concurrency | Medium | Partially resolved |
| F-10, Retention window mismatch | Low | Resolved |
| F-11, Hardcoded path | Low | Resolved |
| F-02, F-03, F-06, F-07, F-09, F-12, F-13, F-14 | High to Low | Open |
