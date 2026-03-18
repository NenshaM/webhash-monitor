Starting a short todo plan for the security review and tracking progress.

Created 3 todos

Progress: security review started; next I'll list concise findings and recommended fixes.

**Summary Findings**
- **Module:** WebhashMonitor.py
  - **Logging config in library:** `logging.basicConfig()` is called at module import, which can unexpectedly configure logging for consumers. Risk: interferes with host app logging or leaks information.  
  - **Non-atomic file writes:** `hash_path.write_text()` overwrites files directly. Risk: partial writes or corruption under concurrent runs or interruptions.  
  - **Race conditions / concurrency:** No locking when reading/updating `hash` files. Risk: two processes may read/write the same file simultaneously causing lost updates.  
  - **Filename derivation uses MD5:** MD5(url) for filenames is predictable and MD5 is collision-prone. Risk: accidental collisions (low) and lack of intent-revealing filenames; slightly easier to infer mapping from hash if attacker has URL list.  
  - **No explicit permissions set on files/dirs:** Files inherit process umask; may be world-readable. Risk: hashes (which may be considered sensitive) could be exposed on multi-user systems.  
  - **Requests usage & SSRF potential:** URLs are accepted from config and passed directly to `requests.get`. If the tool runs with elevated privileges or in networked environments, untrusted URLs could target internal services (SSRF).  
  - **Logging of remote errors includes URL and exception:** `logger.error("Failed to fetch %s: %s", url, e)` may log full URL and error details. Risk: sensitive URLs or tokens in URL query strings could be logged.  
  - **No input validation or scheme restrictions:** Arbitrary schemes (file://, ftp://) could be accepted; behavior undefined.  
  - **Package naming inconsistencies:** Multiple similar package dirs (`webhasher_monitor`, `webhash_monitor`) exist in repo history—risk of importing wrong module in production or CI confusion.

**Recommendations (concrete)**
- **Remove global logging config from library**
  - Move `logging.basicConfig(...)` out of WebhashMonitor.py; configure logging only in CLI entry (main.py) or leave to user. Keep library-level `logger = logging.getLogger(__name__)`.
- **Make file writes atomic**
  - Write to a temp file then `os.replace()`/`Path.replace()` to atomically move into place. Example: write to `hash_path.with_suffix(".tmp")` then replace.
- **Add simple file locking or advisory locks**
  - Use `fcntl` (POSIX) or `portalocker` for cross-platform advisory locking around read/write to the hash file to avoid races.
- **Use stronger/safer filename derivation**
  - Use `sha256(url).hexdigest()` or base64-url-safe of sha256 to reduce collision risk and align with content hashing.
- **Set restrictive file permissions when creating files**
  - Use `os.open` with `mode=0o600` or after creation call `os.chmod(hash_path, 0o600)` to ensure only owner can read/write.
- **Harden request handling**
  - Validate or restrict URL schemes (allow only `http`, `https`). Reject or sanitize others.
  - Optionally resolve hostnames and detect private/internal IPs to reduce SSRF risk, or allow a configurable allowlist/denylist.
  - Use a `requests.Session()` if doing many requests (resource reuse), and set appropriate `timeout` and `allow_redirects=False` as needed.
- **Reduce logging verbosity for errors**
  - Log minimal error context at ERROR level and dump full exception details at DEBUG only. Avoid logging URLs containing secrets.
- **Document threat model and config guidance**
  - In README.md, explain that URLs should be trusted, where hashes are stored, and recommend running under a dedicated unprivileged user.
- **Standardize package layout**
  - Keep a single package name (`webhash_monitor`) and remove duplicate directories to avoid import ambiguity.
- **CI / Test considerations**
  - Ensure CI runs tests in an isolated tmpdir (already done with `tmp_path`), and that conftest.py path injection is intentional.
- **Optional: integrity verification**
  - If hashes are used for security (alerts), consider signing or storing metadata (timestamp) to avoid tampering.

If you want, I can:
- Implement the safest low-friction fixes now: move logging init out of WebhashMonitor.py, make writes atomic, and switch filename hash to SHA256. (I can apply patches and run tests.)