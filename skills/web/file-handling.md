# File Handling Vulnerabilities

**status:** active
**risk:** L0 (detection) – L2 (validation)
**approval:** L2 requires explicit approval
**program_types:** [web2, api]
**source:** reviewed from yaklang/hack-skills, BugBountySkills, recon bundle

## LFI (Local File Inclusion)

### Detection (L0)
- Path traversal: `../../../etc/passwd`
- Encoded variants: `..%2f`, `..%5c`, `%2e%2e%2f`, double-encoding
- Null-byte (PHP <5.3): `%00`
- Wrappers: `php://filter/convert.base64-encode/resource=index`
- Nested: `....//....//....//etc/passwd`
- Unicode/UTF-8: `..%c0%af`, `..%ef%bc%8f`

### Validation (L2 — approval required)
- Read `/etc/hostname` (harmless, proves LFI)
- Read source with php://filter (base64-encodes output)
- Read application config to prove impact
- **NEVER** read `/etc/shadow`, SSH keys, database files, or PII
- **NEVER** write files unless explicitly needed to prove RFI chain

### Key Files (per OS)
**Linux:** `/etc/passwd`, `/etc/hostname`, `/proc/self/environ`, `/proc/self/cmdline`
**Windows:** `C:\Windows\win.ini`, `C:\boot.ini`, `C:\Windows\System32\drivers\etc\hosts`

## RFI (Remote File Inclusion)

### Detection (L0)
- Include external URL: `http://your-server/test.txt`
- Check for DNS callback if HTTP fails
- SMB share: `\\your-server\share\test.txt` (Windows)

### Validation (L2 — approval required)
- Include a harmless PHP script from your server: `<?php echo "RFI_PROOF"; ?>`
- STOP after proving the include executes. Never include actual shells.

## File Upload

### Detection (L0)
- Upload allowed extensions
- Content-Type bypass: change MIME type, keep extension
- Double extension: `shell.php.jpg`, `shell.jpg.php`, `shell.php%00.jpg`
- Oversized files, empty files, negative content-length
- Race condition: upload + access before virus scan
- SVG XSS: `<svg><script>alert(1)</script></svg>` as profile image
- Zip slip: path traversal in archive filenames

### Validation (L2 — approval required)
- Upload a harmless PHP file: `<?php echo "UPLOAD_PROOF"; ?>`
- Confirm execution with a single request. STOP.
- Clean up: delete the uploaded file immediately.
- **NEVER** upload web shells, reverse shells, or malware.

## Path Traversal (Directory Traversal)

### Detection (L0)
- `../` sequences in file parameters
- Absolute paths: `/etc/passwd` in file parameter
- Windows: `..\`, `C:\`, UNC paths `\\server\share`
- Encoded: `..%2f`, `%2e%2e%2f`, `..%252f` (double-decode)
- Zip slip: crafted archive with `../../../` in filenames

### Key Indicators
- File download/view endpoints: `?file=`, `?path=`, `?template=`, `?page=`
- Image resizers/proxy: `?img=`, `?url=`
- Include/require parameters: `?include=`, `?require=`, `?load=`

## File Disclosure

### Detection (L0)
- Source code disclosure: `index.php.bak`, `index.php~`, `.index.php.swp`
- Config files: `web.config`, `appsettings.json`, `.env`, `config.yml`
- Version control: `.git/config`, `.git/HEAD`, `.svn/entries`
- IDE files: `.DS_Store`, `.idea/`, `.vscode/`
- Backup files: `*.bak`, `*.old`, `*.tar.gz`, `*.zip`, `*.sql`

## Stop Conditions

- LFI: prove with `/etc/hostname` (one file), stop
- RFI: prove with a single harmless PHP include, stop
- File upload: prove execution, clean up immediately
- File disclosure: confirm file exists with HEAD request, stop — do not download production secrets
