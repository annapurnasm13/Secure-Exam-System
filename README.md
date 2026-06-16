# Secure Exam System

This version uses no third-party libraries, no external APIs, no CDN files, and no API keys.

## Features
- AES-256 CTR encryption
- Time-based file release
- Passphrase-based decryption
- Admin and Faculty roles
- HMAC-SHA256 integrity verification
## Run

```bash
python app.py
```

Open http://127.0.0.1:5000 in a browser.

## Default logins

- Admin: `admin` / `admin123`
- Faculty: `faculty` / `faculty123`

## Encryption

Uploaded papers are encrypted with project-owned Python code: AES-256 in CTR mode for encryption, SHA-256/HMAC/PBKDF2 implemented manually in utils/encryption.py for key derivation and tamper checking. It does not use Python crypto libraries such as hashlib, hmac, secrets, cryptography, or Fernet for file encryption/decryption.

New AES-encrypted uploads use this demo passphrase in local testing:

```text
exam-pass
```

Do not forget the passphrase for real uploads. The app does not store it, so a forgotten passphrase cannot be recovered.

Old `SES2` encrypted files are not supported by the AES-only format. The app clears `SES2` files from `encrypted_files` and removes their database entries during startup. Existing `SES3` files can still be decrypted, and new uploads use the faster versioned `SES4` format.

## CrypTool and Wireshark

The AES file format is documented so it can be checked in CrypTool or similar classroom tools:

- Bytes `0..3`: magic value `SES4`
- Bytes `4..7`: PBKDF2 round count as a 4-byte big-endian integer
- Bytes `8..23`: 16-byte salt
- Bytes `24..35`: 12-byte nonce
- Bytes `36..-33`: AES-256-CTR ciphertext
- Last 32 bytes: HMAC-SHA256 tag over `SES4 || rounds || salt || nonce || ciphertext`

For AES verification, derive 64 bytes with PBKDF2-HMAC-SHA256 using the passphrase, salt, and the stored round count. The first 32 bytes are the AES-256 key, the last 32 bytes are the HMAC key. AES-CTR uses the 12-byte nonce followed by a 4-byte big-endian counter starting at `0`.

Wireshark can be used to observe the local HTTP upload and download flow on `127.0.0.1:5000`. It will show that encrypted files are transferred/stored as `SES4` ciphertext and that the app is not calling an external encryption API. Because the development server uses plain HTTP, Wireshark can also see submitted form fields on localhost; use it for lab observation only, not for production security.

