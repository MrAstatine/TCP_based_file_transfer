# 🔐 CN Secure File Transfer

This project is a Computer Networks (CN) course project that implements secure file transfer between machines over TCP with AES-based encryption.

## Future Work Roadmap

### 🔐 Security Upgrades (High Impact)

- ✅ Add message authentication (MAC verification)
   - Explicitly verify AES-EAX authentication tags instead of only decrypting.
   - Reject tampered or incomplete files automatically.

- ✅ Use password confirmation handshake
   - Perform a small encrypted challenge-response before sending full file.
   - Prevent wasting bandwidth on wrong passwords.

- ✅ Implement replay-attack protection
   - Add per-session IDs or timestamps.
   - Reject reused nonces or duplicated sessions.

- ✅ Rate-limit authentication attempts
   - Prevent brute-forcing the preset authentication code.

### 🌐 Networking Enhancements

- ✅ Support multiple concurrent clients
   - Use threading or asyncio on the receiver side.
   - Handle each client in an isolated session.

- ✅ Chunk-based streaming encryption
   - Encrypt/send files in chunks instead of loading entire file into memory.
   - Enable large file support and lower RAM usage.

- ✅ Resume interrupted transfers
   - Track byte offsets with chunk manifests.
   - Use receiver-side bitmaps so the sender resumes only missing chunks.

- ✅ Add configurable socket timeouts
   - Prevent hanging connections.

### 🧾 Protocol & Architecture Improvements

- ✅ Define a formal application-layer protocol
   - Message types: AUTH, METADATA, DATA, ACK, ERROR.
   - Version the protocol (for example CNFT/1.0).

- ✅ Add integrity verification summary
   - Send SHA-256 hash of original file.
   - Verify hash after decryption.

- ✅ Introduce session keys
   - Derive one session key once.
   - Derive per-file keys from it (HKDF-style design).

### 🧑‍💻 Usability & UX Improvements

- CLI flags instead of interactive input
   - Example flags: --host, --port, --outdir, --file.
   - Make scripts automation-friendly.

- ✅ Progress reporting on both sides
   - Sender shows live tqdm progress bar.
   - Receiver should show live progress too.

- Transfer summary report
   - Include file size, duration, throughput, and encryption mode.

- Structured logging
   - Replace print statements with logging levels (INFO, WARN, ERROR).

### 📦 Engineering & Code Quality

- Split crypto, networking, and UI into separate modules
   - Example modules: crypto.py, protocol.py, network.py.

- Add unit tests for crypto and protocol logic
   - Key derivation consistency tests.
   - Metadata parsing correctness tests.

- Add requirements.txt and Makefile
   - Improve setup and reproducibility.

- Add type hints and docstrings
   - Improve maintainability and interview-readiness.

### 🔄 Feature Extensions (Very Impressive)

- End-to-end public-key exchange
   - Use RSA or ECC to exchange AES keys securely.
   - Eliminate direct password sharing.

- Encrypted directory transfer
   - Recursively send folders.
   - Preserve folder structure and metadata.

- Basic access control
   - Authorized sender list or user accounts.

- Encrypted file storage on receiver
   - Keep files encrypted at rest.
   - Decrypt only on demand.

### 🧠 Academic / Resume-Level Enhancements

- Threat model documentation
   - Define attacker capabilities and defenses.

- Security comparison section
   - Compare this protocol with SCP/SFTP at a high level.

- Performance benchmarks
   - Measure throughput across multiple file sizes.

- Protocol diagram
   - Visualize handshake, key derivation, transfer, and verification phases.
