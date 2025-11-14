# Contents

- [Secure‑Programming Course Glossary](#glossary-of-concepts-covered-in-the-secureprogramming-course)
- [Secure Programming Sample Exam Glossary](#glossary-of-concepts-covered-in-the-secure-programming-sample-exam)

# Glossary of Concepts Covered in the Secure‑Programming Course
*(Alphabetical order, grouped by theme.)*

## A – C  

| Term | Expanded Definition |
|------|---------------------|
| **A/B Testing** | A controlled experiment that compares two versions of a system (e.g., a UI change or a security prompt) by routing a proportion of real traffic to each version. Used in SaaS and DevOps to validate that security‑related changes (like a new warning banner) improve user behavior without breaking functionality. |
| **Access Control Matrix** | A conceptual table that enumerates every **principal** (user, process, device) on rows and every **resource** (file, database table, API) on columns. The cell value describes the permitted operations (read/write/execute). It is the theoretical foundation for **ACLs** (column‑oriented) and **capabilities** (row‑oriented). |
| **Access Control List (ACL)** | A concrete representation of the Access‑Control Matrix stored *per resource* (the column). Each ACL entry lists the principals that may perform a given operation (e.g., `user:alice rwx`). ACLs are easy for administrators to read but can be inefficient for large systems because checking “who can do what” requires scanning many lists. |
| **Attack Tree** | A hierarchical, **goal‑oriented** model of how an adversary might achieve a specific objective (the root). Internal nodes are AND/OR logical connectors; leaves are atomic attacker actions. By assigning costs, probabilities, or skill levels to leaves, analysts can prioritize defenses, simulate “what‑if” scenarios, and communicate risk to non‑technical stakeholders. |
| **Authentication** | The process of verifying *who* a user (or machine) claims to be, typically via something they **know** (password), **have** (token, smart‑card), or **are** (biometrics). Successful authentication is a prerequisite for **authorization**. |
| **Authorization** | The policy decision that determines *what* an authenticated principal is allowed to do (e.g., read a file, perform a transaction). Implemented via ACLs, capabilities, role‑based access control (RBAC), or attribute‑based access control (ABAC). |
| **Bcrypt / Scrypt / Argon2** | Memory‑hard, adaptive password‑hashing functions that deliberately require large amounts of CPU and RAM, making brute‑force attacks expensive. They incorporate a random **salt** and a configurable cost factor, and are recommended over simple SHA‑1/MD5 hashing for password storage. |
| **Binary Exploit** | Any code execution technique that leverges a software bug (e.g., buffer overflow, use‑after‑free) to inject or repurpose machine instructions. Binary exploits include classic stack smashing, heap spraying, and Return‑Oriented Programming (ROP). |
| **Bi‑directional Control Characters (Trojan‑Source)** | Unicode characters with right‑to‑left (RTL) semantics (e.g., U+202E) that can reorder visible source code without changing its logical flow. When compiled, they can hide malicious logic; when displayed in a naïve editor, the code appears harmless. |
| **Botnet** | A network of compromised computers (or IoT devices) under the remote control of a **command‑and‑control (C2)** server. Botnets are used for distributed denial‑of‑service (DDoS) attacks, spam, credential stuffing, or cryptocurrency mining. |
| **Brute‑Force Attack** | Exhaustively trying every possible credential or key until the correct one is found. Effectiveness depends on password complexity, hash‑function cost, rate‑limiting, and lock‑out policies. |
| **CAPTCHA / reCAPTCHA** | A challenge–response test designed to distinguish humans from automated scripts. Modern CAPTCHAs often rely on behavioral analysis and image recognition; they are part of a **defense‑in‑depth** strategy against credential‑stuffing and automated account creation. |
| **Capability (in Access Control)** | A token, object, or data structure that **embodies** a set of access rights. Holding a capability grants the holder the permissions it encodes, without consulting a central authority. Capabilities are often more efficient for runtime checks than ACLs. |
| **CHERI (Capability Hardware Enhanced RISC Instructions)** | A research ISA that extends conventional pointers with **bounds** and **permissions** metadata, enabling fine‑grained memory safety at hardware level. By preventing out‑of‑bounds accesses, CHERI mitigates many memory‑corruption exploits (buffer overflows, use‑after‑free). |
| **CIA Triad** | The three foundational security goals: **Confidentiality**, **Integrity**, and **Availability**. Every security control can be evaluated against its impact on one or more of these pillars. |
| **CNC (Command‑and‑Control) Server** | The central server that issues instructions to compromised hosts (bots) and receives exfiltrated data. Defending against C2 traffic often involves detecting anomalous outbound connections or DNS tunneling. |
| **Code Signing** | The process of cryptographically signing executable code or packages with a **private key** so that recipients can verify authenticity and integrity using the corresponding **public key**. Code signing is crucial for trusted boot, software updates, and supply‑chain security. |
| **Credential Stuffing** | An automated attack that re‑uses credentials harvested from a breach (username/password pairs) against other services. It exploits the common human habit of **password reuse**. Mitigations include rate limiting, device‑based risk scoring, and **2FA**. |
| **Cross‑Site Request Forgery (CSRF)** | An attack that tricks an authenticated browser into submitting a state‑changing request (e.g., a money transfer) to a trusted site without the user’s intention. Countermeasures: anti‑CSRF tokens, SameSite cookies, and checking the `Referer` header. |
| **Cross‑Site Scripting (XSS)** | Injection of client‑side scripts (usually JavaScript) into web pages viewed by other users. Variants: **Stored** (persisted on the server) and **Reflected** (echoed in the response). Defenses: output encoding, Content‑Security‑Policy (CSP), and input sanitization. |
| **Cryptographic Hash Function** | A deterministic, one‑way function mapping arbitrary‑length input to a fixed‑size digest. Desired properties: **pre‑image resistance**, **second‑pre‑image resistance**, and **collision resistance**. Common families: SHA‑2, SHA‑3, BLAKE2. |
| **CSRF Token** | A random, per‑session value embedded in HTML forms or AJAX requests. The server validates that the token received matches the one it issued, ensuring the request originated from the legitimate site. |
| **CTF (Capture The Flag) Exercise** | A simulated security competition where participants exploit vulnerabilities, reverse‑engineer binaries, or solve crypto puzzles to capture “flags”. CTFs are popular training grounds for binary exploitation and reverse engineering. |
| **Default Password** | Manufacturer‑set credentials (often `admin/admin` or `1234`) that are shipped with hardware/software. Leaving default passwords unchanged is a leading cause of large‑scale compromises (e.g., Mirai IoT botnet). |
| **Denial‑of‑Service (DoS) / Distributed DoS (DDoS)** | An attack that overwhelms a target’s resources (CPU, memory, network bandwidth) rendering it unavailable to legitimate users. Mitigations: traffic scrubbing, rate limiting, and anycast. |
| **Deterministic Random Bit Generator (DRBG)** | A pseudo‑random number generator used in cryptographic contexts. Weaknesses (e.g., the NSA‑influenced Dual_EC_DRBG) can introduce backdoors; modern standards recommend NIST SP 800‑90A compliant constructions. |
| **Diffie‑Hellman Key Exchange** | A protocol that allows two parties to jointly compute a shared secret over an insecure channel. Vulnerable to **log‑jam** attacks if parameters are weak; replaced in many modern protocols by **Elliptic‑Curve Diffie‑Hellman (ECDH)**. |
| **Digital Signature** | A cryptographic primitive that provides **non‑repudiation**, **integrity**, and **authentication** of a message. Created by signing a hash of the message with a private key (RSA, DSA, ECDSA). |
| **DoS Amplification** | An attack technique that exploits a service’s disproportionate response size (e.g., DNS, NTP) to amplify traffic toward the victim. |
| **Dynamic Analysis (DAST)** | Testing of an application **while it is running** (black‑box). It observes actual behavior, catches runtime errors, and can confirm exploitability of reported bugs. |
| **Eavesdropping** | Passive interception of data (network packets, side‑channel emissions, etc.) without altering it. Countered by encryption (TLS, VPN) and physical isolation. |
| **ECC (Elliptic‑Curve Cryptography)** | A family of public‑key algorithms based on the algebraic structure of elliptic curves over finite fields. Offers comparable security to RSA with much smaller key sizes (e.g., 256‑bit ECC ≈ 3072‑bit RSA). |
| **Edge Computing** | Processing data close to the source (IoT, sensors) rather than sending everything to the cloud. Improves latency but introduces new attack surfaces (e.g., compromised edge nodes). |
| **Enterprise Risk Management (ERM)** | A systematic process to identify, assess, and mitigate risks across an organization, integrating security, compliance, and business continuity. |
| **Entropy (in Cryptography)** | A measure of unpredictability or randomness. High‑entropy secrets (keys, salts) are crucial for resisting brute‑force attacks. |
| **Exploit Kit** | A collection of ready‑made exploits (often for browser or plug‑in vulnerabilities) that attackers embed in malicious sites to automatically compromise visitors. |
| **Fuzzing** | Automated generation of massive amounts of semi‑random or structured inputs to a program to discover crashes, hangs, or security‑relevant bugs. Variants: **mutation‑based**, **generation‑based**, **coverage‑guided** (e.g., AFL, libFuzzer). |
| **Garbage Collection (GC) / Use‑After‑Free (UAF)** | In languages with automatic memory management, a **use‑after‑free** may still happen when manual pointer arithmetic is used (e.g., C extensions). Detectable via sanitizers, address‑sanitizer (ASan), or memory‑safe languages. |
| **GPG / PGP** | Open‑source implementations of the OpenPGP standard for public‑key encryption, digital signatures, and key management. Often used for secure email (S/MIME, PGP‑MIME). |
| **Hash‑based Message Authentication Code (HMAC)** | A MAC constructed from a cryptographic hash function and a secret key, providing integrity and authenticity. Commonly used in TLS, JWT, and API request signing. |
| **Header‑Only Library** | A C/C++ library distributed entirely as source headers; eases integration but can increase the attack surface if not audited (e.g., many vulnerabilities in popular header‑only libs). |
| **Heap Spraying** | An exploitation technique that allocates large amounts of memory filled with attacker‑controlled data, increasing the probability that a later memory‑corruption bug lands in attacker‑controlled space. |
| **Hybrid Threat** | An adversary that combines **state‑sponsored capabilities** (e.g., zero‑day exploits) with **criminal monetization** (ransomware, theft). |
| **IAM (Identity and Access Management)** | Enterprise frameworks (e.g., Azure AD, Okta) that centralize authentication, authorization, provisioning, and auditing of user identities. |
| **Implicit Flow (OAuth 2.0)** | An OAuth grant type where the access token is returned directly in the redirect URI, primarily used by single‑page applications. Less secure than Authorization Code flow because it does not involve a client secret. |
| **Information Disclosure** | A breach of **confidentiality** where unauthorized parties obtain data (e.g., via SQL injection, buffer overread, or side‑channel leakage). |
| **Injection (SQL, OS, Command, XPath, etc.)** | Vulnerability pattern where untrusted input is interpreted as code or commands by an interpreter. Proper mitigation: **parameterized queries**, **escaping**, and **input validation**. |
| **Integrity (in CIA)** | Assurance that data has not been altered in an unauthorized way. Guarantees are provided by checksums, digital signatures, and write‑once storage. |
| **IoT (Internet of Things)** | Network‑connected physical devices (sensors, cameras, appliances). Security challenges include default credentials, lack of update mechanisms, and limited computational resources for crypto. |
| **IPSec** | Suite of protocols for securing IP traffic via encryption (ESP) and authentication (AH). Commonly used for VPNs; modern implementations rely on strong ciphers (AES‑GCM) and robust key‑exchange (IKEv2). |
| **JIT (Just‑In‑Time) Compilation** | Runtime compilation of bytecode to native code; can introduce side‑channel leakage (e.g., Spectre) because speculatively executed code may touch secret‑dependent memory. |
| **JSON Web Token (JWT)** | Compact, signed token format used for stateless authentication. Contains a header, payload (claims), and signature. Sensitive claims must be protected; use short expiration and rotate signing keys. |
| **Key‑Derivation Function (KDF)** | A cryptographic primitive (e.g., PBKDF2, Argon2) that stretches a low‑entropy secret (password) into a high‑entropy key. KDFs incorporate salts and configurable iteration counts. |
| **LFI / RFI (Local/Remote File Inclusion)** | Web‑application bugs that allow an attacker to include arbitrary files from the server (LFI) or a remote URL (RFI), often leading to code execution. |
| **Least Privilege** | Principle that a subject (user, process, service) should be granted only the permissions required to perform its job. Reduces blast radius of compromised accounts. |
| **LDAP Injection** | Similar to SQL injection but targets LDAP queries. Mitigation: proper escaping or using parameterized LDAP APIs. |
| **Load‑Balancing (L7/L4)** | Distribution of network traffic across multiple servers. Application‑layer (L7) load balancers can also enforce security policies (e.g., WAF). |
| **Log4j Vulnerability (Log4Shell, CVE‑2021‑44228)** | Remote code execution via JNDI lookups in the Log4j logging library; illustrates the danger of **deserialization** and **untrusted data** in libraries. |
| **Malware** | Malicious software with intent to harm, steal data, or disrupt services. Families include **viruses**, **worms**, **trojans**, **ransomware**, **rootkits**, **botnets**, **polymorphic**, and **metamorphic** code. |
| **Man‑in‑the‑Browser (MitB)** | Malware that runs inside the browser (e.g., a malicious extension) and intercepts or alters web traffic after the TLS termination point, stealing credentials or injecting fraudulent transactions. |
| **Man‑in‑the‑Middle (MitM)** | Active network attacker who intercepts, modifies, or relays communications between two parties. Countered with mutual TLS, certificate pinning, and HSTS. |
| **Mitigation (Security Control)** | Any measure (technical, procedural, or administrative) that reduces the likelihood or impact of a security risk. |
| **Mitre ATT&CK Framework** | A globally‑accessible knowledge base of adversary tactics and techniques, organized by **kill chain** stages (e.g., Recon, Initial Access, Persistence). Used for threat‑modeling, detection, and red‑team planning. |
| **Modular Exponentiation (RSA)** | The core operation of RSA encryption/signature (`c = m^e mod n`). It requires safe padding (OAEP for encryption, PSS for signatures) to avoid deterministic or chosen‑ciphertext attacks. |
| **Monzo‑style “App‑Only” Auth** | A model where the bank’s mobile app is the sole authentication channel, relying on device‑based biometrics and secure enclave storage, eliminating traditional passwords for many flows. |
| **Multifactor Authentication (MFA)** | Requiring two or more of **something you know**, **have**, or **are**. Stronger than 2FA that uses only an OTP, MFA can include hardware tokens (YubiKey) or biometrics. |
| **NAT (Network Address Translation)** | A technique that maps many private IP addresses to a single public IP. While valuable for conservating address space, NAT can obscure source attribution for inbound attacks. |
| **NIST SP 800‑53 / 800‑171** | US government publications providing security and privacy controls for federal information systems and contractors. They drive many industry compliance programs (e.g., CMMC). |

---  

## D – F  

| Term | Expanded Definition |
|------|---------------------|
| **DLL Hijacking** | Exploiting the Windows search order for Dynamic‑Link Libraries so that a malicious DLL placed in a directory under the attacker’s control is loaded by a privileged process, achieving **privilege escalation**. Mitigations: `SafeDllSearchMode`, code signing verification, and DLL‑allow‑list. |
| **Domain‑Generation Algorithm (DGA)** | An algorithm used by malware to algorithmically generate a large number of domain names (often daily) for C2 communication, making static blacklists ineffective. Detectable via machine‑learning on domain entropy and NX‑Domain rates. |
| **Double Submit Cookie** | CSRF mitigation technique where a token is sent both as a cookie and as a request parameter; the server verifies that both values match. |
| **DRM (Digital Rights Management)** | Technological restrictions placed on digital content (e.g., video, e‑books) to control usage. Often introduces **security‑by‑obscurity** that can be bypassed (e.g., key‑extraction from DRM-enabled media). |
| **ECC Curve (e.g., Curve25519)** | A specific elliptic‑curve chosen for good performance and resistance to known attacks. Curve25519 is used for Diffie‑Hellman key exchange and Ed25519 for signatures. |
| **EIP (Instruction Pointer)** | CPU register that holds the address of the next instruction to execute. Overwrites (e.g., via stack overflow) enable **control‑flow hijacking**. |
| **Elliptic‑Curve Diffie‑Hellman (ECDH)** | DH key‑exchange performed over an elliptic‑curve group; yields small keys and fast computations. Frequently used in TLS 1.3 (e.g., `ECDHE_RSA`). |
| **Encryption‑at‑Rest** | Data stored on disk is encrypted to protect confidentiality if the storage media is stolen. Implementations: LUKS, BitLocker, Transparent Data Encryption (TDE). |
| **Entropy‑Based Password Meter** | Tool that estimates password strength based on estimated entropy (bits of randomness). Encourages users to use passphrases or random character strings. |
| **Error‑Based Oracle (e.g., Bleichenbacher)** | An RSA padding oracle that reveals information via distinct error messages (invalid padding vs. invalid ciphertext). Modern TLS libraries mitigate this with constant‑time error handling. |
| **Exploit Mitigation** | OS‑level defenses such as **DEP/NX**, **ASLR**, **Control‑Flow Integrity (CFI)**, **Stack Canaries**, and **SafeSEH** that make it harder to turn a bug into a reliable exploit. |
| **FIDO2 / WebAuthn** | A password‑less authentication standard that uses public‑key cryptography and a hardware authenticator (e.g., security key) to perform a **cryptographic challenge**. |
| **File‑Inclusion (LFI/RFI)** | Vulnerabilities that allow inclusion of arbitrary files (local or remote) into a server‑side script, often leading to code execution. |
| **Filesystem Permissions (UNIX)** | The classic `rwx` triplet for **owner**, **group**, and **others**. Modern extensions include ACLs and extended attributes (e.g., SELinux contexts). |
| **Firmware Rootkit** | Malware that resides in low‑level firmware (BIOS/UEFI, network card, hard‑disk controller). It persists across OS reinstallations and can hide the presence of other malware. |
| **Forward Secrecy (FS)** | Property of a key‑exchange protocol where the compromise of long‑term private keys does **not** compromise past session keys. Achieved in TLS via **DHE/ECDHE** handshakes. |
| **Fuzzing Harness** | Small driver program that supplies inputs to the target system (library, CLI tool, or API) and observes for crashes or hangs. Harnesses include **AFL** forks or libFuzzer **LLVM** instrumentation. |
| **FUTEX (Fast Userspace Mutex)** | A Linux kernel primitive used for efficient user‑space synchronization; can be abused in **priority inversion** attacks if not correctly used. |

---  

## G – I  

| Term | Expanded Definition |
|------|---------------------|
| **GPGPU (General‑Purpose GPU) Computing** | Using GPUs for non‑graphics workloads (e.g., password cracking with Hashcat). Offers massive parallelism, dramatically reducing time to brute‑force high‑entropy passwords but also raising the stakes for using strong, memory‑hard hash functions. |
| **Garbage‑In‑Garbage‑Out (GIGO)** | Principle that poor‑quality input (e.g., unsanitized user data) leads to insecure or incorrect output; emphasizes the need for **input validation**. |
| **GET/POST (HTTP Methods)** | `GET` retrieves data without side effects; `POST` submits data that may change state. Misusing `GET` for actions that modify state can lead to CSRF vulnerabilities. |
| **GPG/PGP Encryption** | Public‑key encryption protocol that provides confidentiality, integrity, and non‑repudiation. Utilizes **RSA/ECDH** for key exchange and **ELGamal**/RSA for encryption. |
| **HSM (Hardware Security Module)** | Tamper‑resistant device that stores cryptographic keys and performs operations (signing, decryption) inside the secure boundary. Often used for PKI, TLS termination, and secure key management. |
| **Hash‑Based Password Attacks** | Use pre‑computed hash tables (rainbow tables) to reverse weak password hashes. Modern defenses: per‑user **salt** and **slow** hash functions (bcrypt, Argon2). |
| **Header Injection** | Attack that manipulates HTTP response headers (e.g., `Location`) to conduct XSS or open redirects. Proper sanitization of any user‑supplied values placed in headers mitigates the risk. |
| **Heap‑Based Buffer Overflow** | Corruption of dynamically allocated memory, often exploited via `malloc`/`free` mis‑use. Can lead to **arbitrary code execution** after manipulation of the heap’s metadata (e.g., `unlink` technique). |
| **HEVC (High Efficiency Video Coding)** | Although not a security term, it exemplifies **complex codecs** that may have exploitable parsing bugs (e.g., CVE‑2020‑XYZ). |
| **HTTP Strict Transport Security (HSTS)** | Response header (`Strict‑Transport‑Security`) that forces browsers to use HTTPS for a domain, mitigating SSL‑strip attacks. |
| **HTTPS (TLS over HTTP)** | Secure version of HTTP that provides confidentiality, integrity, and server authentication via X.509 certificates. |
| **IA-32 / x86‑64 Architecture** | Popular CPU families whose complex **speculative execution** pipelines gave rise to side‑channel attacks like **Spectre** and **Meltdown**. |
| **IDE (Integrated Development Environment)** | While primarily a developer tool, many IDEs now integrate **static analysis**, **dependency checking**, and **runtime instrumentation** to help catch security bugs early. |
| **IEE 802.1X (Port‑Based Network Access Control)** | Network authentication protocol that uses EAP (Extensible Authentication Protocol) to authenticate devices before granting LAN access; helps prevent rogue devices. |
| **Impersonation Attack** | Social‑engineering technique where an attacker pretends to be a trusted entity (e.g., “Your bank”) to obtain credentials. Countered with user education, anti‑phishing DNS (DMARC/DKIM), and **out‑of‑band verification**. |
| **Insecure Direct Object Reference (IDOR)** | When an application uses user-supplied identifiers to access objects without verifying ownership, allowing an attacker to retrieve or modify another user’s data. |
| **Integrity‑Checking Tools (Tripwire, AIDE)** | Systems that compute cryptographic hashes of critical files and compare them to a known‑good baseline to detect unauthorized changes. |
| **Intent‑Based Networking** | Emerging paradigm that automates network policies based on high‑level business intent, potentially reducing configuration bugs that lead to security incidents. |
| **IoC (Indicator of Compromise)** | Artefacts (hashes, IPs, domains, registry keys) that suggest a system has been compromised. Used by SIEMs and threat‑intel platforms for detection and hunting. |
| **IPSec ESP (Encapsulating Security Payload)** | Provides confidentiality, integrity, and anti‑replay for IP packets; widely used in site‑to‑site VPNs. |
| **JIT Hardening** | Techniques (e.g., disabling `JIT` in browsers, adding side‑channel mitigations) to reduce the attack surface of just‑in‑time compilation engines. |
| **JWT (JSON Web Token)** | Compact, URL‑safe means of representing claims to be transferred between two parties. Signed with HMAC or RSA/ECDSA; must be stored securely because possession of a valid token grants access. |
| **Kerckhoffs’ Principle** | The security of a cryptosystem should rely **only** on the secrecy of the key, not on the secrecy of the algorithm. Encourages use of well‑studied, open algorithms. |
| **Key‑Escrow** | A system where encryption keys are stored by a trusted third party (often mandated by governments). Controversial because it creates a high‑value target for attackers and can be abused for surveillance. |
| **Key‑Rotation** | Periodic replacement of cryptographic keys to limit exposure if a key is compromised. Often automated via key‑management services (KMS). |
| **Kernel Address Space Layout Randomization (KASLR)** | Extension of ASLR to randomize the location of the kernel image in memory, making kernel‑mode exploits harder. |
| **Known‑Plaintext Attack (KPA)** | Cryptanalytic technique where the attacker knows (or can guess) some plaintext corresponding to ciphertext, allowing deduction of the key or structure of the cipher. |
| **Lateral Movement** | The phase of an intrusion where the attacker moves from the initially compromised system to other assets on the network, often using stolen credentials (credential dumping) or exploiting trust relationships. |
| **Least Privilege** | See “Least Privilege” above (re‑listed for alphabetical completeness). |
| **Load‑Time Code Generation** | Some JIT compilers generate machine code from scripts at load time; this can be a vector for **code‑injection** if the source is untrusted. |
| **Log Aggregation (ELK Stack, Splunk)** | Centralizing logs from many sources to enable correlation, detection, and forensic analysis. Critical for security incident response. |
| **Log4j (Log4Shell)** | Vulnerability in Apache Log4j 2.x that allowed remote code execution via JNDI lookups. Demonstrated the danger of **deserialization** and **untrusted data** in logging frameworks. |
| **Losing the Keys** | Situation where cryptographic keys are lost or unrecoverable, resulting in data that can no longer be decrypted. Proper key‑backup and escrow policies mitigate this risk. |
| **Machine Learning (ML) for Security** | Use of supervised/unsupervised models to detect anomalies, classify malware, or predict zero‑day exploits. Requires careful data handling to avoid adversarial attacks. |
| **Man‑in‑the‑Browser (MitB)** | See “Man‑in‑the‑Browser” above. |
| **Man‑in‑the‑Middle (MitM)** | See “Man‑in‑the‑Middle” above. |
| **MFA (Multi‑Factor Authentication)** | See “Multifactor Authentication” above. |
| **Memory‑Safe Languages (Rust, Go, Swift)** | Languages designed to eliminate common memory safety bugs (buffer overflows, use‑after‑free) via ownership models, garbage collection, or bounds‑checked arrays. |
| **MFA Fatigue Attack** | Social‑engineering technique where repeated push notifications for MFA are sent until the user approves one. Mitigated by limiting the number of MFA prompts per timeframe. |
| **Mitigation (Security Control)** | See “Mitigation (Security Control)” above. |
| **MITRE ATT&CK** | See “MITRE ATT&CK Framework” above. |
| **Mobile Device Management (MDM)** | Enterprise tool for enforcing security policies (e.g., encryption, password complexity, remote wipe) on smartphones and tablets. |
| **Monolithic Kernel vs Microkernel** | Architectural distinction; monolithic kernels place many drivers in kernel space (increasing attack surface), while microkernels keep most services in user space, reducing the impact of a compromised driver. |
| **MQL (Meta‑Query Language)** | Not directly a security term; omitted. |
| **MTP (Man‑in‑the‑Parking)** | Not applicable. |

---  

## J – N  

| Term | Expanded Definition |
|------|---------------------|
| **JWT (JSON Web Token)** | Already covered; see above. |
| **Kernel Hardening** | Collection of security techniques applied to the operating‑system kernel, such as **grsecurity**, **PaX**, **SELinux**, **AppArmor**, **SMEP/SMAP** (preventing code execution from user pages). |
| **Key‑Derivation Function (KDF)** | Already covered; see above. |
| **Lattice‑Based Cryptography** | Post‑quantum cryptographic schemes (e.g., **Kyber**, **Dilithium**) relying on hardness of lattice problems. Offer resistance to Shor’s algorithm, making them candidates for **PQC** (Post‑Quantum Cryptography) standardization. |
| **LFI (Local File Inclusion)** | See “File‑Inclusion (LFI/RFI)” above. |
| **Log Sanitization** | Process of removing or redacting sensitive data (PII, secrets) from logs before storage or transmission to prevent leakage. |
| **Log Rotation** | Periodic archiving/compression of log files to prevent uncontrolled growth and to enforce retention policies. |
| **Log‑Based IDS** | Intrusion detection that correlates events from logs (e.g., failed logins, privilege escalations) instead of network traffic. |
| **Malware‑as‑a‑Service (MaaS)** | Business model where cyber‑criminals sell exploit kits, ransomware, or botnet rentals via subscription. |
| **Man‑in‑the‑Browser (MitB)** | See above. |
| **Man‑in‑the‑Middle (MitM)** | See above. |
| **Man‑in‑the‑Browser (MitB)** | Duplicate entry; omitted. |
| **Markov Model (for Password Guessing)** | Statistical model that predicts the likelihood of character sequences based on observed password leaks. Used to improve **password crackers** and also to design better password policies. |
| **Memory‑Corruption Bugs** | General class covering buffer overflows, heap overflows, integer overflows, use‑after‑free, and double frees. Each can subvert control flow or data confidentiality. |
| **Mitigation (Security Control)** | See above. |
| **MITRE ATT&CK** | See above. |
| **Mobile Banking Attack Vectors** | Include **malware injecting UI overlays**, **SMS phishing (vishing)**, **fake banking apps**, and **SIM‑swap** attacks. |
| **ModSecurity** | Open‑source web application firewall (WAF) that can detect SQLi, XSS, and other OWASP Top‑10 attacks via rule‑based engine. |
| **Monolithic Kernel** | See above. |
| **NAT Traversal** | Techniques (STUN/TURN, ICE) that allow peer‑to‑peer traffic through NAT devices; essential for VoIP and WebRTC but can also be abused by malware to reach C2 servers. |
| **NDR (Network Detection and Response)** | Advanced network security that combines detection with automated response (e.g., quarantine, traffic shaping). |
| **Nonce** | Random or monotonic value used only once (e.g., in authentication protocols) to prevent replay attacks. |
| **NTP Amplification Attack** | DDoS technique that abuses misconfigured NTP servers (command `monlist`) to reflect massive traffic toward a victim. |
| **NTP (Network Time Protocol) Security** | Authenticated NTP (RFC‑5905) mitigates spoofing and amplification; however many servers run unauthenticated NTP, exposing them to reflection attacks. |
| **NVMe / SSD Firmware Attacks** | Exploits that target the firmware of solid‑state drives to persist malware (e.g., **BadUSB**, **bootkits**). |

---  

## O – R  

| Term | Expanded Definition |
|------|---------------------|
| **OAuth 2.0** | Authorization framework that enables a third‑party application to obtain limited access to an HTTP service. Uses **grant types** (authorization‑code, implicit, client‑credentials, etc.). Must be combined with PKCE for native apps to mitigate code‑interception. |
| **Obfuscation (Code)** | Techniques (renaming, control‑flow flattening, dead code insertion) that make reverse engineering harder. Helpful for protecting intellectual property but can also hide malicious intent (polymorphic/metamorphic malware). |
| **Oblivious DNS (ODNS)** | DNS queries sent through an anonymity network (e.g., Tor) to prevent the resolver from learning the client’s IP address, enhancing privacy. |
| **One‑Time Password (OTP)** | Short‑lived numeric code generated by a token or app (e.g., TOTP, HOTP). Used as a second factor in **2FA**. |
| **Open‑Source Software Supply Chain** | The practice of incorporating community libraries into products. Vulnerabilities (e.g., **event‑stream** compromise) can propagate widely. SBOMs (Software Bill of Materials) are becoming mandatory to track dependencies. |
| **OS Credential Dumping** | Extraction of stored credentials (e.g., `lsass.exe` memory dump on Windows, `/etc/shadow` on Linux). Tools: Mimikatz, `pwdump`. |
| **Password Cracking** | Process of recovering plaintext passwords from hash values using brute‑force, dictionary, or rainbow‑table attacks. |
| **Password Manager** | Application (browser‑based or standalone) that stores encrypted passwords and auto‑fills login forms. Strong managers use a master password and PBKDF2/Argon2 for the vault. |
| **Password Salt** | Random data concatenated with a password before hashing to guarantee unique hash values even for identical passwords. |
| **Patch Management** | Process of acquiring, testing, and deploying software updates to fix security flaws. Essential for reducing **exposure window**. |
| **Phishing** | Social engineering attack that lures victims to a fake site or email to harvest credentials. Modern variants include **spear‑phishing**, **whaling**, and **vishing** (voice phishing). |
| **PKCS#11** | API for interfacing with cryptographic tokens (HSMs, smart cards). Facilitates uniform access to private keys and secure operations. |
| **PKI (Public Key Infrastructure)** | Hierarchical system for issuing, revoking, and managing digital certificates (X.509). Enables TLS, code signing, and S/MIME. |
| **PoC (Proof of Concept)** | Minimal exploit or demonstration that shows a vulnerability is real. Often shared publicly to raise awareness or pressure vendors to patch. |
| **Pod Security Policy (Kubernetes)** | Old Kubernetes object that defines a set of conditions a pod must meet (e.g., non‑root user, read‑only root filesystem) to improve container security. |
| **Polymorphic Malware** | Malware that encrypts or otherwise transforms its own code on each infection while preserving functionality, evading signature‑based detection. |
| **Port Knocking** | Security technique where a client sends a sequence of connection attempts to closed ports; only after the correct sequence does the firewall open the desired port. |
| **Post‑Quantum Cryptography (PQC)** | Cryptographic algorithms believed to be resistant to attacks by quantum computers (e.g., lattice‑based, hash‑based, code‑based). NIST is standardizing a suite for future deployment. |
| **Pre‑Shared Key (PSK)** | Symmetric key manually configured on both ends of a connection (e.g., WPA‑PSK Wi‑Fi). Simpler but less scalable and harder to rotate than certificate‑based authentication. |
| **Privilege Escalation** | Technique that moves a process from a lower privilege level to a higher one (e.g., exploiting setuid binaries, kernel exploits). |
| **Probe (Network Recon)** | Scanning activity (e.g., Nmap, banner grabbing) to enumerate services, versions, and potential vulnerabilities. |
| **Public‑Key Encryption (RSA, ECC)** | Encryption method where the sender encrypts data using the recipient’s public key; only the recipient’s private key can decrypt. |
| **Pwned Passwords (HaveIBeenPwned)** | Service that allows users to check if a password has been exposed in a data breach, encouraging the use of unique passwords. |
| **Quantum‑Resistant Algorithm** | See **Post‑Quantum Cryptography**. |
| **RASP (Runtime Application Self‑Protection)** | Security technology that instruments an application at runtime to detect and block attacks (e.g., SQLi, XSS) from within the process. |
| **Ransomware** | Malware that encrypts victim data and demands payment (usually in cryptocurrency) for the decryption key. Modern variants also **exfiltrate data** for double‑extortion. |
| **Rate Limiting** | Restricting the number of requests a client may make in a given time interval; mitigates brute‑force, credential‑stuffing, and DoS attempts. |
| **RAII (Resource Acquisition Is Initialization)** | C++ idiom that ties resource management (memory, file handles) to object lifetimes, reducing chances of leaks and use‑after‑free bugs. |
| **Read‑Only Memory (ROM)** | Non‑volatile storage that cannot be altered during normal operation; used for firmware that protects boot integrity (e.g., Secure Boot). |
| **Recovery Email / Phone** | Secondary contact used in password‑reset flows; a common attack vector if the recovery channel is less protected than the primary account. |
| **Red Team** | Group that emulates an adversary to test an organization’s detection and response capabilities. |
| **Reflected XSS** | See “Cross‑Site Scripting”. |
| **Remote Code Execution (RCE)** | Vulnerability that allows an attacker to run arbitrary code on a remote system, often via deserialization, command injection, or buffer overflow. |
| **Replay Attack** | Capturing a valid data transmission and retransmitting it to fool a system into performing the same action again. Countered by nonces or timestamps. |
| **Resilient (Fault‑Tolerant) System** | Architecture that continues to operate correctly in the presence of component failures, often through redundancy and graceful degradation. |
| **Reverse Engineering** | Process of analyzing compiled binaries to understand functionality, often to discover vulnerabilities or create patches. |
| **Rogue Access Point** | Unauthorized Wi‑Fi AP that mimics a legitimate network to capture traffic (Evil Twin). |
| **Root of Trust (RoT)** | Hardware or firmware component that the rest of the system trusts for critical security functions (e.g., TPM, secure bootloader). |
| **Rootkit** | Malware that hides its presence by subverting kernel or user‑space monitoring mechanisms (e.g., replacing `ls`, `ps`). Used to maintain persistent privileged access. |
| **RSA (Rivest‑Shamir‑Adleman)** | Asymmetric encryption algorithm based on the difficulty of factoring large integers. Used for key exchange, digital signatures, and encryption (with proper padding). |
| **Runtime Application Self‑Protection (RASP)** | See above. |
| **SAST (Static Application Security Testing)** | See “Static Analysis” below (covers source‑code/static binary scanning). |
| **SLA (Service Level Agreement)** | Contractual document that defines the level of service (availability, response time) a provider must deliver. Security‑related SLA clauses can specify incident‑response times. |
| **Sandbox** | Isolated execution environment (e.g., VM, container, browser sandbox) that restricts a program’s ability to affect the host system, useful for testing and mitigating exploits. |
| **Secure Boot** | Firmware feature that verifies each component of the boot chain (using signatures stored in the hardware Root of Trust) before execution, preventing unauthorized bootloaders or kernels. |
| **Security by Design** | Philosophy that security considerations are integrated from the earliest design phases, not added as an afterthought. |
| **Security Information and Event Management (SIEM)** | Platform that aggregates logs, normalizes events, and provides correlation and alerting. Enables detection of complex attack patterns (e.g., lateral movement). |
| **Security Operations Center (SOC)** | Centralized team responsible for monitoring, detection, response, and remediation of security incidents. |
| **Segmentation (Network)** | Dividing a network into isolated zones (e.g., VLANs, firewalls) to limit the spread of compromise. |
| **Side‑Channel Attack** | Attack that extracts secret data by measuring physical phenomena (timing, power, EM radiation, cache state). Notable examples: **Meltdown**, **Spectre**, **Flush+Reload**, **Power Analysis**. |
| **Signature‑Based Detection** | Antivirus/IDS technique that matches observed code or behavior against a database of known malicious signatures. Effective against known malware,weak against polymorphic/metamorphic code. |
| **Simjacker** | Attack that abuses the SIM Toolkit to execute commands on a phone via specially crafted SMS messages, allowing location tracking and data exfiltration. |
| **Spear‑phishing** | Targeted phishing aimed at a specific individual or organization, often using personalized information to increase success probability. |
| **Static Analysis (SAST)** | Examination of source code or binaries without executing them to locate potential vulnerabilities (e.g., taint analysis, data‑flow analysis, pattern matching). |
| **Supply‑Chain Attack** | Compromise of a third‑party component (library, firmware, CI/CD pipeline) that propagates into downstream products (e.g., SolarWinds, Kaseya). |
| **Threat Modeling** | Systematic process of identifying assets, enumerating potential attackers, and mapping possible attack paths (e.g., STRIDE, PASTA). Produces threat trees and mitigations. |
| **TLS (Transport Layer Security) 1.3** | Latest version of TLS; removes legacy ciphers, enforces forward secrecy, and reduces handshake round‑trips, improving both security and performance. |
| **Token‑Binding** | Mechanism that binds a TLS client certificate or token to a TLS session, mitigating token theft (e.g., session‑hijacking). |
| **Trojan Source** | Vulnerability that injects invisible Unicode direction‑changing characters into source code, causing the compiled logic to differ from the displayed code. |
| **Two‑Factor Authentication (2FA)** | See “Multifactor Authentication”. |
| **U2F (Universal 2nd Factor)** | Open authentication standard using a physical security key (e.g., YubiKey) that performs a cryptographic challenge‑response. |
| **UEFI Secure Boot** | Modern firmware replacement for BIOS that implements Secure Boot functionality. Prevents loading unsigned bootloaders or OS kernels. |
| **URL‑Encoding** | Encoding of characters in a URL using `%xx` so that special characters are safely transmitted. Required to prevent injection attacks in query strings. |
| **User‑Controlled Input** | Any data supplied by an external actor (web form, API payload, command line) that must be validated/sanitized before use. |
| **VAULT (HashiCorp Vault)** | Secrets‑management platform that provides encryption‑as‑a‑service, dynamic credentials, and lease‑based secret rotation. |
| **Vulnerability Disclosure** | Process whereby a security researcher reports a discovered flaw to the vendor (or public) in a responsible manner, often with a coordinated timeline. |
| **WAF (Web Application Firewall)** | HTTP‑level firewall that inspects traffic for known attack patterns (e.g., OWASP Top‑10) and can block or sanitize malicious requests. |
| **White‑Box Cryptography** | Techniques that aim to protect cryptographic keys in environments where the attacker can observe the implementation (e.g., embedded devices). |
| **Whitelisting** | Allowlist‑based security approach where only explicitly permitted applications, URLs, or binaries are allowed to execute. |
| **XSS (Cross‑Site Scripting)** | See “Cross‑Site Scripting”. |
| **XML External Entity (XXE) Attack** | Vulnerability in XML parsers that process external entities, leading to file disclosure, SSRF, or denial‑of‑service. Mitigated by disabling external entity resolution. |
| **Zero‑Day Vulnerability** | Exploit for a previously unknown flaw; no patch exists at the time of discovery. Highly valuable on the black market. |
| **Zero‑Trust Architecture** | Security model that assumes no implicit trust within a network boundary; every request is authenticated, authorized, and encrypted. |

---  

## S – Z  

| Term | Expanded Definition |
|------|---------------------|
| **SBOM (Software Bill of Materials)** | Machine‑readable list of all components, libraries, and versions that constitute a software artifact. Enables rapid identification of vulnerable components after a CVE is disclosed. |
| **SCADA (Supervisory Control and Data Acquisition)** | Industrial control system used to monitor and control critical infrastructure (power plants, water treatment). Often runs legacy OSes with known vulnerabilities, making them high‑value targets for nation‑state actors. |
| **Secure Enclave (e.g., Intel SGX, ARM TrustZone)** | Isolated execution environment that provides confidentiality and integrity for code and data even if the OS is compromised. Uses hardware‑enforced memory encryption and attestation. |
| **Security Development Lifecycle (SDL)** | Structured process (often modeled after Microsoft’s SDL) that integrates security activities (threat modeling, secure coding, static analysis, penetration testing) into each phase of software development. |
| **Security Misconfiguration** | Failure to securely configure software, servers, or devices (e.g., leaving default passwords, exposing admin interfaces). The **most common** OWASP Top‑10 issue. |
| **Security Operations Center (SOC)** | Team that monitors security alerts, investigates incidents, and coordinates response. Uses SIEM, IDS/IPS, and threat‑intel feeds. |
| **Shellcode** | Small piece of code injected by an attacker (often via a buffer overflow) that spawns a command interpreter or performs a payload action. Modern mitigation (NX, ASLR) forces attackers to use ROP or return‑to‑libc instead. |
| **Side‑Channel Attack** | See “Side‑Channel Attack”. |
| **SIEM (Security Information and Event Management)** | See “Security Information and Event Management”. |
| **Signature‑Based Detection** | See “Signature‑Based Detection”. |
| **SLA (Service Level Agreement)** | See “SLA”. |
| **SMAP / SMEP (Supervisor Mode Access/Execution Prevention)** | CPU flags (available on recent x86 processors) that prevent kernel mode from accessing or executing user‑mode pages, mitigating certain kernel‑level memory‑corruption exploits. |
| **Spear‑phishing** | See “Spear‑phishing”. |
| **Static Application Security Testing (SAST)** | See “Static Analysis”. |
| **Steganography (in malware)** | Hiding malicious code or data inside innocuous files (images, audio). Used to bypass network filters and file‑type restrictions. |
| **Supply‑Chain Attack** | See “Supply‑Chain Attack”. |
| **TLS 1.3** | See “TLS 1.3”. |
| **Token‑Binding** | See “Token‑Binding”. |
| **Two‑Factor Authentication (2FA)** | See “Multifactor Authentication”. |
| **U2F (Universal 2nd Factor)** | See “U2F”. |
| **UEFI Secure Boot** | See “UEFI Secure Boot”. |
| **UTC (Coordinated Universal Time)** | Not a security term per se; omitted. |
| **Vulnerability Management** | Ongoing process of identifying, evaluating, treating, and reporting security vulnerabilities. Includes **patch management**, **risk scoring** (CVSS), and **exception handling**. |
| **WebAssembly (Wasm) Sandbox** | Binary format for running code in the browser (or other runtimes) within a sandbox that isolates memory and system calls, reducing risk of native exploits. |
| **Whitelist / Allowlist** | See “Whitelisting”. |
| **XSS (Cross‑Site Scripting)** | See “Cross‑Site Scripting”. |
| **YARA Rules** | Pattern‑matching language used to classify and identify malware samples based on textual or binary signatures. |
| **Zero‑Day Exploit** | See “Zero‑Day Vulnerability”. |
| **Zero‑Trust Network** | See “Zero‑Trust Architecture”. |
| **Zygote Process (Android)** | Parent process that forks to create new app processes, sharing common libraries and reducing memory usage. Security implications: a compromise of the Zygote can affect all apps. |

---  

## How to Use This Glossary  

1. **Reference while studying** – Look up unfamiliar terms the moment they appear in lecture notes or textbooks.  
2. **Cross‑link concepts** – Many terms are related (e.g., *ASLR* ↔ *NX*, *ROP* ↔ *Return‑to‑libc*). Understanding the relationship clarifies attack‑defense chains.  
3. **Mind the hierarchy** – Broad principles (e.g., *CIA Triad*, *Least Privilege*) guide the selection of concrete mechanisms (*ASLR*, *MFA*, *RBAC*).  
4. **Keep up to date** – Some entries (e.g., *Post‑Quantum Cryptography*, *SGX mitigations*) evolve quickly; revisit the latest standards and vendor advisories.

---  

**End of Glossary**.

# Glossary of Concepts Covered in the Secure Programming Sample Exam
### A – MITRE ATT&CK Matrix  
**Definition:** A globally‑accessible framework that categorises adversary **tactics**, **techniques**, and **procedures** (TTPs) used during cyber‑attacks.  
**Expanded explanation:** Rather than tracking individual vulnerabilities, ATT&CK maps the *behaviour* of attackers (e.g., “Credential Dumping”, “Lateral Movement”) and provides a common language for threat‑intelligence sharing, detection engineering, and red‑team planning. It helps defenders understand *how* a compromise happens, not just *what* is vulnerable.

---

### B – Risk (Cyber‑Security Context)  
**Definition:** The product of **vulnerability**, **threat**, and **impact** (sometimes expressed as *vulnerability × threat × impact*).  
**Expanded explanation:**  
| Component | Meaning |
|-----------|---------|
| **Vulnerability** | A weakness in a system, process, or controls. |
| **Threat** | A potential adversary or event that could exploit the weakness. |
| **Impact** | The consequence (financial, reputational, operational) if exploitation occurs. |

The quantitative view helps organisations prioritize remediation efforts.

---

### C – Developer Mistakes that Affect Security  
**Definition:** Programming errors such as **bugs**, insecure API use, inadequate input validation, or neglecting safe‑coding practices.  
**Expanded explanation:** While UI glitches or outdated hardware are undesirable, they are not direct security bugs. Classic security‑relevant mistakes include buffer overflows, use‑after‑free, SQL injection, and hard‑coded credentials.

---

### D – Key Phases of Secure Software Development  
**Definition:** The set of activities that embed security throughout the software lifecycle, commonly: **requirements analysis, secure design, secure coding, security testing, code review, and incident response planning**.  
**Expanded explanation:** Security is not an after‑thought; each phase adds controls (e.g., threat modeling during design, static analysis during coding, fuzzing during testing) that reduce the attack surface early and often.

---

### E – Race Conditions & Detection Tools  
**Definition:** Situations where the program’s behaviour depends on the relative timing of concurrent operations, leading to **data races** or **TOCTOU** bugs.  
**Expanded explanation:** Tools like **ThreadSanitizer (TSan)** instrument the compiled binary to monitor memory accesses at runtime and report potential data races in C/C++ programs, aiding developers in fixing concurrency bugs before deployment.

---

### F – Firmware Vulnerabilities (False Statement)  
**Definition:** The *false* claim is that **firmware vulnerabilities cannot be exploited remotely**.  
**Expanded explanation:** In reality, many embedded devices expose firmware bugs over the network (e.g., insecure update mechanisms, backdoors). Remote exploitation can lead to device takeover, pivoting to other assets, or insertion of persistent malware.

---

### G – Typical Consequences of a Privileged‑Program Race Condition  
**Definition:** **Unauthorized modification of protected files** (e.g., a race that lets an attacker replace a configuration file before a privileged process reads it).  
**Expanded explanation:** Such bugs can lead to privilege escalation, insertion of malicious code, or denial of service, because the attacker can influence the system while it holds elevated rights.

---

### H – Time‑Of‑Check‑To‑Time‑Of‑Use (TOCTOU)  
**Definition:** A race condition that occurs when a resource is **checked** (e.g., existence, permissions) and later **used**, and the state changes in between.  
**Expanded explanation:** Classic example: a program checks that a file is owned by root, then opens it; an attacker replaces the file after the check but before opening, causing the program to act on a malicious file.

---

### I – Dirty COW Exploitation Steps  
**Definition:** The correct step is **using ThreadSanitizer (TSan) – but for Dirty COW the relevant step is “mapping read‑only memory using MAP_PRIVATE”**.  
**Expanded explanation:** Dirty COW (CVE‑2016‑5195) exploits a race in the Linux copy‑on‑write implementation. The attacker maps a read‑only page, repeatedly writes to it while the kernel is copying it, eventually gaining write access to otherwise read‑only memory.

---

### J – Static Application Security Testing (SAST) Methods  
**Definition:** **Data‑flow analysis** – a technique that tracks how data moves through a program to identify unsafe flows (e.g., tainted input reaching a dangerous API).  
**Expanded explanation:** SAST tools analyze source code or binaries without executing them, looking for patterns such as hard‑coded secrets, buffer overflows, or injection points.

---

### K – Benefits of Stack Canaries  
**Definition:** **Protection against stack‑based buffer overflows**.  
**Expanded explanation:** A canary value is placed just before the return address on the stack. If a buffer overflow overwrites the canary, the program detects the corruption before returning and aborts, thwarting classic stack‑smashing attacks.

---

### L – Methods to Subvert Stack Canaries  
**Definition:** **Bypassing the canary with a non‑sequential write** (e.g., writing to the buffer in a way that skips over the canary).  
**Expanded explanation:** Advanced attackers may use techniques like *partial overwrites* or *information leaks* to learn the canary value, then overwrite it correctly, or they may use *return‑oriented programming* that avoids the canary altogether.

---

### M – Heap‑Management Vulnerabilities  
**Definition:** **Use‑after‑free** – occurs when a program continues to use a pointer after the memory it points to has been freed.  
**Expanded explanation:** The freed memory may be reallocated for other data, allowing an attacker to corrupt data structures, achieve arbitrary write, or trigger code execution.

---

### N – Address Space Layout Randomization (ASLR) Characteristics  
**Definition:** **Prevents an attacker from knowing exact memory addresses** by randomising the locations of executable regions (stack, heap, libraries).  
**Expanded explanation:** ASLR raises the bar for code‑reuse attacks (e.g., ROP) because the attacker must first discover the randomized base address, which is hard without additional information leaks.

---

### O – Heap Overflows  
**Definition:** **Writing more data to a heap buffer than it can hold** (e.g., `malloc(64)` but `memcpy` writes 128 bytes).  
**Expanded explanation:** This can corrupt adjacent heap metadata, leading to arbitrary allocation/free behaviour, or enable *heap spraying* techniques to place malicious payloads at predictable locations.

---

### P – Return‑to‑libc Attacks  
**Definition:** **Redirecting execution to a function in the C standard library** (e.g., `system("/bin/sh")`) instead of injecting shellcode.  
**Expanded explanation:** By overwriting a return address with the address of `system` and supplying a suitable argument, an attacker can execute commands even when the stack is non‑executable (NX) or when stack canaries are present.

---

### Q – SQL Injection (Web Application Security)  
**Definition:** **An attack where malicious SQL statements are inserted into user‑controlled input fields, causing the database to execute unintended commands.**  
**Expanded explanation:** Typical payloads manipulate `WHERE` clauses (`' OR 1=1; --`) to bypass authentication, extract data, or modify/deleting tables. Mitigations include prepared statements, input validation, and least‑privilege database accounts.

---

### R – Blind SQL Injection  
**Definition:** **A variant where the application does not return query results directly; the attacker infers success/failure through side‑effects (e.g., time delays, boolean responses).**  
**Expanded explanation:** Attackers craft payloads that cause the server to behave differently (e.g., `IF (condition) WAITFOR DELAY '0:0:5'`) and observe timing or error messages to extract data one bit at a time.

---

### S – Cross‑Site Request Forgery (CSRF)  
**Definition:** **An attack that tricks an authenticated user’s browser into sending a forged HTTP request to a vulnerable site, performing actions without the user’s consent.**  
**Expanded explanation:** CSRF exploits the trust a site places in the user’s session cookie. Countermeasures include anti‑CSRF tokens, SameSite cookie attributes, and checking the `Referer` header.

---

### T – Heap‑Based Buffer Overflow Consequence  
**Definition:** **A crash or segmentation fault of the affected program** (most common observable symptom).  
**Expanded explanation:** Overrunning a heap buffer can corrupt allocator metadata, leading to crashes, or, if leveraged skillfully, arbitrary code execution.

---

### U – Side‑Channel Attacks  
**Definition:** **Attacks that derive secret information from indirect emissions such as power consumption, electromagnetic radiation, or timing information.**  
**Expanded explanation:** Even when cryptographic algorithms are mathematically sound, implementation details can leak bits of a key; mitigations include constant‑time coding, noise injection, and shielding.

---

### V – Manual Code Review Process Components  
**Definition:** **Pair Programming** (two developers work together, reviewing each other’s code in real time).  
**Expanded explanation:** Pair programming encourages immediate feedback, knowledge sharing, and catches logical flaws that automated tools may miss. It complements static analysis and testing.

---

### W – Symbolic Execution (Static Analysis)  
**Definition:** **A technique that treats inputs as symbolic values rather than concrete data, exploring program paths and generating constraints for each branch.**  
**Expanded explanation:** When combined with an SMT solver, symbolic execution can prove the absence of certain bugs or find inputs that trigger vulnerabilities, though it may suffer from path explosion.

---

### X – Red Zones in Heap Management  
**Definition:** **Guard regions placed before and after allocated heap blocks to detect overflows and underflows.**  
**Expanded explanation:** Writing into a red zone triggers a fault (e.g., abort, heap corruption detection), helping developers identify memory‑corruption bugs early during testing.

---

### Y – Return‑Oriented Programming (ROP) Techniques  
**Definition:** **Reusing existing “gadgets” (short instruction sequences ending in a `ret`) to build malicious payloads without injecting new code.**  
**Expanded explanation:** ROP bypasses NX/DEP protections by chaining legitimate code fragments. Mitigations include Control‑Flow Integrity (CFI) and fine‑grained ASLR.

---

### Z – ASLR Bypass Methods  
**Definition:** **Brute‑forcing the address of shellcode** (repeatedly attempting guesses until the correct location is hit).  
**Expanded explanation:** While theoretical, in practice attackers may combine info leaks (e.g., format‑string vulnerabilities) with brute force to defeat ASLR.

---

### AA – Non‑Executable (NX) Pages  
**Definition:** **Memory pages marked as non‑executable, preventing the CPU from running code stored there.**  
**Expanded explanation:** NX mitigates classic stack‑based buffer overflows by refusing to execute injected shellcode. However, attackers can still use ROP (which reuses existing executable code) to bypass NX.

---

### AB – Virtual Tables (vtables) in C++  
**Definition:** **Structures that store pointers to virtual functions for each class, enabling dynamic dispatch.**  
**Expanded explanation:** Overwrites of vtable pointers (e.g., via heap overflow) can redirect program flow to attacker‑controlled code, a common exploitation path for C++ applications.

---

### AC – Data Execution Prevention (DEP)  
**Definition:** **A hardware‑enforced policy that marks certain memory regions (e.g., stack, heap) as non‑executable, similar to NX.**  
**Expanded explanation:** DEP is implemented by the CPU (e.g., Intel XD bit) and the operating system, providing a first line of defense against code‑injection attacks.

---

### AD – Rainbow Table  
**Definition:** **A pre‑computed lookup table that maps hash values back to their original plaintext inputs (commonly passwords).**  
**Expanded explanation:** By storing hash‑plaintext pairs, an attacker can reverse weak hashes (e.g., unsalted MD5) quickly. Salting passwords and using strong, slow hash functions (bcrypt, scrypt) mitigate rainbow‑table attacks.

---

### AE – Injection Flaws (General)  
**Definition:** **Vulnerabilities where untrusted data is sent to an interpreter (SQL, OS shell, LDAP, etc.) without proper sanitisation.**  
**Expanded explanation:** Besides SQL injection, the family includes NoSQL injection, command injection, LDAP injection, and cross‑site scripting (XSS). Defensive coding uses parameterised APIs and strict input validation.

---

### AF – Virus vs. Worm  
**Definition:**  
- **Virus:** Malware that attaches to legitimate files and spreads when the infected host runs those files.  
- **Worm:** Self‑propagating malware that spreads independently (often via network services) without user interaction.  
**Expanded explanation:** Viruses rely on a host program for execution; worms exploit vulnerabilities (e.g., open ports) to replicate across machines, often causing rapid outbreaks.

---

### AG – EBP & EIP (x86 Registers)  
**Definition:**  
- **EBP (Extended Base Pointer):** Points to the base of the current stack frame, enabling stable access to local variables and function arguments.  
- **EIP (Extended Instruction Pointer):** Holds the address of the next instruction to execute; altering EIP is how control flow hijacks (e.g., return‑address overwrites) take effect.  
**Expanded explanation:** In 32‑bit x86 calling conventions, the prologue typically pushes the old EBP, sets EBP = ESP, then allocates space for locals. Overwriting saved EBP or the return address (stored above it) can lead to stack‑based exploits.

---

### AH – Polymorphic vs. Metamorphic Malware  
**Definition:**  
- **Polymorphic malware:** Encrypts its payload with a changing key each replication; a small decryption stub remains constant.  
- **Metamorphic malware:** Rewrites its own code (e.g., via code substitution, register renaming) so that each copy looks syntactically different, without relying on encryption.  
**Expanded explanation:** Both aim to evade signature‑based detection. Polymorphism is easier to implement; metamorphism is more sophisticated and harder for static analysis tools to recognise.

---

### AI – Fencepost Error (Off‑by‑One)  
**Definition:** **Using `i <= n` instead of `i < n` when iterating over an array of size `n`, leading to an out‑of‑bounds access.**  
**Expanded explanation:** In the sample code, the loop iterates one element past the end of `basket`, potentially writing beyond the `good` array and causing a buffer overflow.

---

### AJ – Buffer Overflow (Stack & Heap)  
**Definition:** **Writing more data to a fixed‑size memory region than it can contain, corrupting adjacent memory.**  
**Expanded explanation:**  
- **Stack overflow:** Overwrites return address, saved frame pointer, or local variables; often exploited with canaries, ROP, or ret2libc.  
- **Heap overflow:** Corrupts allocator metadata (e.g., `size` fields) leading to arbitrary `malloc`/`free` behaviour, use‑after‑free, or controlled code execution.

---

### AK – Command Injection  
**Definition:** **When attacker‑supplied input is incorporated into a shell command without proper sanitisation, allowing execution of arbitrary commands.**  
**Expanded explanation:** In the exam code, `system(cmd)` runs a command built from user‑controlled `bad` data, enabling an attacker to inject `; rm -rf /` or similar payloads.

---

### AL – Stack Canaries (Implementation Detail)  
**Definition:** **A known sentinel value placed between local buffers and control data (saved EBP/return address).**  
**Expanded explanation:** At function exit, the canary is checked; mismatch triggers program termination. Modern compilers (e.g., GCC `-fstack-protector`) generate a random canary per process, making guessing infeasible.

---

### AM – Secure Coding Practices (General)  
**Definition:** **A set of principles and techniques (input validation, least privilege, defense‑in‑depth, use of safe libraries) that reduce the likelihood of introducing vulnerabilities.**  
**Expanded explanation:** Following secure coding guidelines, employing static/dynamic analysis, applying compiler hardening flags, and performing thorough code reviews together form a robust software security lifecycle.

---

*All definitions are derived from the sample exam content and augmented with general security knowledge.*
