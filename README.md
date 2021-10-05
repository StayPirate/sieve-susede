# Personal sieve scripts collection

This repository is intended to store and organize my personal sieve scripts. Maintaining them is as much important as hard. Since their complexity grows every day, I decided to organize them in a better way, by splitting them into multiple files and by versioning them via git. Using the below-described snippets, at each git commit they are automatically updated on the mail-server as well.

## Requirement
You need `sieveshell` installed. Good news for [secbox](https://github.com/StayPirate/secbox) users, in case you are running `secbox >= 1.10` and `secbox-image >= 2.7`, then you already have `sieveshell` available. You can double-check with the following commands:
```bash
> secbox -v
script     :  secbox                                                       v.1.9
image      :  non_public/maintenance/security/container/containers/secbox  v.2.7
container  :  secbox                                                       running
> which sieveshell
sieveshell: aliased to secbox --no-tty sieveshell
```

## How to use

I store my credentials (application password) in the local wallet, which I can access via D-Bus using the secret-service protocol. The following aliases are intended to collect the username and password for the secret service provider (keepassxc in my case).

```bash
alias unlock_wallet='echo "check the explanation attribute ;)" | secret-tool store --label="dummy-entry" explanation \
                    "Because of quirks in the gnome libsecret API, a dummy entry needs to be stored in order to \
                     guarantee that this keyring was properly unlocked. More details at http://crbug.com/660005 and \
                     https://github.com/keepassxreboot/keepassxc/issues/4443"'
                       
alias suse-de_pass='unlock_wallet && \
                    secret-tool search client sieveshell workstation wintermute 2>&1 | \
                    grep -E "^secret" | \
                    cut -d " " -f3'
                       
alias suse-de_user='unlock_wallet && \
                    secret-tool search client sieveshell workstation wintermute 2>&1 | \
                    grep -E "^attribute\.UserName" | \
                    cut -d " " -f3'
```

From within the repo work-tree, I run the following command to upload the .sieve scripts to the remote mail-server. This can be hooked into the git client in a way that it automatically updates the sieve scripts on the mail-server every time a new commit is created (see below).

```bash
find $(git rev-parse --show-toplevel) -type f -name "*.sieve" -printf "put %p %f\n" | sort -nr | \
sieveshell --user $(suse-de_user) \
           --passwd $(suse-de_pass) \
           --use-tls \
           --port 4190 \
           imap-int.suse.de
```

## Git hook

The [hook](.githooks/pre-commit) is already provided within this repository, I strongly suggest you leverage [conditional includes](https://git-scm.com/docs/git-config#_conditional_includes) (great tool) in your gitconfig. This will be as easier as appending the following lines to your `~/.gitconfig`:
```
; Only include if the repository is sieve-susude
[includeIf "gitdir:~/Workspace/sieve-susede/.git"]
        path = ~/Workspace/sieve-susede/.githooks/sieveshell.gitconfig
```

Do not forget to adjust the paths in the above snippet.

# Inbox index

```
INBOX
├── Spam
├── Trash
├── Tools
│   ├── Bugzilla
│   │   ├── Direct
│   │   └── Security Team
│   │       ├── Embargoed
│   │       └── Reassigned back
│   ├── IBS
│   │   ├── build
│   │   └── requests
│   │       ├── pushed back
│   │       └── to review
│   ├── OBS
│   │   ├── build
│   │   └── Security Tools
│   ├── Jira
│   ├── Confluence
│   └── Gitlab
├── ML
│   ├── SUSE
│   │   ├── security-team
│   │   │   ├── Xorg
│   │   │   └── Samba
│   │   ├── security
│   │   │   ├── Xen
│   │   │   │   └── Security Advisory
│   │   │   ├── MariaDB
│   │   │   ├── Django
│   │   │   ├── Ceph
│   │   │   ├── Kubernetes
│   │   │   └── Qemu
│   │   ├── maintsecteam
│   │   │   ├── maintenance wr
│   │   │   ├── workreport
│   │   │   └── smash-smelt
│   │   ├── security-reports
│   │   │   ├── Embargo Alerts
│   │   │   └── Chromium
│   │   ├── devel
│   │   ├── high-impact-vul
│   │   ├── high-impact-vul-info
│   │   ├── kernel
│   │   ├── linux
│   │   ├── maint-coord
│   │   ├── maintsec-reports
│   │   │   └── channels changes
│   │   ├── research
│   │   ├── results
│   │   ├── secure-boot
│   │   ├── secure-devel
│   │   ├── security-intern
│   │   ├── security-review
│   │   ├── sle-security-updates
│   │   │   ├── container
│   │   │   └── image
│   │   └── users
│   ├── OpenSUSE
│   │   ├── factory
│   │   ├── users
│   │   └── security announce
│   ├── SecList
│   │   ├── Nmap Announce
│   │   ├── Breach Exchange
│   │   ├── Full Disclosure
│   │   │   ├── malvuln
│   │   │   ├── apple
│   │   │   ├── korelogic
│   │   │   ├── onapsis
│   │   │   ├── asterisk
│   │   │   ├── atlassian
│   │   │   └── mikrotik
│   │   ├── Open Source Security
│   │   │   └── WebKit SA
│   │   ├── linux-distro
│   │   ├── vince
│   │   ├── Info Security News
│   │   ├── CERT Advisories
│   │   └── OpenSSF
│   │       ├── Announcements
│   │       ├── Security Threats
│   │       ├── Security Tooling
│   │       ├── Vul Disclosure
│   │       └── Code Best Practices
│   ├── Debian
│   │   ├── Security Announce
│   │   └── Security Tracker
│   ├── RedHat
│   │   ├── Security Announce
│   │   └── IBM Virt Security
│   ├── Ubuntu
│   │   ├── Hardened
│   │   ├── Security Announce
│   │   └── Security Patch
│   ├── Italian
│   │   └── GNU Translation
│   └── Security Advisory
│       └── Weechat
└── NL
    ├── LWN
    ├── CyberSaiyan
    └── Grapl Security
```