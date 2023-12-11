require [ "fileinto", "mailbox", "envelope", "variables", "include", "imap4flags" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "USERNAME" ];

#######################
##### External ML #####
#######################
### OpenSUSE: https://lists.opensuse.org
### Seclist: https://seclists.org/
### Open Source Security Foundation: https://lists.openssf.org/g/mas
#
# ML
# ├── SecList
# │   ├── Breach Exchange
# │   ├── Full Disclosure
# │   │   ├── malvuln
# │   │   ├── apple
# │   │   ├── korelogic
# │   │   ├── onapsis
# │   │   ├── asterisk
# │   │   ├── atlassian
# │   │   └── mikrotik
# │   ├── osss
# │   ├── linux-distros
# │   ├── distros
# │   ├── kernel hardening
# │   ├── Linux Security Module
# │   ├── vince
# │   ├── Info Security News
# │   ├── WebKit
# │   │   ├── Upstream Private
# │   │   └── Security Advisory
# │   └── CERT Advisories
# │       └── Week Summary
# ├── OpenSSF
# │   ├── Announcements
# │   ├── Security Threats
# │   ├── Security Tooling
# │   ├── Vul Disclosure
# │   ├── Code Best Practices
# │   ├── Alpha-Omega Announcements
# │   ├── Supply Chain Integrity
# │   ├── Securing Critical Projects
# │   └── OSS-SIRT
# ├── OpenSUSE
# │   ├── factory
# │   └── users
# ├── Debian
# │   ├── Security
# │   ├── Security Tools
# │   └── Security Tracker
# ├── RedHat
# │   └── IBM Virt Security
# ├── Ubuntu
# │   ├── Hardened
# │   └── Security Patch
# ├── Archlinux
# │   ├── arch-announce
# │   ├── arch-events
# │   └── arch-general
# ├── Fedora
# │   ├── security
# │   ├── selinux
# │   └── users
# └── Italian
#     └── GNU Translation

# rule:[Seclist - breachexchang]
# https://www.riskbasedsecurity.com/mailing-list/
if header :contains "List-Id" "<breachexchange.lists.riskbasedsecurity.com>" { fileinto :create "INBOX/ML/SecList/Breach Exchange"; stop; }

# rule:[Seclist - Full-Disclosure - malvuln]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "From" "malvuln13@gmail.com" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/malvuln"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - apple-sa]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "To" [ "security-announce@lists.apple.com", "product-security-noreply@lists.apple.com" ] ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/apple"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - korelogic-sa]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :contains "Reply-To" "disclosures@korelogic.com" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/korelogic"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - onapsis]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :contains "Reply-To" "research@onapsis.com" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/onapsis"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - asterisk-sa]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "From" "security@asterisk.org" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/asterisk"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - mikrotik-sa]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           header :contains "Subject" "mikrotik" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/mikrotik"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - atlassian]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "From" "security@atlassian.com" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/atlassian";
    stop;
}
# rule:[Seclist - Full-Disclosure]
# https://nmap.org/mailman/listinfo/fulldisclosure
if header :contains "List-Id" "<fulldisclosure.seclists.org>" { fileinto :create "INBOX/ML/SecList/Full Disclosure"; stop; }

# rule:[Seclist - oss-security]
# http://oss-security.openwall.org/wiki/mailing-lists/oss-security
if header :contains "List-Id" "<oss-security.lists.openwall.com>" {

    # WebKit SA
    if header :contains "Subject" "WebKit Security Advisory" {
        fileinto :create "INBOX/ML/SecList/WebKit/Security Advisory";
        stop;
    }

    # Jenkins SA
    if anyof ( header :contains "Subject" "Multiple vulnerabilities in Jenkins",
               header :contains "Subject" "Vulnerability in Jenkins" ) {
        fileinto :create "INBOX/Feed/SA/Jenkins";
        stop;
    }

    # Xen Security Advisory (XSA)
    # XSA are sent to osss and also to the xen-announce ML, since I'm subscribed to both
    # then I discard the ones sent to osss.
    if anyof (  address :contains "To" "xen-announce@lists.xen.org",
                header  :contains "Subject" "Xen Security Advisory" ) {
                    discard;
    }

    # oss-security catch all rule
    fileinto :create "INBOX/ML/SecList/osss";
    stop;

}

# rule:[Seclist - linux-distros and distros]
# https://oss-security.openwall.org/wiki/mailing-lists/distros
if header :is "X-List" "vs.openwall.org" { 
   if address :is [ "Cc", "To" ] "linux-distros@vs.openwall.org" { fileinto :create "INBOX/ML/SecList/linux-distros"; stop; }
   elsif address :is [ "Cc", "To" ] "distros@vs.openwall.org" { fileinto :create "INBOX/ML/SecList/distros"; stop; }
}

# rule:[Seclist - linux-kernel-hardening]
# The upstream Linux kernel hardening mailing list, where development, maintenance, and administrivia happen.
# https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Get_Involved
if header :is "List-Id" "<linux-hardening.vger.kernel.org>"  { fileinto :create "INBOX/ML/SecList/kernel dev hardening"; stop; }

# rule:[Seclist - kernel-hardening]
# The general Linux kernel hardening mailing list, where new hardening topics and summaries of completed work are discussed.
# https://www.openwall.com/lists/kernel-hardening/
if header :is "List-Id" "<kernel-hardening.lists.openwall.com>"  { fileinto :create "INBOX/ML/SecList/kernel hardening"; stop; }

# rule:[Seclist - linux-security-module]
# https://www.spinics.net/lists/linux-security-module/maillist.html
if header :contains "List-Id" "linux-security-module.vger.kernel.org"  { fileinto :create "INBOX/ML/SecList/Linux Security Module"; stop; }

# rule:[Seclist - VINCE]
# https://kb.cert.org/vince/comm/auth/login/
if address :is "From" "cert+donotreply@cert.org" {
           if header :contains "Subject" [ "VU#132185", "VU#855201",  "VU#930724", "VU#119678", "VU#709991",
                                           "VU#730793", "VU#495815" ] {
                     addflag "\\Seen";
           }
           fileinto :create "INBOX/ML/SecList/vince";
           stop;
}

# rule:[Seclist - infosecnews]
# http://lists.infosecnews.org/mailman/listinfo/isn_lists.infosecnews.org
if header :contains "List-Id" "<isn.lists.infosecnews.org>" { fileinto :create "INBOX/ML/SecList/Info Security News"; stop; }

# rule:[Seclist - CERT]
# https://public.govdelivery.com/accounts/USDHSCISA/subscriber/edit?preferences=true#tab1
if allof ( address :is "To" "${SUSEDE_ADDR}",
           anyof ( address :contains "From" "US-CERT@ncas.us-cert.gov",
                   address :contains "From" "CISA@public.govdelivery.com",
                   address :contains "From" "cisacommunity@ncas.us-cert.gov",
                   address :contains "From" "US-CERT@messages.cisa.gov",
                   address :contains "From" "CISA@messages.cisa.gov" )) {
                       if header :contains "Subject" "Vulnerability Summary for the Week" {
                           fileinto :create "INBOX/ML/SecList/CERT Advisories/Week Summary";
                           stop;
                       }
                       fileinto :create "INBOX/ML/SecList/CERT Advisories";
                       stop;
}

# rule:[openSSF - Events]
# https://email.linuxfoundation.org/hs/manage-preferences/unsubscribe
if anyof ( address :contains "From" "operations@openssf.org",
           envelope :contains "From" "Open Source Security Foundation (OpenSSF) - Meetings",
           address :contains "From" "Open Source Security Foundation (OpenSSF) - Meetings" ) {
                fileinto :create "INBOX/ML/OpenSSF";
                stop;
}

# rule:[openSSF - Announcements]
# https://lists.openssf.org/g/openssf-announcements
if header :contains "List-Id" "<openssf-announcements.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Announcements"; stop; }

# rule:[openSSF - Security threats]
# https://lists.openssf.org/g/openssf-wg-security-threats
if header :contains "List-Id" "<openssf-wg-security-threats.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Security Threats"; stop; }

# rule:[openSSF - Security tools]
# https://lists.openssf.org/g/openssf-wg-security-tooling
if header :contains "List-Id" "<openssf-wg-security-tooling.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Security Tooling"; stop; }

# rule:[openSSF - Vulnerability disclosures]
# https://lists.openssf.org/g/openssf-wg-vul-disclosures
if header :contains "List-Id" "<openssf-wg-vul-disclosures.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Vul Disclosures"; stop; }

# rule:[openSSF - Secure code best practices]
# https://lists.openssf.org/g/openssf-wg-best-practices
if header :contains "List-Id" "<openssf-wg-best-practices.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Code Best Practices"; stop; }

# rule:[openSSF - Alpha-Omega Announcements]
# https://lists.openssf.org/g/alpha-omega-announcements
if header :contains "List-Id" "<alpha-omega-announcements.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Alpha-Omega Announcements"; stop; }

# rule:[openSSF - Supply Chain Integrity]
# https://lists.openssf.org/g/openssf-supply-chain-integrity
if header :contains "List-Id" "<openssf-supply-chain-integrity.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Supply Chain Integrity"; stop; }

# rule:[openSSF - Securing Critical Projects]
# https://lists.openssf.org/g/openssf-wg-securing-crit-prjs
if header :contains "List-Id" "<openssf-wg-securing-crit-prjs.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Securing Critical Projects"; stop; }

# rule:[openSSF - OSS SIRT]
# https://lists.openssf.org/g/openssf-sig-osssirt
if header :contains "List-Id" "<openssf-sig-osssirt.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/OSS-SIRT"; stop; }

# rule:[Debian - security tracker mute bot]
if allof ( header :contains "List-Id" "<debian-security-tracker.lists.debian.org>",
           address :contains "From" "sectracker@soriano.debian.org") {
    discard;
    stop;
}
# rule:[Debian - security tracker]
# https://lists.debian.org/debian-security-tracker/
if header :contains "List-Id" "<debian-security-tracker.lists.debian.org>" { fileinto :create "INBOX/ML/Debian/Security Tracker"; stop; }

# rule:[Debian - security]
# https://lists.debian.org/debian-security/
if header :contains "List-Id" "<debian-security.lists.debian.org>" { fileinto :create "INBOX/ML/Debian/Security"; stop; }

# rule:[Debian - security tools]
# https://lists.debian.org/debian-security-tools/
if header :contains "List-Id" "<debian-security-tools.lists.debian.org>" { fileinto :create "INBOX/ML/Debian/Security Tools"; stop; }

# rule:[Ubuntu - security patch]
# https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-patch
if header :contains "List-Id" "<ubuntu-security-patch.lists.ubuntu.com>" { fileinto :create "INBOX/ML/Ubuntu/Security Patch"; stop; }

# rule:[Ubuntu - hardened]
# https://lists.ubuntu.com/mailman/listinfo/ubuntu-hardened
if header :contains "List-Id" "<ubuntu-hardened.lists.ubuntu.com>" { fileinto :create "INBOX/ML/Ubuntu/Hardened"; stop; }

# rule:[Archlinux - arch-announce]
# https://lists.archlinux.org/listinfo/arch-announce
if header :contains "List-Id" "<arch-announce.lists.archlinux.org>" { fileinto :create "INBOX/ML/Archlinux/arch-announce"; stop; }

# rule:[Archlinux - arch-events]
# https://lists.archlinux.org/listinfo/arch-events
if header :contains "List-Id" "<arch-events.lists.archlinux.org>" { fileinto :create "INBOX/ML/Archlinux/arch-events"; stop; }

# rule:[Gentoo Linux Security Advisories - gentoo-announce]
# https://www.gentoo.org/support/security/
#
# Even though I unsubscribed myself from this ML, I still get emails from it.
# The following rule is meant to discard any email coming from gentoo-announce.
if header :contains "List-Id" "<gentoo-announce.gentoo.org>" { discard; stop; }

# rule:[Fedora - security]
# https://lists.fedoraproject.org/admin/lists/users.lists.fedoraproject.org/
if header :contains "List-Id" "<security.lists.fedoraproject.org>" { fileinto :create "INBOX/ML/Fedora/security"; stop; }

# rule:[Fedora - selinux]
# https://lists.fedoraproject.org/archives/list/selinux@lists.fedoraproject.org/
if header :contains "List-Id" "<selinux.lists.fedoraproject.org>" { fileinto :create "INBOX/ML/Fedora/selinux"; stop; }

# rule:[WebKit Security Private ML]
# https://webkit.org/security-policy/
if header :contains "List-Id" "<webkit-security.lists.webkit.org>" { fileinto :create "INBOX/ML/SecList/WebKit/Upstream Private"; stop; }