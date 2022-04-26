require [ "fileinto", "mailbox", "body", "variables", "include", "envelope", "subaddress", "imap4flags" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME", "SECURITY_TEAM_ADDR" ];
# Flags
global [ "FLAG_DUPLICATED", "FLAG_BZ_REASSIGNED", "FLAG_BZ_RESOLVED", "FLAG_EMBARGOED", "FLAG_PUBLISHED" ];

#######################
##### Internal ML #####
#######################
### SUSEDE: https://mailman.suse.de/mailman/listinfo
### SUSECOM: http://lists.suse.com/mailman/listinfo

# INBOX
# ├── Tools
# │  └── Bugzilla
# │      └── Security Team
# │          └── Proactive
# │              └── Reports
# └── ML
#     └── SUSE
#         ├── security-team
#         │   ├── Xorg
#         │   └── Samba
#         ├── security
#         │   ├── Xen
#         │   │   └── Security Advisory
#         │   ├── MariaDB
#         │   ├── Django
#         │   ├── Ceph
#         │   ├── Kubernetes
#         │   ├── Qemu
#         │   ├── Cloud Foundry
#         │   ├── strongSwan
#         │   ├── Adobe
#         │   ├── Subversion
#         │   └── Mitre
#         │       └── SUSE CNA
#         ├── kernel-security
#         ├── maintsecteam
#         │   ├── maintenance wr
#         │   ├── workreport
#         │   └── smash-smelt
#         ├── security-reports
#         │   ├── Embargo Alerts
#         │   └── Chromium
#         ├── devel
#         ├── high-impact-vul
#         ├── high-impact-vul-info
#         ├── kernel
#         ├── linux
#         ├── maint-coord
#         │   └── QA Failed
#         ├── maintsec-reports
#         │   └── channels changes
#         ├── research
#         ├── results
#         ├── secure-boot
#         ├── secure-devel
#         ├── security-intern
#         ├── security-review
#         ├── sle-security-updates
#         │   ├── container
#         │   └── image
#         └── users

# rule:[devel]
# https://mailman.suse.de/mailman/listinfo/devel
if header :contains "List-Id" "<devel.suse.de>" { fileinto :create "INBOX/ML/SUSE/devel"; stop; }

# rule:[high-impact-vul]
# https://mailman.suse.de/mailman/listinfo/high-impact-vul
if header :contains "List-Id" "<high-impact-vul.suse.de>" { fileinto :create "INBOX/ML/SUSE/high-impact-vul"; stop; }

# rule:[high-impact-vul-info]
# https://mailman.suse.de/mailman/listinfo/high-impact-vul-info
if header :contains "List-Id" "<high-impact-vul-info.suse.de>" { fileinto :create "INBOX/ML/SUSE/high-impact-vul-info"; stop; }

# rule:[kernel]
# https://mailman.suse.de/mailman/listinfo/kernel
if header :contains "List-Id" "<kernel.suse.de>" { fileinto :create "INBOX/ML/SUSE/kernel"; stop; }

# rule:[maintsecteam - Maintenance_Weekly-Report]
if allof ( header  :contains "List-Id" "<maintsecteam.suse.de>",
           address :is       "From"    "maint-coord@suse.de",
           # The subject contains ( Maintenance && Weekly Report )
           header :contains "Subject" "Maintenance",
           header :contains "Subject" "Weekly Report" ) {
    fileinto :create "INBOX/ML/SUSE/maintsecteam/maintenance wr";
    stop;
}
# rule:[maintsecteam - workreports]
if allof ( header :contains "List-Id" "<maintsecteam.suse.de>",
           # The subject contains ( workreport || (work && report) )
           anyof ( header :contains "Subject" "workreport",
                   allof ( header :contains "Subject" "work",
                           header :contains "Subject" "report" ))) {
    fileinto :create "INBOX/ML/SUSE/maintsecteam/workreport";
    stop;
}
# rule:[maintsecteam - SMESH-SMELT_Releases]
if allof ( header :contains "List-Id" "<maintsecteam.suse.de>",
           # The subject contains ( release && (smash || smelt) )
           allof ( header :contains "Subject" "release",
                   anyof ( header :contains "Subject" "smash",
                           header :contains "Subject" "smelt" ))) {
    fileinto :create "INBOX/ML/SUSE/maintsecteam/smash-smelt";
    stop;
}
# rule:[maintsecteam]
# https://mailman.suse.de/mailman/listinfo/maintsecteam
if header :contains "List-Id" "<maintsecteam.suse.de>" { fileinto :create "INBOX/ML/SUSE/maintsecteam"; stop; }

# rule:[maintsec-reports - channel file changed]
# Note: it seems that only SLE12 changes are sent over this ML.
if allof ( header :contains "List-Id" "<maintsec-reports.suse.de>",
           header :contains "Subject" "Channel changes for" ) {
    fileinto :create "INBOX/ML/SUSE/maintsec-reports/channels changes";
    stop;
}
# rule:[maintsec-reports]
# https://mailman.suse.de/mailman/listinfo/maintsec-reports
if header :contains "List-Id" "<maintsec-reports.suse.de>" { fileinto :create "INBOX/ML/SUSE/maintsec-reports"; stop; }

# rule:[maint-coord - only failed tests]
# Discard all the successful QA test notifications and put the failed ones into a dedicated folder
if allof ( header  :contains "List-Id" "<maint-coord.suse.de>",
           address :is       "From"    "qa-maintenance@suse.de",
           header  :contains "Subject" "SUSE:Maintenance:" ) {
                   if anyof ( body :contains "SUMMARY: FAILED",
                              body :contains "SUMMARY: PASSED/FAILED" ) {
                       fileinto :create "INBOX/ML/SUSE/maint-coord/QA Failed"; }
                   elsif body :contains "SUMMARY: PASSED" { discard; }
                   else { fileinto :create "INBOX/ML/SUSE/maint-coord"; }
                   stop;
}
# rule:[maint-coord]
# https://mailman.suse.de/mailman/listinfo/maint-coord
if header :contains "List-Id" "<maint-coord.suse.de>" { fileinto :create "INBOX/ML/SUSE/maint-coord"; stop; }

# rule:[research]
# https://mailman.suse.de/mailman/listinfo/research
if header :contains "List-Id" "<research.suse.de>" { fileinto :create "INBOX/ML/SUSE/research"; stop; }

# rule:[results]
# https://mailman.suse.de/mailman/listinfo/results
if header :contains "List-Id" "<results.suse.de>" { fileinto :create "INBOX/ML/SUSE/results"; stop; }

# rule:[secure-boot]
# https://mailman.suse.de/mailman/listinfo/secure-boot
if header :contains "List-Id" "<secure-boot.suse.de>" { fileinto :create "INBOX/ML/SUSE/secure-boot"; stop; }

# rule:[secure-devel]
# https://mailman.suse.de/mailman/listinfo/secure-devel
if header :contains "List-Id" "<secure-devel.suse.de>" { fileinto :create "INBOX/ML/SUSE/secure-devel"; stop; }

# rule:[security - redhat noise]
# Remove all the noise made by the RH ServiceNow instance
if allof ( header  :contains "List-Id" "<security.suse.de>",
           header  :is       "X-ServiceNow-Generated" "true",
           anyof ( address :is "From" "secalert@redhat.com",
                   address :is "From" "infosec@redhat.com" )) {
    fileinto :create "INBOX/Trash";
    stop;
}
# rule:[security - XSA]
if allof ( header  :contains "List-Id" "<security.suse.de>",
           address :is       "From"    "security@xen.org" ) {
    fileinto :create "INBOX/ML/SUSE/security/Xen/Security Advisory";
    stop;
}
# rule:[security - xen]
if allof ( header :contains "List-Id"     "<security.suse.de>",
           header :is       "X-BeenThere" "xen-security-issues-discuss@lists.xenproject.org" ) {
    fileinto :create "INBOX/ML/SUSE/security/Xen";
    stop;
}
# rule:[security - ceph]
if allof ( header :contains "List-Id" "<security.suse.de>",
           anyof ( address :is "CC" "security@ceph.io",
                   address :is "To" "security@ceph.io" )) {
    fileinto :create "INBOX/ML/SUSE/security/Ceph";
    stop;
}
# rule:[security - MariaDB]
if allof ( header  :contains "List-Id" "<security.suse.de>",
           address :is       "From"    "announce@mariadb.org") {
    fileinto :create "INBOX/ML/SUSE/security/MariaDB";
    stop;
}
# rule:[security - Django]
if allof ( header :contains "List-Id" "<security.suse.de>",
           header :contains "Subject" "Django security releases") {
    fileinto :create "INBOX/ML/SUSE/security/Django";
    stop;
}
# rule:[security - Kubernetes]
if allof ( header  :contains "List-Id"     "<security.suse.de>",
           anyof ( address :is "From" "distributors-announce@kubernetes.io",
                   address :is "From" "kubernetes-security-announce@googlegroups.com" )) {
    fileinto :create "INBOX/ML/SUSE/security/Kubernetes";
    stop;
}
# rule:[security - Cloud Foundry]
if allof ( header   :contains "List-Id" "<security.suse.de>",
           envelope :domain   "From"    "cloudfoundry.org") {
    fileinto :create "INBOX/ML/SUSE/security/Cloud Foundry";
    stop;
}
# rule:[security - Mitre SUSE CNA report]
if allof ( header   :contains "List-Id" "<security.suse.de>",
           anyof ( allof ( header   :is       "From"    "cna-coordinator@mitre.org",
                           header   :contains "Subject" "suse CNA Report" ),
                   allof ( header   :is       "From"    "nvd@nist.gov",
                           header   :contains "Subject" "audit has been completed SUSE" ))) {
    fileinto :create "INBOX/ML/SUSE/security/Mitre/SUSE CNA";
    stop;
}
# rule:[security - Mitre]
if allof ( header  :contains "List-Id" "<security.suse.de>",
           anyof ( address :domain "From"             "mitre.org",
                   header  :is     "X-MITRE-External" "True" )) {
    fileinto :create "INBOX/ML/SUSE/security/Mitre";
    stop;
}
# rule:[security - strongSwan]
if allof ( header   :contains "List-Id" "<security.suse.de>",
           envelope :domain   "From"    "strongswan.org",
           header   :contains "Subject" "security advisory" ) {
    fileinto :create "INBOX/ML/SUSE/security/strongSwan";
    stop;
}
# rule:[security - Adobe]
if allof ( header   :contains "List-Id" "<security.suse.de>",
           address  :domain   "From"    "mail.adobe.com",
           header   :contains "Subject" "Adobe Security Bulletin") {
    fileinto :create "INBOX/ML/SUSE/security/Adobe";
    stop;
}
# rule:[security - no VINCE]
# discard VINCE notification from this ML since I already got them directly
if allof ( header   :contains "List-Id" "<security.suse.de>",
           address  :is       "From"    "cert+donotreply@cert.org" ) {
    discard;
    stop;
}
# rule:[security - no security@suse.com duplicates]
# security@suse.com redirects everything to security@suse.de, then if an email is sent
# to both security@suse.de and security@suse.com I get it twice in my inbox
if allof ( header  :contains "List-Id" "<security.suse.de>",
           address :contains [ "To", "CC" ] "security@suse.com",
           address :contains [ "To", "CC" ] "security@suse.de",
           header  :contains "Resent-From" "security@suse.com" ) {
    addflag "${FLAG_DUPLICATED}";
    fileinto :create "INBOX/Trash";
    stop;
}
# rule:[security - subversion]
# Subversion pre-disclosure notifications
if allof ( header   :contains "List-Id" "<security.suse.de>",
           header   :contains "Subject" "Subversion",
           envelope :domain   "From"    "apache.org" ) {
    fileinto :create "INBOX/ML/SUSE/security/Subversion";
    stop;
}
# rule:[security]
# https://mailman.suse.de/mailman/listinfo/security
if header :contains "List-Id" "<security.suse.de>" { fileinto :create "INBOX/ML/SUSE/security"; stop; }

# rule:[security - qemu security]
# https://lists.nongnu.org/mailman/listinfo/qemu-security
if header :contains "List-Id" "<qemu-security.nongnu.org>" { fileinto :create "INBOX/ML/SUSE/security/Qemu"; stop; }

# rule:[security-intern]
# https://mailman.suse.de/mailman/listinfo/security-intern
if header :contains "List-Id" "<security-intern.suse.de>" { fileinto :create "INBOX/ML/SUSE/security-intern"; stop; }

# rule:[security-reports - Embargo Alerts]
if allof ( header :contains "List-Id" "<security-reports.suse.de>",
           header :contains "Subject" "EMBARGOED ISSUE MENTIONED IN" ) {
    fileinto :create "INBOX/ML/SUSE/security-reports/Embargo Alerts"; 
    stop;
}
# rule:[security-reports - Embargo date missing]
if allof ( header :contains "List-Id" "<security-reports.suse.de>",
           header :contains "Subject" "OBS:EmbargoDate not set for" ) {
    fileinto :create "INBOX/ML/SUSE/security-reports/Embargo Alerts"; 
    stop;
}
# rule:[security-reports - Chromium Releases]
if allof ( header :contains "List-Id" "<security-reports.suse.de>",
           header :contains "Subject" "Chromium Stable" ) {
    fileinto :create "INBOX/ML/SUSE/security-reports/Chromium";
    stop;
}
# rule:[security-reports]
# https://mailman.suse.de/mailman/listinfo/security-reports
if header :contains "List-Id" "<security-reports.suse.de>" { fileinto :create "INBOX/ML/SUSE/security-reports"; stop; }

# rule:[security-review]
# https://mailman.suse.de/mailman/listinfo/security-review
if header :contains "List-Id" "<security-review.suse.de>" { fileinto :create "INBOX/ML/SUSE/security-review"; stop; }

# rule:[security-team - no US-CERT]
# Discard newsletters coming US-CERT because these are duplicated for me as I'm already subscribed to that list
# ML -> SecList -> CERT Advisories
if allof ( header  :contains "List-Id" "<security-team.suse.de>",
           address :is       "From"  [ "US-CERT@ncas.us-cert.gov",
                                       "CISA@public.govdelivery.com",
                                       "cisacommunity@ncas.us-cert.gov",
                                       "US-CERT@messages.cisa.gov",
                                       "CISA@messages.cisa.gov"          ] ) {
    fileinto :create "INBOX/Trash";
    stop;
}
# rule:[security-team - xorg-security ML]
if allof ( header :contains "List-Id"     "<security-team.suse.de>",
           header :contains "X-BeenThere" "xorg-security@lists.x.org" ) {
    fileinto :create "INBOX/ML/SUSE/security-team/Xorg";
    stop;
}
# rule:[security-team - Samba ML]
if allof ( header :contains "List-Id" "<security-team.suse.de>",
           header :contains "From"    "samba-bugs@samba.org" ) {
    fileinto :create "INBOX/ML/SUSE/security-team/Samba";
    stop;
}
# rule:[security-team - security-team and me in CC ]
# When someone follows up on a thread where I'm also in CC, I want it in the same ML folder
if allof (     address :contains "CC" "${SECURITY_TEAM_ADDR}",
               address :contains "CC" "${SUSEDE_ADDR}",
           not address :contains "To" "${SUSEDE_ADDR}" ) {
    fileinto :create "INBOX/ML/SUSE/security-team";
    stop;
}
# rule:[security-team - proactive audit report ]
# Weekly audit report for the proactive team to the proactive BZ folder
if allof ( address :is "From" "jenkins@suse.de",
           address :is "To" "${SECURITY_TEAM_ADDR}",
           header  :contains "List-Id" "<security-team.suse.de>",
           header  :contains "Subject" "Audit Bug Report for" ) {
    addflag "\\Seen";
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Proactive/Reports";
    stop;
}
# rule:[security-team]
# https://mailman.suse.de/mailman/listinfo/security-team
if header :contains "List-Id" "<security-team.suse.de>" { fileinto :create "INBOX/ML/SUSE/security-team"; stop; }

# rule:[users]
# https://mailman.suse.de/mailman/listinfo/users
if header :contains "List-Id" "<users.suse.de>" { fileinto :create "INBOX/ML/SUSE/users"; stop; }

# rule:[linux]
# http://lists.suse.com/mailman/listinfo/linux
if header :contains "List-Id" "<linux.lists.suse.com>" { fileinto :create "INBOX/ML/SUSE/linux"; stop; }

# rule:[sle-security-updates - containers]
if allof ( header :contains "List-Id" "<sle-security-updates.lists.suse.com>",
           body   :contains           "SUSE Container Update Advisory" ) {
    fileinto :create "INBOX/ML/SUSE/sle-security-updates/container"; 
    stop;
}
# rule:[sle-security-updates - images]
if allof ( header :contains "List-Id" "<sle-security-updates.lists.suse.com>",
           body   :contains           "SUSE Image Update Advisory" ) {
    fileinto :create "INBOX/ML/SUSE/sle-security-updates/image"; 
    stop;
}
# rule:[sle-security-updates]
# https://lists.suse.com/mailman/listinfo/sle-security-updates
if header :contains "List-Id" "<sle-security-updates.lists.suse.com>" { fileinto :create "INBOX/ML/SUSE/sle-security-updates"; stop; }

# rule:[kernel-security-sentinel]
# https://lists.suse.com/mailman/listinfo/kernel-security-sentinel
if header :contains "List-Id" "<kernel-security-sentinel.lists.suse.com>" { fileinto :create "INBOX/ML/SUSE/kernel-security"; stop; }