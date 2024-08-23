require [ "fileinto", "mailbox", "body", "variables", "include", "envelope", "subaddress", "imap4flags" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "USERNAME", "SECURITY_TEAM_ADDR" ];
global [ "FLAG_DUPLICATED", "FLAG_MUTED", "FLAG_BETA" ];

#######################
##### Internal ML #####
#######################
### SUSEDE: https://mailman.suse.de/mailman/listinfo
### SUSECOM: http://lists.suse.com/mailman/listinfo

# rule:[devel]
# https://mailman.suse.de/mailman/listinfo/devel
if header :contains "List-Id" "<devel.suse.de>" { fileinto :create "INBOX/ML/SUSE/devel"; stop; }

# rule:[high-impact-vul]
# https://mailman.suse.de/mailman/listinfo/high-impact-vul
if header :contains "List-Id" "<high-impact-vul.suse.de>" { fileinto :create "INBOX/ML/SUSE/high-impact-vul"; stop; }

# rule:[high-impact-vul-info]
# https://mailman.suse.de/mailman/listinfo/high-impact-vul-info
if header :contains "List-Id" "<high-impact-vul-info.suse.de>" { fileinto :create "INBOX/ML/SUSE/high-impact-vul-info"; stop; }

# rule:[maintsecteam]
# https://mailman.suse.de/mailman/listinfo/maintsecteam
if header :contains "List-Id" "<maintsecteam.suse.de>" { fileinto :create "INBOX/ML/SUSE/maintsecteam"; stop; }

# rule:[maintsec-reports]
# https://mailman.suse.de/mailman/listinfo/maintsec-reports
if header :contains "List-Id" "<maintsec-reports.suse.de>" {

    # Discard all the scripts reports and the weekly wiki diff
    if header :contains "Subject" [ "/bin/", "Changes in MaintenanceSecurity Wiki" ] {
        discard;
        stop;
    }

    # If none of the above matched
    fileinto :create "INBOX/ML/SUSE/maintsec-reports";
    stop;
}

# rule:[maint-coord]
# https://mailman.suse.de/mailman/listinfo/maint-coord
if header :contains "List-Id" "<maint-coord.suse.de>" {

    # Hide BZ reports
    if header :contains "Subject" "[Bugzilla] Bugs for Maintenance Team" {
        addflag "\\Seen";
    }

    # Discard all the successful QA test notifications and put the failed ones into a dedicated folder
    if allof ( address :is "From" "qa-maintenance@suse.de",
               header :contains "Subject" "SUSE:Maintenance:" ) {
                    if anyof ( body :contains "SUMMARY: FAILED",
                               body :contains "SUMMARY: PASSED/FAILED" ) {
                        fileinto :create "INBOX/ML/SUSE/maint-coord/QA Failed";
                    }
                    elsif body :contains "SUMMARY: PASSED" {
                        discard;
                    }
                    else {
                        fileinto :create "INBOX/ML/SUSE/maint-coord";
                    }
               stop;
    }

    fileinto :create "INBOX/ML/SUSE/maint-coord";
    stop;
}

# rule:[secure-boot]
# https://mailman.suse.de/mailman/listinfo/secure-boot
if header :contains "List-Id" "<secure-boot.suse.de>" { fileinto :create "INBOX/ML/SUSE/secure-boot"; stop; }

# rule:[SUSE - security]
# https://mailman.suse.de/mailman/listinfo/security
if header  :contains "List-Id" "<security.suse.de>" {

    # Remove all the noise made by the RH ServiceNow instance
    if allof ( header  :is "X-ServiceNow-Generated" "true",
               anyof ( address :is "From" "secalert@redhat.com",
                       address :is "From" "infosec@redhat.com" )) {
        fileinto :create "INBOX/Trash";
        stop;
    }

    # The Document Foundation
    if header :contains "X-BeenThere" "lists.documentfoundation.org" {
        fileinto :create "INBOX/ML/SUSE/security/TDF";
        stop;
    }

    # XSA
    if address :is "From" "security@xen.org" {
        fileinto :create "INBOX/ML/SUSE/security/Xen/XSA Embargo";
        stop;
    }

    # XEN
    if header :is "X-BeenThere" "xen-security-issues-discuss@lists.xenproject.org" {
        fileinto :create "INBOX/ML/SUSE/security/Xen";
        stop;
    }

    # CEPH
    if anyof ( address :is "Cc" "security@ceph.io",
               address :is "To" "security@ceph.io" ) {
        fileinto :create "INBOX/ML/SUSE/security/Ceph";
        stop;
    }

    # MariaDB
    if address :is "From" "announce@mariadb.org" {
        fileinto :create "INBOX/ML/SUSE/security/MariaDB";
        stop;
    }

    # Django
    if header :contains "Subject" "Django security releases" {
        fileinto :create "INBOX/ML/SUSE/security/Django";
        stop;
    }

    # Kubernetes
    if anyof ( address :is "From" "distributors-announce@kubernetes.io",
               address :is "From" "kubernetes-security-announce@googlegroups.com",
               header  :is "X-BeenThere" "distributors-announce@kubernetes.io" ) {
        fileinto :create "INBOX/ML/SUSE/security/Kubernetes";
        stop;
    }

    # Cloud Foundry
    if envelope :domain "From" "cloudfoundry.org" {
        fileinto :create "INBOX/ML/SUSE/security/Cloud Foundry";
        stop;
    }

    # Mitre SUSE CNA report
    if anyof ( allof ( header   :is       "From"    "cna-coordinator@mitre.org",
                       header   :contains "Subject" "suse CNA Report" ),
               allof ( header   :is       "From"    "nvd@nist.gov",
                       header   :contains "Subject" "audit has been completed SUSE" )) {
        if not body :contains [ "Failed", "failure" ] {
            addflag "\\Seen";
        }
        fileinto :create "INBOX/ML/SUSE/security/Mitre/SUSE CNA";
        stop;
    }

    # Mitre
    if anyof ( address :domain "From" "mitre.org",
               header :is "X-MITRE-External" "True" ) {
        # The document foundation is echoing everything coming from this ML, so I need to kill it
        if header :is "X-BeenThere" "tdf-security@lists.documentfoundation.org" {
            fileinto :create "INBOX/Trash";
        } else {
            addflag "\\Seen";
            fileinto :create "INBOX/ML/SUSE/security/Mitre";
        }
        stop;
    }

    # StrongSwan
    if allof ( envelope :domain "From" "strongswan.org",
               header :contains "Subject" "security advisory" ) {
        fileinto :create "INBOX/ML/SUSE/security/strongSwan";
        stop;
    }

    # Discard Adobe SA, from the open source pov we don't care
    if allof ( address :domain "From" "mail.adobe.com",
               header :contains "Subject" "Adobe Security Bulletin") {
        addflag "\\Seen";
        fileinto :create "INBOX/Trash";
        stop;
    }

    # discard VINCE notification from this ML since I already got them directly
    if address :is "From" "cert+donotreply@cert.org" {
        discard;
        stop;
    }

    # security@suse.COM redirects everything to security@suse.DE, then if an email is sent
    # to both security@suse.de and security@suse.com I get it twice in my inbox
    if allof ( address :contains [ "To", "Cc" ] "security@suse.com",
               address :contains [ "To", "Cc" ] "security@suse.de",
               header  :contains "Resent-From" "security@suse.com" ) {
        addflag "${FLAG_DUPLICATED}";
        fileinto :create "INBOX/Trash";
        stop;
    }

    # Subversion pre-disclosure notifications
    if allof ( header :contains "Subject" "Subversion",
               envelope :domain "From" "apache.org" ) {
        fileinto :create "INBOX/ML/SUSE/security/Subversion";
        stop;
    }

    # If none of the above matched, then move the rest to the security folder
    fileinto :create "INBOX/ML/SUSE/security";
    stop;
}

# rule:[security - qemu security]
# https://lists.nongnu.org/mailman/listinfo/qemu-security
if header :contains "List-Id" "<qemu-security.nongnu.org>" { fileinto :create "INBOX/ML/SUSE/security/Qemu"; stop; }

# Dumplicated Embargo Notifications
#
# Since I'm subscribed to both the security-reports and security-team MLs, the following emails are duplicates.
# Only keeps the copy sent to security-reports
if allof ( address :is "To" "${SECURITY_TEAM_ADDR}",
           address :is "Cc" "security-reports@suse.de",
           header :contains "Subject" [ "OBS:EmbargoDate not set for", "EMBARGOED ISSUE MENTIONED IN" ] ) {

                if header :contains "List-Id" "<security-reports.suse.de>" {
                    fileinto :create "INBOX/ML/SUSE/security-reports/Embargo Alerts";
                    stop;
                }
                elsif header :contains "List-Id" "<security-team.suse.de>" {
                    fileinto :create "INBOX/Trash";
                    stop;
                }

}

# rule:[security-reports]
# https://mailman.suse.de/mailman/listinfo/security-reports
if header :contains "List-Id" "<security-reports.suse.de>" {

    # Only keeps reports with KPI failure for security or EMU incidents
    if header :is "Subject" "SUSE Maintenance - Reports - Imminent-Kpis" {
        if allof ( body :contains "[ SUSE:Maintenance:",
                   body :contains [ "security", "emu" ] ) {
            fileinto :create "INBOX/ML/SUSE/security-reports/Missing KPI";
        }
        else {
            fileinto :create "INBOX/Trash";
        }
        stop;
    }

    # Discard Chromium releases notifications
    if header :contains "Subject" "Chromium Stable" {
        fileinto :create "INBOX/Trash";
        stop;
    }

    # If none of the above matched
    fileinto :create "INBOX/ML/SUSE/security-reports";
    stop;
}

# rule:[security-review]
# https://mailman.suse.de/mailman/listinfo/security-review
if header :contains "List-Id" "<security-review.suse.de>" { discard; stop; }

# rule:[security-team]
# https://mailman.suse.de/mailman/listinfo/security-team
if header  :contains "List-Id" "<security-team.suse.de>" {

    # Discard newsletters coming US-CERT, these are duplicated for me as I'm already personally subscribed to that list.
    # Those can be found at: ML -> SecList -> CERT Advisories
    if address :is "From" [ "US-CERT@ncas.us-cert.gov",
                            "CISA@public.govdelivery.com",
                            "cisacommunity@ncas.us-cert.gov",
                            "US-CERT@messages.cisa.gov",
                            "CISA@messages.cisa.gov" ] {
        fileinto :create "INBOX/Trash";
        stop;
    }

    # Xorg-security ML
    if header :contains "X-BeenThere" "xorg-security@lists.x.org" {
        fileinto :create "INBOX/ML/SUSE/security-team/Xorg";
        stop;
    }

    # Samba ML
    if header :contains "From" "samba-bugs@samba.org" {
        fileinto :create "INBOX/ML/SUSE/security-team/Samba";
        stop;
    }

    # Weekly audit report for the proactive team to the proactive BZ folder
    if allof ( address :is "From" "jenkins@suse.de",
               address :is "To" "${SECURITY_TEAM_ADDR}",
               header  :contains "Subject" "Audit Bug Report for" ) {
        addflag "\\Seen";
        fileinto :create "INBOX/Tools/Bugzilla/Proactive/Reports";
        stop;
    }

    # Team's workreports
    if header :contains "Subject" [ "workreport", "work report" ] {
        fileinto :create "INBOX/ML/SUSE/security-team/workreport";
        stop;
    }

    # Ignore IDP TOTP pin codes
    if allof( header :is "Subject" "Your OTP",
              address :is "From" "idp-mfa@suse.de" ) {
        fileinto :create "INBOX/Trash";
        stop;
    }

    # If none of the above rules matched, then put to the main security-team folder
    if header :contains "List-Id" "<security-team.suse.de>" { 
        fileinto :create "INBOX/ML/SUSE/security-team";
        stop;
    }
}

# rule:[users]
# https://mailman.suse.de/mailman/listinfo/users
if header :contains "List-Id" "<users.suse.de>" { fileinto :create "INBOX/ML/SUSE/users"; stop; }

# rule:[kernel-security-sentinel]
# https://lists.suse.com/mailman/listinfo/kernel-security-sentinel
if header :contains "List-Id" "<kernel-security-sentinel.lists.suse.com>" { fileinto :create "INBOX/ML/SUSE/kernel-security"; stop; }

# rule:[smash-devel]
# https://mailman.suse.de/mailman/listinfo/smash-devel
if header :contains "List-Id" "<smash-devel.suse.de>" { fileinto :create "INBOX/Tools/Gitlab/Smash/smash-devel"; stop; }
