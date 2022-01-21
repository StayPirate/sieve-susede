require [ "fileinto", "mailbox", "body", "variables", "include", "regex" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

######################
#####  Bugzilla  #####
######################
# Tools
# └── Bugzilla
#     ├── Direct
#     │   └── Needinfo
#     └── Security Team
#         ├── Embargoed
#         ├── Reassigned back
#         ├── Critical
#         ├── High
#         └── Needinfo

# rule:[mute bots]
# Do not allow bots to make noise to specific Bugzilla's sub-folder,
# put them into the generic Bugzilla folder instead.
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           anyof ( header :is "X-Bugzilla-Who" "swamp@suse.de",
                   header :is "X-Bugzilla-Who" "bwiedemann+obsbugzillabot@suse.com",
                   header :is "X-Bugzilla-Who" "smash_bz@suse.de",
                   header :is "x-bugzilla-who" "maint-coord+maintenance_robot@suse.de",
                   header :is "x-bugzilla-who" "openqa-review@suse.de" )) {
	discard;
	stop;
}

# rule:[mute n2p status]
# Ignore notification when the only change is the status from new to in progress
# But allow notification with a new comment.
if allof ( address  :is "From" "bugzilla_noreply@suse.com",
           header   :is "X-Bugzilla-Type" "changed",
           header   :is "X-Bugzilla-Changed-Fields" "bug_status",
           header   :is "X-Bugzilla-Status" "IN_PROGRESS",
           anyof ( body     :contains "Status|NEW",
                   body     :contains "Status  NEW     IN_PROGRESS"),
           not body :contains "--- Comment #" ) {
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[mute new (not me) CC or assigned_to]
# Ignore, if the only change is a new person added/removed to CC, or changed the assignee.
# But allow notification with a new comment.
if allof ( address  :is       "From" "bugzilla_noreply@suse.com",
           header   :is       "X-Bugzilla-Type" "changed",
           anyof ( header   :contains "X-Bugzilla-Changed-Fields" "cc",
                   header   :contains "X-Bugzilla-Changed-Fields" "assigned_to"),
           not body :contains "Comment" ) {
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[security - needinfo secteam]
# Needinfo requested for security-team
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           address :is "To"   "security-team@suse.de",
           header  :contains "Subject" "needinfo requested:" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Needinfo";
    stop;
}

# rule:[Embargoed notification]
if allof ( address :is "From" "bugzilla_noreply@suse.com", 
           address :is "To" "security-team@suse.de",
           header  :contains "Subject" "EMBARGOED" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Embargoed";
    stop;
}

# rule:[No Longer Embargoed]
# Embargoed issues when become public
if allof ( address    :is "From" "bugzilla_noreply@suse.com", 
           address    :is "To" "security-team@suse.de",
           header     :is "X-Bugzilla-Type" "changed",
           header     :contains "X-Bugzilla-Changed-Fields" "short_desc",
           not header :contains "Subject" "EMBARGOED",
           body       :contains "EMBARGOED" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Embargoed";
    stop;
}

# rule:[security - reassigned]
# Issues re-assigned to security-team
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           address :is "To"   "security-team@suse.de",
           header  :is "x-bugzilla-assigned-to" "security-team@suse.de",
           header  :is "X-Bugzilla-Type" "changed",
           header  :contains "x-bugzilla-changed-fields" "assigned_to" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Reassigned back";
    stop;
}

# rule:[security - reassigned issue is processed]
# After an issue was assigned back to security-team, someone from that team
# might re-assigne it to someone elese. In that case, I want that information
# within the same folder of the previous reassigned notification.
#
# Example used to craft the regex:
# Assignee|security-team@suse.de       |kernel-bugs@suse.de
if allof (     address :is "From" "bugzilla_noreply@suse.com",
               address :is "To"   "security-team@suse.de",
           not header  :is "x-bugzilla-assigned-to" "security-team@suse.de",
               header  :is "X-Bugzilla-Type" "changed",
               header  :contains "x-bugzilla-changed-fields" "assigned_to",
               body    :contains "Assignee|security-team@suse.de" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Reassigned back";
    stop;
}

# rule:[security - issue is resolved]
# As an agreement security related issues should not be closed by the assignee
# after he solve the issue, instead the issue has to be assigned back to the
# security team, who will then review it and close the issue if everything is ok.
# The following rule put the closing notification right after the re-assigned to
# security-team notification. This will help me to quickly see which are the BZ
# issues which are reasigned back but not closed (reviewd by the security team).
if allof ( address :is       "From"                      "bugzilla_noreply@suse.com",
           address :is       "To"                        "security-team@suse.de",
           header  :is       "x-bugzilla-assigned-to"    "security-team@suse.de",
           header  :is       "X-Bugzilla-Type"           "changed",
           header  :contains "x-bugzilla-changed-fields" "bug_status",
           header  :is       "X-Bugzilla-Status"         "RESOLVED" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Reassigned back";
    stop;
}

# rule:[direct needinfo]
# Needinfo requested for me
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           address :is "To"   "${SUSECOM_ADDR}",
           header  :contains "Subject" "needinfo requested:" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Direct/Needinfo";
    stop;
}

# rule:[direct notification]
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           address :is "To" "${SUSECOM_ADDR}" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Direct";
    stop;
}

# rule:[High priority issues]
# Move high priority issues to a dedicated folder
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           address :is "To" "security-team@suse.de",
           header  :is "X-Bugzilla-Priority" "P2 - High" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/High";
    stop;
}

# rule:[Critical priority issues]
# Move critical priority issues to a dedicated folder
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           address :is "To" "security-team@suse.de",
           anyof( header  :is "X-Bugzilla-Priority" "P0 - Crit Sit",
                  header  :is "X-Bugzilla-Priority" "P1 - Urgent",
                  header  :is "X-Bugzilla-Severity" "Critical")) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Critical";
    stop;
}

# rule:[maint-coord - catch all]
# Discard all the issues assigned to maint-coord
if allof ( address :is "From" "bugzilla_noreply@suse.com", 
           address :is "To" "maint-coord@suse.de" ) {
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[BZ - security]
# Notifications sent to security-team, no bot's messages end up here.
if allof ( address :is "From" "bugzilla_noreply@suse.com", 
           address :is "To" "security-team@suse.de" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team";
    stop;
}