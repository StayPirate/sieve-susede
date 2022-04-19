require [ "fileinto", "mailbox", "body", "variables", "include", "regex", "editheader", "imap4flags" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME", "SECURITY_TEAM_ADDR" ];
# Flags
global [ "FLAG_DUPLICATED", "FLAG_BZ_REASSIGNED", "FLAG_BZ_RESOLVED", "FLAG_EMBARGOED", "FLAG_PUBLISHED",
         "FLAG_MUTED", "FLAG_NEEDINFO", "FLAG_BZ_CRITICAL", "FLAG_BZ_HIGH", "FLAG_BZ_DIRECT", "FLAG_BZ_BAD_HANDLED",
         "FLAG_BETA" ];

######################
#####  Bugzilla  #####
######################
# Tools
# └── Bugzilla
#     ├── openSUSE
#     ├── Direct
#     │   └── Needinfo
#     └── Security Team
#         ├── Embargoed
#         ├── Reassigned back
#         ├── Critical
#         ├── High
#         ├── Needinfo
#         ├── Proactive
#         │   └── Reports
#         └── Others
#             └── security-team

#    /$$      /$$             /$$
#   | $$$    /$$$            | $$
#   | $$$$  /$$$$ /$$   /$$ /$$$$$$    /$$$$$$
#   | $$ $$/$$ $$| $$  | $$|_  $$_/   /$$__  $$
#   | $$  $$$| $$| $$  | $$  | $$    | $$$$$$$$
#   | $$\  $ | $$| $$  | $$  | $$ /$$| $$_____/
#   | $$ \/  | $$|  $$$$$$/  |  $$$$/|  $$$$$$$
#   |__/     |__/ \______/    \___/   \_______/
#
###############################################

########## -----> BETA <----- ##########
# rule:[mute unmeaningful bz notification]
# Trash all the unwanted BZ notifications, but keep them if they contain a non-bot comment 
if allof ( address    :is "From"            "bugzilla_noreply@suse.com",
           header     :is "X-Bugzilla-Type" "changed",
           not body   :contains "Comment" ) {
                if anyof( # the only change is the subject
                          header :is "X-Bugzilla-Changed-Fields" "short_desc",
                          # the only change is the assigne
                          allof (     header :is "X-Bugzilla-Changed-Fields" "assigned_to",
                                  not header :is "X-Bugzilla-Assigned-To" [ "${SUSECOM_ADDR}", "${SECURITY_TEAM_ADDR}" ]),
                          # someone was CCed, but me
                          allof (     header :is "X-Bugzilla-Changed-Fields" "cc",
                                  not header :is "X-Bugzilla-Who" [ "${SUSECOM_ADDR}", "${SECURITY_TEAM_ADDR}" ]),
                          # the status change from NEW to IN_PROGRESS
                          allof ( header :is "X-Bugzilla-Changed-Fields" "bug_status",
                                  header :is "X-Bugzilla-Status" "IN_PROGRESS",
                                  body   :contains [ "Status|NEW", "Status  NEW     IN_PROGRESS" ]),
                          # comments are toggled between private and public state
                          header :is "X-Bugzilla-Changed-Fields" "longdescs.isprivate",
                          # issue blocks another issue
                          header :is "X-Bugzilla-Changed-Fields" "blocked",
                          # only the url field is changed
                          header :is "X-Bugzilla-Changed-Fields" "bug_file_loc",
                          # notification reffers to a related bz issue
                          body :regex "Bug [0-9]{6,}<.*> depends on[= \n]+bug [0-9]{6,}<.*>,",
                          # only the group field is changed
                          header :is "X-Bugzilla-Changed-Fields" "bug_group",
                          # security-team post the common embargoed instruction
                          allof ( header :contains "Subject" "EMBARGOED",
                                  body   :contains "This is an embargoed bug. This means that this information is not public.",
                                  body   :contains "THIS IS A PRIVATE COMMENT" ),
                          # only change is a "depends on" another bug
                          header :is "X-Bugzilla-Changed-Fields" "dependson"
                ) {
                    #addflag "${FLAG_MUTED}";
                    #fileinto :create "INBOX/Trash";
                    addflag "${FLAG_BETA}";
                }
}
########## -----> BETA <----- ##########

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

# rule:[mute security-team notification]
# This rule discards all the notification sent to security-team@suse.de.
# As a member of the SUSE security team I receive BZ notifications for both
# my personal account ${SUSECOM_ADDR} and security-team@suse.de via that ML.
# This, of course, makes me receive duplicated notifications when I'm
# personal involved in an issue where security-team@suse.de also is.
# === SOLUTION ===
# Fortunatelly BZ allows users to "watch" other users [0][1], and now that
# I started to watch security-team@suse.de I get all the notifications that
# it gets, but those are sent directly to ${SUSECOM_ADDR}.
# This is a much convinient way, beacuse if I'm also personally involved in
# the same BZ issue, then I get the notification only once.
# Watch a specific component would also have been a good solution, but this
# feature won't be available before Bugzilla v6.0 [1].
#
# With this in mind, I can sefely discard all the email notifications sent
# to security-team@suse.de. :)
#
# [0] https://www.bugzilla.org/docs/3.0/html/userpreferences.html
# [1] https://bugzilla.suse.com/userprefs.cgi
# [2] https://bugzilla.mozilla.org/show_bug.cgi?id=76794
if allof ( address :is       "From"           "bugzilla_noreply@suse.com",
           address :is       "To"             "${SECURITY_TEAM_ADDR}",
           header  :contains "List-Id"        "<security-team.suse.de>",
           header  :contains "X-Bugzilla-URL" [ "://bugzilla.suse.com", "://bugzilla.opensuse.org" ]) {
	discard;
    stop;
}

# rule:[mute all maint-coord notifications]
# Discard all the notifications sent to maint-coord
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           address :is "To" "maint-coord@suse.de" ) {
    discard;
    stop;
}

# rule:[mute n2p status]
# Ignore notification when the only change is the status from new to in progress
# But allow notifications with comments.
if allof ( address  :is "From" "bugzilla_noreply@suse.com",
           header   :is "X-Bugzilla-Type" "changed",
           header   :is "X-Bugzilla-Changed-Fields" "bug_status",
           header   :is "X-Bugzilla-Status" "IN_PROGRESS",
           anyof ( body     :contains "Status|NEW",
                   body     :contains "Status  NEW     IN_PROGRESS"),
           not body :contains "Comment" ) {
    addflag "${FLAG_MUTED}";
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[mute CC (if not me or security-team)]
# Trash if the only change is a new person added/removed to CC, but allow notification with a new comment.
if allof ( address    :is       "From"                      "bugzilla_noreply@suse.com",
           header     :is       "X-Bugzilla-Type"           "changed",
           header     :is       "X-Bugzilla-Changed-Fields" "cc",
           not header :is       "X-Bugzilla-Who"          [ "${SUSECOM_ADDR}", "${SECURITY_TEAM_ADDR}" ],
           not body   :contains "Comment" ) {
    addflag "${FLAG_MUTED}";
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[mute assigned_to changed (if not me or security-team)]
# Trash if the only change is the assignee, but allow notifications with new comments.
if allof ( address    :is       "From"                      "bugzilla_noreply@suse.com",
           header     :is       "X-Bugzilla-Type"           "changed",
           header     :is       "X-Bugzilla-Changed-Fields" "assigned_to",
           not header :is       "X-Bugzilla-Assigned-To"  [ "${SUSECOM_ADDR}", "${SECURITY_TEAM_ADDR}" ],
           not body   :contains "Comment" ) {
    addflag "${FLAG_MUTED}";
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[mute changed subject]
# Trash if the only change is a change to the issue's subject, but allow notifications with new comments.
if allof ( address    :is "From"                      "bugzilla_noreply@suse.com",
           header     :is "X-Bugzilla-Type"           "changed",
           header     :is "X-Bugzilla-Changed-Fields" "short_desc",
           not body   :contains "Comment" ) {
    addflag "${FLAG_MUTED}";
    fileinto :create "INBOX/Trash";
    stop;
}

#    /$$$$$$$$ /$$                 /$$                                 /$$
#   | $$_____/|__/                | $$                                | $$
#   | $$       /$$ /$$   /$$      | $$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$   /$$$$$$$
#   | $$$$$   | $$|  $$ /$$/      | $$__  $$ /$$__  $$ |____  $$ /$$__  $$ /$$__  $$ /$$__  $$ /$$_____/
#   | $$__/   | $$ \  $$$$/       | $$  \ $$| $$$$$$$$  /$$$$$$$| $$  | $$| $$$$$$$$| $$  \__/|  $$$$$$
#   | $$      | $$  >$$  $$       | $$  | $$| $$_____/ /$$__  $$| $$  | $$| $$_____/| $$       \____  $$
#   | $$      | $$ /$$/\  $$      | $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$$|  $$$$$$$| $$       /$$$$$$$/
#   |__/      |__/|__/  \__/      |__/  |__/ \_______/ \_______/ \_______/ \_______/|__/      |_______/
#
########################################################################################################

# rule:[fix MS Exchange broken threads]
# MS Exchange mangles email headers without any respect for the standards,
# this leads to a different bad behavior from non-Outlook MUA.
# This rule is intended to re-create the correct Message-ID header in order
# to fix the broken threads in Thunderbird.
if allof ( header :regex "Message-ID" ".*\.outlook\.com>$",
           header :matches "x-ms-exchange-parent-message-id" "*" ) {
             # Replace Message-ID with x-ms-exchange-parent-message-id
             deleteheader "Message-ID";
             addheader :last "Message-ID" "${1}";
}

# rule:[fix opensuse.org and suse.com broken threads]
# SUSE has two separated bugzilla instances that write to the same
# database: bugzilla.suse.com and bugzilla.opensuse.org.
# Hence, people could comment on the same issue from both of them. This is
# a problem for email threads because two threads are created in MUAs, one
# with all the emails sent from bugzilla.suse.com and another with emails
# sent from bugzilla.opensuse.org, even if these are about the same issue.
# This rule is intended to fix this by overwriting relevant headers by
# setting them to bugzilla.suse.com.
if header :regex "Message-ID" "(.*bug-[0-9]+-[0-9]+)(.*)@http\.bugzilla\.opensuse\.org/>$" {
    deleteheader "Message-ID";
    addheader :last "Message-ID" "${1}${2}@http.bugzilla.suse.com/>";
    if header :contains "In-Reply-To" "@http.bugzilla.opensuse.org/>" {
        deleteheader "In-Reply-To";
        addheader :last "In-Reply-To" "${1}@http.bugzilla.suse.com/>";
    }
    if header :contains "References" "@http.bugzilla.opensuse.org/>" {
        deleteheader "References";
        addheader :last "References" "${1}@http.bugzilla.suse.com/>";
    }
}

#    /$$$$$$$$ /$$
#   | $$_____/| $$
#   | $$      | $$  /$$$$$$   /$$$$$$   /$$$$$$$
#   | $$$$$   | $$ |____  $$ /$$__  $$ /$$_____/
#   | $$__/   | $$  /$$$$$$$| $$  \ $$|  $$$$$$
#   | $$      | $$ /$$__  $$| $$  | $$ \____  $$
#   | $$      | $$|  $$$$$$$|  $$$$$$$ /$$$$$$$/
#   |__/      |__/ \_______/ \____  $$|_______/
#                            /$$  \ $$
#                           |  $$$$$$/
#                            \______/
#
################################################

# rule:[flags - needinfo for security-team]
# Needinfo requested for security-team
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           header  :contains "Subject" "needinfo requested:",
           body    :contains "<${SECURITY_TEAM_ADDR}> for needinfo:" ) {
    addflag "${FLAG_NEEDINFO}";
}

# rule:[flags - needinfo for me]
# Needinfo requested for me
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           header  :contains "Subject" "needinfo requested:",
           body    :contains "<${SUSECOM_ADDR}> for needinfo:" ) {
    addflag "${FLAG_NEEDINFO}";
}

# rule:[flags - embargoed notifications]
# notification about an embargoed issue
if allof ( address :is "From" "bugzilla_noreply@suse.com", 
           header  :contains "Subject" "EMBARGOED" ) {
    addflag "${FLAG_EMBARGOED}";
}

# rule:[flags - embargoed issue get public]
# Embargoed issues become public
if allof ( address    :is "From" "bugzilla_noreply@suse.com", 
           header     :is "X-Bugzilla-Type" "changed",
           header     :contains "X-Bugzilla-Changed-Fields" "short_desc",
           not header :contains "Subject" "EMBARGOED",
           body       :contains "EMBARGOED" ) {
    addflag "${FLAG_PUBLISHED}";
}

# rule:[flags - issue is resolved]
# As an agreement, all the security related issues should not be closed by the
# assignee once he did his work, instead the issue should to be assigned back to
# the security team, who will then review and close the issue if everything is fine.
# The rule put the closing notification in the same folder of the re-assigned one.
# This helps me to quickly check which BZ issues are still open and which not.
# Also prepend the tag [RESOLVED] in the email's subject.
if allof ( address :is       "From"                      "bugzilla_noreply@suse.com",
           header  :is       "X-Bugzilla-Type"           "changed",
           header  :contains "x-bugzilla-changed-fields" "bug_status",
           header  :is       "X-Bugzilla-Status"         "RESOLVED" ) {
               if header :is "x-bugzilla-assigned-to"    "${SECURITY_TEAM_ADDR}" {
                   addflag "${FLAG_BZ_RESOLVED}";
                   # TODO: I can also add here the flag \\Seen in case the issue was
                   #       closed by a security team member.
               } else {
                   addflag "${FLAG_BZ_BAD_HANDLED}";
               }
}

# rule:[flags - reassigned to security-team]
# Issues re-assigned to the security-team
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           header  :is "x-bugzilla-assigned-to" "${SECURITY_TEAM_ADDR}",
           header  :is "X-Bugzilla-Type" "changed",
           header  :contains "x-bugzilla-changed-fields" "assigned_to" ) {
                addflag "${FLAG_BZ_REASSIGNED}";
}

# rule:[flags - critical priority issues]
# Move critical priority issues to a dedicated folder
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           anyof( header  :is "X-Bugzilla-Priority" "P0 - Crit Sit",
                  header  :is "X-Bugzilla-Priority" "P1 - Urgent",
                  header  :is "X-Bugzilla-Severity" "Critical")) {
    addflag "${FLAG_BZ_CRITICAL}";
}

# rule:[flags - high priority issues]
# Move high priority issues to a dedicated folder
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           header  :is "X-Bugzilla-Priority" "P2 - High" ) {
    addflag "${FLAG_BZ_HIGH}";
}

# rule:[flags - notification directed to me]
# Notifications sent directly to me, the reason could be I'm the reporter or CC or assignee etc..
if allof (     address :is "From" "bugzilla_noreply@suse.com",
           not header  :is "x-bugzilla-reason" "None" ) {
    addflag "${FLAG_BZ_DIRECT}";
}

#    /$$$$$$$$        /$$       /$$
#   | $$_____/       | $$      | $$
#   | $$     /$$$$$$ | $$  /$$$$$$$  /$$$$$$   /$$$$$$   /$$$$$$$
#   | $$$$$ /$$__  $$| $$ /$$__  $$ /$$__  $$ /$$__  $$ /$$_____/
#   | $$__/| $$  \ $$| $$| $$  | $$| $$$$$$$$| $$  \__/|  $$$$$$
#   | $$   | $$  | $$| $$| $$  | $$| $$_____/| $$       \____  $$
#   | $$   |  $$$$$$/| $$|  $$$$$$$|  $$$$$$$| $$       /$$$$$$$/
#   |__/    \______/ |__/ \_______/ \_______/|__/      |_______/
#
#################################################################   

# rule:[folders - proactive security audit bugs]
# Notifications about AUDIT bugs are not part of the reactive security scope, so they
# will be moved into the a dedicated folder Tools/Bugzilla/Security Team/Proactive.
#
# Note: keep this rule before the "not security reactive issues" rule, since AUDIT bugs are
# sometimes created in different BZ products/components!
if allof ( address :is    "From"    "bugzilla_noreply@suse.com", 
           header  :regex "subject" "^\[Bug [0-9]{7,}] (New: )?AUDIT-(0|1|TASK|FIND|TRACKER|STALE|WHITELIST):.*$" ) {
    addflag "\\Seen";
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Proactive";
    stop;
}

# rule:[folders - opensuse issues]
# openSUSE only bugs
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           header :contains "X-Bugzilla-Product" "openSUSE" ){
              fileinto :create "INBOX/Tools/Bugzilla/openSUSE";
              stop;
}

# rule:[folders - not security reactive issues]
# Security related issues that are not the usual reactive/proactive tasks.
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           not header :is "X-Bugzilla-Product" "SUSE Security Incidents",
           not header :is "X-Bugzilla-Component" "Incidents",
           # "Live Patches" is a component of the "SUSE Linux Enterprise Live Patching", but they are part of the daily reactive tasks.
           not header :is "X-Bugzilla-Component" "Live Patches",
           not header :contains "Subject" "needinfo canceled:" ){
              if header :contains "x-bugzilla-watch-reason" "${SECURITY_TEAM_ADDR}" {
                 fileinto :create "INBOX/Tools/Bugzilla/Security Team/Others/security-team"; }
              else {
                 fileinto :create "INBOX/Tools/Bugzilla/Security Team/Others"; }
              stop;
}

# rule:[folders - generic notification for security-team]
# Notifications sent to security-team, no bot's messages end up here.
if address :is "From" "bugzilla_noreply@suse.com" {
    fileinto :create "INBOX/Tools/Bugzilla";
    stop;
}