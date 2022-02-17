require [ "fileinto", "mailbox", "body", "variables", "include", "regex", "editheader" ];
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
#         ├── Needinfo
#         └── Proactive

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
# my personal account ${SUSEDE_ADDR} and security-team@suse.de via that ML.
# This, of course, makes me receive duplicated notifications when I'm
# personal involved in an issue where security-team@suse.de also is.
# === SOLUTION ===
# Fortunatelly BZ allows users to "watch" other users [0][1], and now that
# I started to watch security-team@suse.de I get all the notifications that
# it gets, but those are sent directly to ${SUSEDE_ADDR}.
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
           address :is       "To"             "security-team@suse.de",
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
           not body :contains "--- Comment #" ) {
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[mute new (not me) CC]
# Trash if the only change is a new person added/removed to CC, but allow notification with a new comment.
if allof ( address    :is       "From"                      "bugzilla_noreply@suse.com",
           header     :is       "X-Bugzilla-Type"           "changed",
           header     :is       "X-Bugzilla-Changed-Fields" "cc",
           not header :is       "X-Bugzilla-Who"          [ "${SUSEDE_ADDR}", "security-team@suse.de" ],
           not body   :contains "Comment" ) {
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[mute new (not me) assigned_to]
# Trash if the only change is the assignee, but allow notifications with new comments.
if allof ( address    :is       "From"                      "bugzilla_noreply@suse.com",
           header     :is       "X-Bugzilla-Type"           "changed",
           header     :contains "X-Bugzilla-Changed-Fields" "assigned_to",
           not header :is       "X-Bugzilla-Assigned-To"  [ "${SUSEDE_ADDR}", "security-team@suse.de" ],
           not body   :contains "Comment" ) {
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[proactive security audit bugs]
# Notifications about AUDIT bugs are not part of the reactive security scope, so they
# will be moved into the a dedicated folder Tools/Bugzilla/Security Team/Proactive.
if allof ( address :is    "From"    "bugzilla_noreply@suse.com", 
           header  :regex "subject" "^\[Bug [0-9]{7,}] (New: )?AUDIT-(0|1|TASK|FIND|TRACKER):.*$" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team";
    stop;
}

# rule:[needinfo for security-team]
# Needinfo requested for security-team
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           header  :contains "Subject" "needinfo requested:",
           body    :contains "<security-team@suse.de> for needinfo:" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Needinfo";
    stop;
}

# rule:[needinfo for me]
# Needinfo requested for me
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           header  :contains "Subject" "needinfo requested:",
           body    :contains "<${SUSEDE_ADDR}> for needinfo:" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Direct/Needinfo";
    stop;
}

# rule:[embargoed notifications]
if allof ( address :is "From" "bugzilla_noreply@suse.com", 
           header  :contains "Subject" "EMBARGOED" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Embargoed";
    stop;
}

# rule:[embargoed issue get public]
# Embargoed issues become public notifications
if allof ( address    :is "From" "bugzilla_noreply@suse.com", 
           header     :is "X-Bugzilla-Type" "changed",
           header     :contains "X-Bugzilla-Changed-Fields" "short_desc",
           not header :contains "Subject" "EMBARGOED",
           body       :contains "EMBARGOED" ) {
    if header :matches "Subject" "*" { set "subject" "${1}"; }    # Match the entire subject
    deleteheader "Subject";                                       # Delete the orginal subject
    addheader :last "Subject" "[PUBLISHED] ${subject}";
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Embargoed";
    stop;
}

# rule:[reassigned to security-team]
# Issues re-assigned to the security-team
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           header  :is "x-bugzilla-assigned-to" "security-team@suse.de",
           header  :is "X-Bugzilla-Type" "changed",
           header  :contains "x-bugzilla-changed-fields" "assigned_to" ) {
                # Store the original subject in a variable that later rules can use
                if header :matches "Subject" "*" { set "subject" "${1}"; }    # Match the entire subject
                deleteheader "Subject";                                       # Delete the orginal subject
                addheader :last "Subject" "[REASSIGNED] ${subject}";
                fileinto :create "INBOX/Tools/Bugzilla/Security Team/Reassigned back";
                stop;
}

# rule:[reassigned issue requires more work]
# After that an issue is assigned back to security-team, it can happen that it will be
# re-assigned to another team/person since more work is needed. In that case it want to
# get such informaion in the same folder where the re-assign to the security-team was.
#
# Example used to craft the regex:
# Assignee|security-team@suse.de       |kernel-bugs@suse.de
#
if allof (     address :is "From" "bugzilla_noreply@suse.com",
           not header  :is "x-bugzilla-assigned-to" "security-team@suse.de",
               header  :is "X-Bugzilla-Type" "changed",
               header  :contains "x-bugzilla-changed-fields" "assigned_to",
               body    :contains "Assignee|security-team@suse.de" ) {
                  fileinto :create "INBOX/Tools/Bugzilla/Security Team/Reassigned back";
                  stop;
}

# rule:[issue is resolved]
# As an agreement, all the security related issues should not be closed by the
# assignee once he did his work, instead the issue should to be assigned back to
# the security team, who will then review and close the issue if everything is fine.
# The rule put the closing notification in the same folder of the re-assigned one.
# This helps me to quickly check which BZ issues are still open and which not.
# Also prepend the tag [RESOLVED] in the email's subject.
if allof ( address :is       "From"                      "bugzilla_noreply@suse.com",
           header  :is       "x-bugzilla-assigned-to"    "security-team@suse.de",
           header  :is       "X-Bugzilla-Type"           "changed",
           header  :contains "x-bugzilla-changed-fields" "bug_status",
           header  :is       "X-Bugzilla-Status"         "RESOLVED" ) {
               # Store the original subject in a variable that later rules can use
               if header :matches "Subject" "*" { set "subject" "${1}"; }    # Match the entire subject
               deleteheader "Subject";                                       # Delete the orginal subject
               addheader :last "Subject" "[RESOLVED] ${subject}";
               fileinto :create "INBOX/Tools/Bugzilla/Security Team/Reassigned back";
               stop;
}

# rule:[critical priority issues]
# Move critical priority issues to a dedicated folder
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           anyof( header  :is "X-Bugzilla-Priority" "P0 - Crit Sit",
                  header  :is "X-Bugzilla-Priority" "P1 - Urgent",
                  header  :is "X-Bugzilla-Severity" "Critical")) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/Critical";
    stop;
}

# rule:[high priority issues]
# Move high priority issues to a dedicated folder
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           header  :is "X-Bugzilla-Priority" "P2 - High" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team/High";
    stop;
}

# rule:[generic notification for security-team]
# Notifications sent to security-team, no bot's messages end up here.
if allof ( address :is "From" "bugzilla_noreply@suse.com",
           header  :contains "x-bugzilla-watch-reason" "security-team@suse.de" ) {
    fileinto :create "INBOX/Tools/Bugzilla/Security Team";
    stop;
}

# rule:[generic notification for me]
if address :is "From" "bugzilla_noreply@suse.com" {
    fileinto :create "INBOX/Tools/Bugzilla/Direct";
    stop;
}
