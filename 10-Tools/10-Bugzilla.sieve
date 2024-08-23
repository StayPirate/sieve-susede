require [ "fileinto", "mailbox", "body", "variables", "include", "regex", "editheader", "imap4flags" ];

# Global vars
global [ "SUSECOM_ADDR", "SECURITY_TEAM_ADDR" ];
global [ "FLAG_DUPLICATED", "FLAG_MUTED", "FLAG_BETA", "FLAG_DIRECT" ];
# Local vars
set "FLAG_BZ_REASSIGNED"  "bz_reassigned";
set "FLAG_BZ_RESOLVED"    "bz_resolved";
set "FLAG_EMBARGOED"      "embargoed";
set "FLAG_PUBLISHED"      "published";
set "FLAG_NEEDINFO"       "needinfo";
set "FLAG_BZ_CRITICAL"    "critical";
set "FLAG_BZ_HIGH"        "high";
set "FLAG_BZ_BAD_HANDLED" "bz_bad_handled";

######################
#####  Bugzilla  #####
######################
# Tools
# └── Bugzilla
#     ├── openSUSE
#     ├── Proactive
#     │   └── Reports
#     └── Other

if address :is "From" [ "bugzilla-noreply@suse.com", "bugzilla_noreply@suse.com" ] {

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

    # rule:[mute bots]
    # Do not allow bots to make noise to specific Bugzilla's sub-folder,
    # put them into the generic Bugzilla folder instead.
    if anyof ( header :is "X-Bugzilla-Who" "swamp@suse.de",
               header :is "X-Bugzilla-Who" "bwiedemann+obsbugzillabot@suse.com",
               allof ( header :is "X-Bugzilla-Who" "smash_bz@suse.de",
                       not header :is "X-Bugzilla-Type" "new" ),
               header :is "x-bugzilla-who" "maint-coord+maintenance_robot@suse.de",
               header :is "x-bugzilla-who" "maint-coord+maintenance-robot@suse.de",
               header :is "x-bugzilla-who" "openqa-review@suse.de",
               allof ( header :is "X-Bugzilla-Who" "meissner@suse.com",
                       body :regex "openSUSE-[SR]U-.*: An update" )) {
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
    if allof ( address :is       "To"             "${SECURITY_TEAM_ADDR}",
               header  :contains "List-Id"        "<security-team.suse.de>",
               header  :contains "X-Bugzilla-URL" [ "://bugzilla.suse.com", "://bugzilla.opensuse.org" ]) {
    	discard;
        stop;
    }

    # rule:[mute all maint-coord notifications]
    # Discard all the notifications sent to maint-coord
    if address :is "To" "maint-coord@suse.de" {
        discard;
        stop;
    }

    # rule:[mute unmeaningful bz notification]
    if anyof (

        # Trash all the unwanted BZ notifications, but keep them if they contain a non-bot comment
        allof ( header     :is "X-Bugzilla-Type" "changed",
                not body   :contains "Comment",
                anyof( 
                       # the only change is the subject
                       header :is "X-Bugzilla-Changed-Fields" "short_desc",

                       # the only change is the assigne
                       allof (     header :is "X-Bugzilla-Changed-Fields" "assigned_to",
                               not header :is "X-Bugzilla-Assigned-To" [ "${SUSECOM_ADDR}", "${SECURITY_TEAM_ADDR}" ]),

                       # someone was CCed, but me
                       allof (     header :is "X-Bugzilla-Changed-Fields" "Cc",
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

                       # only change is a "depends on" another bug
                       header :is "X-Bugzilla-Changed-Fields" "dependson"
                )
            ),

        # security-team post the common embargoed instruction
        allof ( header :contains "Subject" "EMBARGOED",
                body   :contains "This is an embargoed bug. This means that this information is not public.",
                body   :contains "THIS IS A PRIVATE COMMENT" )
    ) {
        addflag "${FLAG_MUTED}";
    }

    if hasflag :contains "${FLAG_MUTED}" {
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
    if header :regex "Message-ID" "(.*bug-[0-9]+-[0-9]+)(.*)@http[s]?\.bugzilla\.(opensuse\.org|suse\.com)/>$" {
        deleteheader "Message-ID";
        addheader :last "Message-ID" "${1}${2}@http.bugzilla.suse.com/>";
        if header :matches "In-Reply-To" [ "*@https\.bugzilla\.suse\.com/>",
                                           "*@https\.bugzilla\.opensuse\.org/>",
                                           "*@http\.bugzilla\.opensuse\.org/>" ] {
            deleteheader "In-Reply-To";
            addheader :last "In-Reply-To" "${1}@http.bugzilla.suse.com/>";
        }
        if header :matches "References" [ "*@https\.bugzilla\.suse\.com/>",
                                          "*@https\.bugzilla\.opensuse\.org/>",
                                          "*@http\.bugzilla\.opensuse\.org/>" ] {
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
    if allof ( header  :contains "Subject" "needinfo requested:",
               body    :contains "<${SECURITY_TEAM_ADDR}> for needinfo:" ) {
        addflag "${FLAG_NEEDINFO}";
    }

    # rule:[flags - needinfo for me]
    # Needinfo requested for me
    if allof ( header  :contains "Subject" "needinfo requested:",
               body    :contains "<${SUSECOM_ADDR}> for needinfo:" ) {
        addflag "${FLAG_NEEDINFO}";
    }

    # rule:[flags - embargoed notifications]
    # notification about an embargoed issue
    if header :contains "Subject" "EMBARGOED" {
        addflag "${FLAG_EMBARGOED}";
    }

    # rule:[flags - embargoed issue get public]
    # Embargoed issues become public
    if allof ( header     :is "X-Bugzilla-Type" "changed",
               header     :contains "X-Bugzilla-Changed-Fields" "short_desc",
               not header :contains "Subject" "EMBARGOED",
               body       :contains "EMBARGOED" ) {
        addflag "${FLAG_PUBLISHED}";
    }

    # rule:[flags - issue is resolved]
    # Internal agreement states that all the security related BZ issues should NOT be closed
    # by the assignee once his job is done, instead the issue should to be reassigned back to
    # the security team, who will then review it and only close the issue if everything is fine.
    # This sieve rule flags incoming notifications as FLAG_BZ_RESOLVED if that's assigned to the
    # security-team at the time it gets closed, or flags it as FLAG_BZ_BAD_HANDLED if that was
    # still assigned to anybody else.
    # That helps to quickly spot BZ issues that are correcly closed and the ones which haven't
    # followed the right steps.
    if allof ( header  :is       "X-Bugzilla-Type"           "changed",
               header  :contains "x-bugzilla-changed-fields" "bug_status",
               header  :is       "X-Bugzilla-Status"         "RESOLVED" ) {
                   if header :is "x-bugzilla-assigned-to"    "${SECURITY_TEAM_ADDR}" {
                       addflag "${FLAG_BZ_RESOLVED}";
                       # TODO: I could add here the flag \\Seen in case the issue was
                       #       closed by a security team member.
                   } else {
                       addflag "${FLAG_BZ_BAD_HANDLED}";
                   }
    }

    # rule:[flags - reassigned to security-team]
    # Issues re-assigned to the security-team
    if allof ( header  :is "x-bugzilla-assigned-to" "${SECURITY_TEAM_ADDR}",
               header  :is "X-Bugzilla-Type" "changed",
               header  :contains "x-bugzilla-changed-fields" "assigned_to" ) {
                    addflag "${FLAG_BZ_REASSIGNED}";
    }

    # rule:[flags - critical priority issues]
    # Move critical priority issues to a dedicated folder
    if anyof( header  :is "X-Bugzilla-Priority" "P0 - Crit Sit",
              header  :is "X-Bugzilla-Priority" "P1 - Urgent",
              header  :is "X-Bugzilla-Severity" "Critical") {
        addflag "${FLAG_BZ_CRITICAL}";
    }

    # rule:[flags - high priority issues]
    # Move high priority issues to a dedicated folder
    if header :is "X-Bugzilla-Priority" "P2 - High" {
        addflag "${FLAG_BZ_HIGH}";
    }

    # rule:[flags - notification directed to me]
    # Notifications sent directly to me, the reason could be I'm the reporter or CC or assignee etc..
    if not header :is "x-bugzilla-reason" "None" {
        addflag "${FLAG_DIRECT}";
    }

    # rule:[flags - unfocus non-direct notifications]
    # Mark all less important notifications as read. I only want to get focus on comments where
    #  * A needinfo flag is assigned to me or to my team
    #  * Comments that reassign the bug to the security team
    #  * Comments that close bugs without having reassigned
    #    it to the security team first
    if not hasflag :contains [ "${FLAG_BZ_BAD_HANDLED}", "${FLAG_NEEDINFO}", "${FLAG_BZ_REASSIGNED}" ] {
         addflag "\\Seen";
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
    if header :regex "subject" "^\[Bug [0-9]{7,}] (New: )?AUDIT-(0|1|TASK|FIND|TRACKER|STALE|WHITELIST):.*$" {
        addflag "\\Seen";
        fileinto :create "INBOX/Tools/Bugzilla/Proactive";
        stop;
    }

    # rule:[folders - opensuse issues]
    # openSUSE only bugs
    if header :contains "X-Bugzilla-Product" "openSUSE" {
        fileinto :create "INBOX/Tools/Bugzilla/openSUSE";
        stop;
    }

    # rule:[folders - not security reactive issues]
    # Security related issues that are not the usual reactive/proactive tasks.
    if allof ( not hasflag :contains "${FLAG_NEEDINFO}",
               not header :is "X-Bugzilla-Product" [ "SUSE Security Incidents", "SUSE Linux Enterprise Live Patching" ],
               not header :is "X-Bugzilla-Component" [ "Incidents", "Live Patches", "Kernel Live Patches" ] ){
                  fileinto :create "INBOX/Tools/Bugzilla/Other";
                  stop;
    }

    # All the other notification goes in the main Bugzilla folder
    fileinto :create "INBOX/Tools/Bugzilla";
    stop;

}