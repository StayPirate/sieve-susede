require ["fileinto", "mailbox", "variables", "include", "envelope"];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "USERNAME" ];

# rule:[Spam]
if allof ( header :contains "X-Spam-Flag" "YES",

           ###  W H I T E L I S T  ###
           # Below are the rules to whitelist SPAM emails (X-Spam-Flag:YES).
           # They will always be treated as non-SPAM.

           # Always deliver distros and linux-distros messages
           not header :is "X-List" "vs.openwall.org",

           # osss usually gets very few SPAM emails. Most of the flagged ones are false positives.
           # Hence, whitelist all of them.
           not header :is "List-ID" "<oss-security.lists.openwall.com>",

           # Always deliver CISA notifications
           not address :is "From" [ "cert+donotreply@cert.org", "US-CERT@messages.cisa.gov" ],

           # Always allow SUSE BZ notifications
           not address :is "From" "bugzilla_noreply@suse.com",

           # Always deliver internal gitlab instance notifications
           not envelope :is "From" "gitlab@suse.de"

) {
    fileinto :create "INBOX/Spam";
    stop;
}

# rule:[Unwanted emails]
# Trash non-SPAM recurring unwanted emails
if allof ( address :is "To" "${SUSECOM_ADDR}",
           anyof ( address :domain "From" [ "checkmarx.com", "veeam.com", "apiiro.com", "magnetforensics.com",
                                            "tryendorlabs.ai", "info.microstrategy.com", "microstrategy.com",
                                            "fortinet.com", "global.fortinet.com", "netscout.com", "tp2.terrapinn.com" ],
                   address :is "From" "messages-noreply@linkedin.com" )
    ) {
    fileinto :create "INBOX/Spam";
    stop;
}
