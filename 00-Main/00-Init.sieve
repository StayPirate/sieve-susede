# Sieve: https://tools.ietf.org/html/rfc5228
require [ "variables", "include" ];

### Variables ###
#
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME", "SECURITY_TEAM_ADDR" ];
set "SUSEDE_ADDR" "ggabrielli@suse.de";
set "SUSECOM_ADDR" "gianluca.gabrielli@suse.com";
set "BZ_USERNAME" "crazybyte";
SET "SECURITY_TEAM_ADDR" "security-team@suse.de";

### System Flags ###
# IMAP system flags are specified at
# https://datatracker.ietf.org/doc/html/rfc3501#section-2.3.2
# Usually: \Answered \Flagged \Draft \Deleted \Seen \Recent
#
global [ "SYSTEM_FLAG_SEEN" ];
set "SYSTEM_FLAG_SEEN" "\\Seen";
#
### Custom Flags ###
# Custom flags are available if the IMAP server enable them.
# In order to check if your server allows you to use them, you can check if
# \* is present in the PERMANENTFLAGS setting.
# E.g:
#     * OK [PERMANENTFLAGS (\Answered \Flagged \Draft \Deleted \Seen \*)]
# You can get this info connecting to your imap server via cmdline, you can
# use the openssl cmdline utility for that:
#     > openssl s_client -connect imap-int.suse.de:993
#
global [ "FLAG_DUPLICATED", "FLAG_BZ_REASSIGNED", "FLAG_BZ_RESOLVED",
         "FLAG_EMBARGOED", "FLAG_PUBLISHED" ];
set "FLAG_DUPLICATED"    "duplicated";
set "FLAG_BZ_REASSIGNED" "bz_reassigned";
set "FLAG_BZ_RESOLVED"   "bz_resolved";
set "FLAG_EMBARGOED"     "embargoed";
set "FLAG_PUBLISHED"     "published";

include :personal "01-Spam.sieve";

# GPG encrypted emails
include :personal "02-E2E_Encrypted.sieve";

# Internal tools notification
include :personal "10-Bugzilla.sieve";
include :personal "10-IBS.sieve";
include :personal "10-OBS.sieve";
include :personal "10-Confluence.sieve";
include :personal "10-Gitlab.sieve";
include :personal "10-Jira.sieve";

# Mailing Lists
include :personal "20-Internal_ML.sieve";
include :personal "21-External_ML.sieve";

# News Letters
include :personal "30-Linux.sieve";
include :personal "30-security.sieve";