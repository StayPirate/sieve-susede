# Sieve: https://tools.ietf.org/html/rfc5228
require [ "variables", "include" ];

set "susede_addr" "ggabrielli@suse.de";
set "susecom_addr" "gianluca.gabrielli@suse.com";
set "bugzilla_username" "crazybyte";

include :personal "01-Spam.sieve";

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