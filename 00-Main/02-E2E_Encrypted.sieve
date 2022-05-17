require ["fileinto", "mailbox", "variables", "include", "editheader", "regex"];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "USERNAME" ];

# GPG encrypted emails are not checked from the SUSE mail server, and
# it change the subject by prepending the string ***UNCHECKED***.
# This is anoying and can cause issue when reply to encrypted MLs, so
# this filter is intended to revert such behavior.

# store the original subject in a variable that later rules can use
if allof ( header :regex    "Subject" "^(\\*\\*\\*UNCHECKED\\*\\*\\* )(.*)",
           header :contains "X-Spam-Status" "ENCRYPTED_MESSAGE=-1" ) {
    # delete the orginal subject...
    deleteheader "Subject";
    addheader :last "Subject" "${2}";
}