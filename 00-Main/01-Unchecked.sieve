require ["fileinto", "mailbox", "variables", "include", "editheader", "regex"];

# GPG/end-to-end encrypted (and some other) emails are not checked from the SUSE
# mail server, so it change the subject by prepending the string ***UNCHECKED***.
# This is anoying and can cause issue when reply to encrypted MLs, so
# this filter is intended to revert such behavior.

if header :regex    "Subject" "(.*)(\\*\\*\\*UNCHECKED\\*\\*\\* )(.*)" {
    # delete the orginal subject...
    deleteheader "Subject";
    addheader :last "Subject" "${1}${3}";
}