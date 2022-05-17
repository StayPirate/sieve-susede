require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "USERNAME" ];

#######################
#####   J I R A   #####
#######################
# Tools
# ├── Jira SUSE
# └── Jira SD

# rule:[Jira SUSE]
if allof ( address :is "From" "jira@suse.com",
           header  :is "x-jira-fingerprint" "ba86a44d1de16baf461a884e98837e6f" ) {
    fileinto :create "INBOX/Tools/Jira SUSE";
    stop;
}

# rule:[Jira SD (Service Desk)]
if allof ( address :is "From" "jira-sd@suse.com",
           header  :is "x-jira-fingerprint" "06b32e55c1a08529631bc96cd7f9ccde" ) {
    fileinto :create "INBOX/Tools/Jira SD";
    stop;
}