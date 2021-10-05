require [ "fileinto", "mailbox" ];

#######################
#####   J I R A   #####
#######################
# Tools
# └── Jira

# rule:[catch all]
# Notifications from Jira end up here.
if allof ( address :is "From" "jira@suse.com" ) {
    fileinto :create "INBOX/Tools/Jira";
    stop;
}