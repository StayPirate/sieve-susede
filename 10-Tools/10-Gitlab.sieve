require [ "fileinto", "mailbox" ];

#######################
##### G I T L A B #####
#######################
# Tools
# └── Gitlab

# rule:[catch all]
# Notifications from Gitlab end up here.
if allof ( address :is "From" "gitlab@suse.de" ) {
    fileinto :create "INBOX/Tools/Gitlab";
    stop;
}