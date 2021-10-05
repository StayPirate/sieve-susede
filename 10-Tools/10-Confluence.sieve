require [ "fileinto", "mailbox" ];

########################
#####  CONFLUENCE  #####
########################
# Tools
# └── Confluence

# rule:[catch all]
# Notifications from Confluence end up here.
if allof ( address :is "From" "confluence@suse.com" ) {
    fileinto :create "INBOX/Tools/Confluence";
    stop;
}