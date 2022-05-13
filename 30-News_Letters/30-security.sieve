require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### NEWS LETTER #####
#######################
# Feed
# ├── Blog
# │   └── Good Reads
# └── News Letter
#     └── CyberSaiyan

# rule:[CyberSaiyan]
# https://cybersaiyan.us17.list-manage.com
if allof ( address :contains "From" "@cybersaiyan.it",
           address :contains "To" "${SUSEDE_ADDR}" ) {
    fileinto :create "INBOX/Feed/News Letter/CyberSaiyan";
    stop;
}

# rule:[Grapl Security]
# https://www.graplsecurity.com/subscribe
if envelope :detail "to" "graplnl" {
    fileinto :create "INBOX/Feed/Blog/Good Reads";
    stop;
}