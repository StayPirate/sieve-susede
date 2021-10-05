require [ "fileinto", "mailbox", "envelope", "subaddress" ];

#######################
##### NEWS LETTER #####
#######################
# NL
# ├── CyberSaiyan
# └── Grapl Security

# rule:[CyberSaiyan]
# https://cybersaiyan.us17.list-manage.com
if allof ( envelope :domain :is "From" "cybersaiyan.it",
           address          :is "To" "${susede_addr}" ) {
    fileinto :create "INBOX/NL/CyberSaiyan";
    stop;
}

# rule:[Grapl Security]
# https://www.graplsecurity.com/subscribe
if envelope :detail "to" "graplnl" {
    fileinto :create "INBOX/NL/Grapl Security";
    stop;
}