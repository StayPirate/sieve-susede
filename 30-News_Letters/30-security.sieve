require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### NEWS LETTER #####
#######################
# NL
# ├── CyberSaiyan
# └── Grapl Security

# rule:[CyberSaiyan]
# https://cybersaiyan.us17.list-manage.com
if allof ( envelope :domain :is "From" "cybersaiyan.it",
           address          :is "To" "${SUSEDE_ADDR}" ) {
    fileinto :create "INBOX/NL/CyberSaiyan";
    stop;
}

# rule:[Grapl Security]
# https://www.graplsecurity.com/subscribe
if envelope :detail "to" "graplnl" {
    fileinto :create "INBOX/NL/Grapl Security";
    stop;
}