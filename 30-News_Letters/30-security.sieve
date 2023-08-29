require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include", "imap4flags" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "USERNAME" ];

#######################
##### NEWS LETTER #####
#######################
# Feed
# ├── Blog
# │   └── Good Reads
# └── News Letter
#     └── CyberSaiyan

# rule:[Grapl Security]
# https://www.graplsecurity.com/subscribe
if envelope :detail "To" "graplnl" {
    fileinto :create "INBOX/Feed/Blog/Good Reads";
    stop;
}