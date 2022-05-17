require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "USERNAME" ];

#######################
##### NEWS LETTER #####
#######################
# Feed
# ├── Weekly update
# │   └── LWN
# └── News Letter
#     └── Linux Foundation

# rule:[LWN]
# https://lwn.net
if allof ( address :is "From" "lwn@lwn.net",
           address :is "To" "${SUSEDE_ADDR}" ) {
    fileinto :create "INBOX/Feed/Weekly update/LWN";
    stop;
}

# rule:[Linux Foundation]
# https://linuxfoundation.org
if allof ( address :domain "From" "linuxfoundation.org",
           address :is     "To"   "${SUSEDE_ADDR}" ) {
    fileinto :create "INBOX/Feed/News Letter/Linux Foundation";
    stop;
}