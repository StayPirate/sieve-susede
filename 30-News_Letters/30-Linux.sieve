require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### NEWS LETTER #####
#######################
# NL
# ├── LWN
# └── Linux Foundation

# rule:[LWN]
# https://lwn.net
if allof ( address :is "From" "lwn@lwn.net",
           address :is "To" "${SUSEDE_ADDR}" ) {
    fileinto :create "INBOX/NL/LWN";
    stop;
}

# rule:[Linux Foundation]
# https://linuxfoundation.org
if allof ( address :is "From" [ "no-reply@linuxfoundation.org",
                                "training@linuxfoundation.org",
                                "marketing@linuxfoundation.org" ],
           address :is "To" "${SUSEDE_ADDR}" ) {
    fileinto :create "INBOX/NL/Linux Foundation";
    stop;
}