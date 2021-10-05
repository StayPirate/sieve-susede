require [ "fileinto", "mailbox" ];

#######################
##### NEWS LETTER #####
#######################
# NL
# └── LWN

# rule:[LWN]
# https://lwn.net
if allof ( address :is "From" "lwn@lwn.net",
           address :is "To" "${susede_addr}" ) {
    fileinto :create "INBOX/NL/LWN";
    stop;
}