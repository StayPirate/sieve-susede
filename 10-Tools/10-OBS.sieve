require [ "fileinto", "mailbox" ];

#######################
#####    O B S    #####
#######################
# Tools
# └── OBS
#     ├── build
#     └── Security Tools

# rule:[mute bots]
# Delete noisy bot comments
if allof ( header :is "x-mailer" "OBS Notification System",
           header :is "x-obs-url" "https://build.opensuse.org",
           anyof ( header :is "x-obs-event-type" "comment_for_request",
                   header :is "x-obs-event-type" "comment_for_project" ),
           anyof ( header :is "x-obs-request-commenter" "sle-qam-openqa",
                   header :is "x-obs-request-commenter" "maintenance-robot",
                   header :is "x-obs-request-commenter" "openqa-maintenance",
                   header :is "x-obs-request-commenter" "abichecker" )) {
    discard;
    stop;
}

# rule:[security tools]
if allof ( header  :is "X-Mailer" "OBS Notification System",
           header  :is "X-OBS-URL" "https://build.opensuse.org",
           address :is "To" "security-team@suse.de" ) {
    fileinto :create "INBOX/Tools/OBS/Security tools";
    stop;
}

# rule:[my build failed]
# A package I maintain failed to build
if allof ( header  :is "X-Mailer" "OBS Notification System",
           header  :is "X-OBS-URL" "https://build.opensuse.org",
           address :contains "To" "${susecom_addr}",
           header  :contains "x-obs-event-type" "build_fail" ) {
    fileinto :create "INBOX/Tools/OBS/build";
    stop;
}

# rule:[catch all]
# Any other notification from OBS goes into the generic OBS folder
if allof ( header :is "X-Mailer" "OBS Notification System",
           header :is "X-OBS-URL" "https://build.opensuse.org" ) {
    fileinto :create "INBOX/Tools/OBS";
    stop;
}