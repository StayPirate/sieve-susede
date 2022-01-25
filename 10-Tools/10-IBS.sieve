require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
#####    I B S    #####
#######################
# Tools
# └── IBS
#     ├── build
#     └── requests
#         ├── pushed back
#         └── to review

# rule:[mute bots]
# Delete noisy bot comments
if allof ( header :is "X-Mailer" "OBS Notification System",
           header :is "X-OBS-URL" "https://build.suse.de",
           anyof ( header :is "x-obs-event-type" "comment_for_request",
                   header :is "x-obs-event-type" "comment_for_project" ),
           anyof ( header :is "x-obs-request-commenter" "sle-qam-openqa",
                   header :is "x-obs-request-commenter" "maintenance-robot",
                   header :is "x-obs-request-commenter" "openqa-maintenance",
                   header :is "x-obs-request-commenter" "abichecker",
                   header :is "x-obs-request-commenter" "cloud_bot" )) {
    discard;
    stop;
}

# rule:[ignore maintenance-team review requested]
# IBS ignore reviews for the maintenance-team
if allof ( header :is "X-Mailer" "OBS Notification System",
           header :is "X-OBS-URL" "https://build.suse.de",
           header :is "x-obs-event-type" "review_wanted",
           header :is "x-obs-review-by-group" "maintenance-team" ) {
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[security-team review requested]
# A review is pending for the security-team
if allof ( header :is "X-Mailer" "OBS Notification System",
           header :is "X-OBS-URL" "https://build.suse.de",
           header :is "x-obs-event-type" "review_wanted",
           header :is "x-obs-review-by-group" "security-team" ) {
    fileinto :create "INBOX/Tools/IBS/requests/to review";
    stop;
}

# rule:[my request declined]
# A request issued by me is not accepted
if allof (     header :is "X-Mailer" "OBS Notification System",
               header :is "X-OBS-URL" "https://build.suse.de",
               header :is "x-obs-request-creator" "${BZ_USERNAME}",
               header :is "x-obs-event-type" "request_statechange",
           not header :is "x-obs-request-state" "accepted" ) {
    fileinto :create "INBOX/Tools/IBS/requests/pushed back";
    stop;
}

# rule:[my build failed]
# A package I maintain failed to build
if allof ( header  :is "X-Mailer" "OBS Notification System",
           header  :is "X-OBS-URL" "https://build.suse.de",
           address :contains "To" "${SUSECOM_ADDR}",
           header  :contains "x-obs-event-type" "build_fail" ) {
    fileinto :create "INBOX/Tools/IBS/build";
    stop;
}

# rule:[my request]
# Notification for requests I issued
if allof ( header :is "X-Mailer" "OBS Notification System",
           header :is "X-OBS-URL" "https://build.suse.de",
           header :is "x-obs-request-creator" "${BZ_USERNAME}" ) {
    fileinto :create "INBOX/Tools/IBS/requests";
    stop;
}

# rule:[catch all]
# Any other notification from IBS goes into the generic IBS folder
if allof ( header :is "X-Mailer" "OBS Notification System",
           header :is "X-OBS-URL" "https://build.suse.de" ) {
    fileinto :create "INBOX/Tools/IBS";
    stop;
}