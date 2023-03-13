require [ "fileinto", "mailbox", "variables", "include", "imap4flags" ];

# Global vars
global [ "SUSECOM_ADDR", "USERNAME" ];
global [ "FLAG_DUPLICATED", "FLAG_MUTED", "FLAG_DIRECT" ];

# Local vars
set "FLAG_OBS_RQ_ACCEPTED"      "rq_accepted";
set "FLAG_OBS_RQ_NOT_ACCEPTED"  "rq_pushed-back";
set "FLAG_OBS_RQ_REVIEW_NEEDED" "rq_need-review";

#######################
#####    I B S    #####
#######################
# Tools
# └── IBS
#     ├── build
#     └── requests

if allof (  header :is "X-Mailer" "OBS Notification System",
            header :is "X-OBS-URL" "https://build.suse.de" ) {

    # rule:[mute bots]
    # Delete noisy bot comments
    if allof (  anyof ( header :is "x-obs-event-type" "comment_for_request",
                        header :is "x-obs-event-type" "comment_for_project" ),
                anyof ( header :is "x-obs-request-commenter" "sle-qam-openqa",
                        header :is "x-obs-request-commenter" "maintenance-robot",
                        header :is "x-obs-request-commenter" "openqa-maintenance",
                        header :is "x-obs-request-commenter" "abichecker",
                        header :is "x-obs-request-commenter" "cloud_bot" )) {
                            discard;
                            stop;
    }

    # rule:[ignore maintenance review requested]
    # IBS ignore reviews for the maintenance-team and maintenance-release-approver
    if allof (  header :is "x-obs-event-type" "review_wanted",
                anyof ( header :is "x-obs-review-by-group" "maintenance-team",
                        header :is "x-obs-review-by-group" "maintenance-release-approver" )) {
                    discard;
                    stop;
    }

    # rule:[security-team review requested]
    # A review is pending for the security-team
    if allof (  header :is "x-obs-event-type" "review_wanted",
                header :is "x-obs-review-by-group" "security-team" ) {
                    addflag "${FLAG_OBS_RQ_REVIEW_NEEDED}";
    }

    # rule:[request declined]
    if header :is "x-obs-event-type" "request_statechange" {
        if header :is "x-obs-request-state" "accepted" {
            discard;
            stop;
        } else {
            addflag "${FLAG_OBS_RQ_NOT_ACCEPTED}";
            addflag "\\Seen";
        }
    }

    # rule:[my request]
    # Notification for requests I issued
    if header :is "x-obs-request-creator" "${USERNAME}" {
        addflag "${FLAG_DIRECT}";
    }

    # rule:[my build failed]
    # A package I maintain failed to build
    if allof (  address :contains "To" "${SUSECOM_ADDR}",
                header  :contains "x-obs-event-type" "build_fail" ) {
                    fileinto :create "INBOX/Tools/IBS/build";
                    stop;
    }

    # Catch all, any other notification from IBS goes into the generic IBS folder
    if not hasflag :contains [ "$FLAG_OBS_RQ_REVIEW_NEEDED", "FLAG_DIRECT" ] {
        addflag "\\Seen";
    }
    fileinto :create "INBOX/Tools/IBS/requests";
    stop;

}