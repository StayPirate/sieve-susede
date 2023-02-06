require [ "fileinto", "mailbox", "variables", "include", "envelope", "imap4flags", "body" ];
# Global vars
global [ "USERNAME", "NAME" ];
global [ "FLAG_DUPLICATED", "FLAG_MUTED", "FLAG_BETA", "FLAG_DIRECT" ];

#######################
##### G I T L A B #####
#######################
# Tools
# └── Gitlab
#     ├── Checkers
#     ├── Mtk
#     ├── Smash
#     │   ├── Merge request
#     │   │   └── Merged
#     │   └── smash-devel
#     └── Smelt

if envelope :is "From" "gitlab@suse.de" {

    # I enabled on GL to also send me notification for my activity. This helps
    # me to maintain full threads, but at the same time I prefer to automatically
    # set notificaion about my own activity as "read". 
    if header :contains "X-GitLab-NotificationReason" "own_activity" {
        addflag "\\Seen";
    }

    # Add the "direct" imap_flag for notification where I've been mentioned
    if allof (      body :contains [ "${USERNAME}", "${NAME}" ],
                not header :contains "X-GitLab-NotificationReason" "own_activity" ) {
                    addflag "${FLAG_DIRECT}";
    }

    if header :is "X-GitLab-Project" "smash" {
        if exists "X-GitLab-MergeRequest-ID" {
            fileinto :create "INBOX/Tools/Gitlab/Smash/Merge request";
        } else {
            fileinto :create "INBOX/Tools/Gitlab/Smash";
        }
        stop;
    }

    if header :is "X-GitLab-Project" "smelt" {
        if not hasflag :contains "${FLAG_DIRECT}" {
            addflag "\\Seen";
        }
        fileinto :create "INBOX/Tools/Gitlab/Smelt";
        stop;
    }

    if header :is "X-GitLab-Project" "checkers" {
        fileinto :create "INBOX/Tools/Gitlab/Checkers";
        stop;
    }

    if header :is "X-GitLab-Project" "Maintenance ToolKit" {
        fileinto :create "INBOX/Tools/Gitlab/Mtk";
        stop;
    }

    # All the other notifications goes in the main Gitlab folder
    fileinto :create "INBOX/Tools/Gitlab";
    stop;

}