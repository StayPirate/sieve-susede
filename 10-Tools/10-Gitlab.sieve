require [ "fileinto", "mailbox", "variables", "include", "envelope" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### G I T L A B #####
#######################
# Tools
# └── Gitlab
#     ├── Checkers
#     ├── Mtk
#     ├── Smash
#     └── Smelt

if envelope :is "From" "gitlab@suse.de" {

    if header :is "X-GitLab-Project" "smash" {
        fileinto :create "INBOX/Tools/Gitlab/Smash";
        stop;
    }

    if header :is "X-GitLab-Project" "smelt" {
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