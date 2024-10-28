require [ "fileinto", "mailbox", "variables", "include", "envelope", "imap4flags", "body" ];
# Global vars
global [ "USERNAME", "NAME" ];
global [ "FLAG_DUPLICATED", "FLAG_MUTED", "FLAG_BETA", "FLAG_DIRECT" ];

if header :is "X-Mailer" "Gitea" {

    # [...]

    # All the other notification goes in the main Gitea main folder
    fileinto :create "INBOX/Tools/Gitea";
    stop;
}