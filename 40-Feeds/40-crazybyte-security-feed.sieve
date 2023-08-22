require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include", "imap4flags", "body" ];

if header :is "X-RSS-Instance" "crazybyte-security-feed" {

    # rule:[SAMSH MRs to master]
    # https://gitlab.suse.de/tools/smash/-/merge_requests?scope=all&state=merged&target_branch=master
    if header :is "X-RSS-Feed" "https://gitlab.suse.de/tools/smash/-/merge_requests" {

        if header :matches "Subject" "Release *" {
            addflag "SAMSH-Release";
        }

        fileinto :create "INBOX/Tools/Gitlab/Smash/Merge request/Merged";
        stop;
    }

    fileinto :create "INBOX/Trash";

}