require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include", "imap4flags", "copy", "regex" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "USERNAME" ];

# rule:[Grapl Security]
# https://www.graplsecurity.com/subscribe
if envelope :detail "To" "graplnl" {
    fileinto :create "INBOX/Feed/Blog/Good Reads";
    stop;
}

# rule:[SUSE Cybersecurity Champions]
if header :regex "subject" "^Cybersecurity, Privacy and Risk Champions [a-zA-Z]+ newsletter$" {
    redirect :copy "stoyan.manolov@suse.com";
    fileinto :create "INBOX/ML/SUSE/Cybersec Champ";
    stop;
}
