# Personal sieve scripts collection

This repository is intended to store and organize my personal sieve scripts. Since their complexity grows every day I decided to organize them in a better way: split them into multiple files while versioning via git. Using the below-described [git-hook](#The-git-way), at each git commit the scripts are automatically uploaded to the mail-server.

## Requirement
You need `sieveshell` installed. Good news for [secbox](https://github.com/StayPirate/secbox) users, in case you are running `secbox >= 1.10` and `secbox-image >= 2.7`, then you already have `sieveshell` available. You can double-check with the following commands:
```bash
> secbox -v
script     :  secbox                                                       v.1.9
image      :  non_public/maintenance/security/container/containers/secbox  v.2.7
container  :  secbox                                                       running
> which sieveshell
sieveshell: aliased to secbox --no-tty sieveshell
```

## How to use

1. ### **The manual way**

    I store my credentials (application password) in the local wallet, which I can access via D-Bus using the secret-service protocol. The following functions are intended to collect username and password for the secret service provider (keepassxc for me).

    ```bash
    unlock_wallet() {
        echo "check the explanation attribute ;)" | secret-tool store --label="dummy-entry" explanation \
        "Because of quirks in the gnome libsecret API, a dummy entry needs to be stored in order to \
        guarantee that this keyring was properly unlocked. More details at http://crbug.com/660005 and \
        https://github.com/keepassxreboot/keepassxc/issues/4443"
    }

    get_user() {
        unlock_wallet
        secret-tool search client sieveshell workstation wintermute 2>&1 | \
        grep -E "^attribute\.UserName" | \
        cut -d " " -f3
    }

    get_pass() {
        unlock_wallet
        secret-tool search client sieveshell workstation wintermute 2>&1 | \
        grep -E "^secret" | \
        cut -d " " -f3
    }
    ```

    From inside the repo work-tree, I run the following command to upload the *.sieve scripts to the mail-server. This can be hooked into the git client in a way that it automatically updates the sieve scripts at every new commit (see below).

    ```bash
    find $(git rev-parse --show-toplevel) -type f -name "*.sieve" -printf "put %p %f\n" | sort -nr | \
    sieveshell --user $(get_user) \
            --passwd $(get_pass) \
            --use-tls \
            --port 4190 \
            imap-int.suse.de
    ```

2. ### **The git way**

    The [hook](.githooks/pre-commit) is already provided within this repository, I strongly suggest you leverage [conditional includes](https://git-scm.com/docs/git-config#_conditional_includes) (cool beans) in your gitconfig. This will be as easy as appending the following lines to your `~/.gitconfig` (e.g. [mine](https://github.com/StayPirate/dotfiles/blob/ebb1fdd4eba76b7a5bae77d512ec3ba7f0d16549/.gitconfig#L29-L31)):

    ```
    ; Only include if the repository is sieve-susede
    [includeIf "gitdir:~/Workspace/sieve-susede/.git"]
            path = ~/Workspace/sieve-susede/.githooks/sieveshell.gitconfig
    ```
    <sup>\* Do not forget to adjust the paths in the above snippet.</sup> 
    
    You can now jump into your local repository copy, make your changes and commit.

---
After the first run, ensure that `00-Init.sieve` is activated. Or you can activate it after your first upload running:

```bash
echo "activate 00-Init.sieve \n list" | \
sieveshell --user $(get_user) \
        --passwd $(get_pass) \
        --use-tls \
        --port 4190 imap-int.suse.de
```
And check for: `00-Init.sieve   <<-- active`.