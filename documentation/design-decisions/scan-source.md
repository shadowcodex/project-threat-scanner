# Scanning source

We support 3 sources right now with a plan for 4th in future.

- Github Public Repos
- Local Folder
- Local Git repo

For git we do shallow clones right now, later we may expand that to offer more forensic possibilities. Slowly loosening up our hardened security stance.

Local folders just copy directly into the scanning lab environment.

## Future targets

- github private repos (Gotta figure out safe key management)
- gitlab repos (probably easy to add, just haven't tested)