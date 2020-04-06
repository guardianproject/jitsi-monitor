
This project is a script that checks the response times from all known
[Jitsi Meet](https://github.com/jitsi/jitsi-meet) instances.  It
monitors all known public Jitsi Meet instances for ping times and TLS
quality.  When run in GitLab CI, it publishes the results to GitLab
Pages. It can be used standalone to aid choosing which Jitsi Meet
instance works best for you.

# Running Locally

This can be run locally to get results based on the local network.  So
far, this has only been tested on Debian/buster.  It is recommended
that this is either run on a throwaway setup, like in Docker or a VM.
If you have FireJail installed, this will run the JavaScript inside of
a jail.

# Source Lists

* https://github.com/jitsi/jitsi-meet/wiki/Jitsi-Meet-Instances
* https://adn56.net/wiki/index.php?title=La_visio_conf%C3%A9rence#Les_outils
* https://framatalk.org/accueil/en/info/
* https://fediverse.blog/~/DonsBlog/videochat-server
* https://gitlab.com/guardianproject/jitsi-monitor/-/wikis/Jitsi-Meet-Instances
