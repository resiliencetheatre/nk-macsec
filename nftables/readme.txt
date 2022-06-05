# nftables filtering examples

Load ruleset with:

sudo nft flush ruleset; sudo  nft -f nftables.conf; sudo nft list ruleset

Check counters:

sudo nft list table netdev macsec

Reference:

* https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
* https://wiki.gentoo.org/wiki/Nftables#Family_netdev_and_ingress_hook
* https://blog.samuel.domains/blog/security/nftables-hardening-rules-and-good-practices


