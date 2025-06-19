WireGuard for SMF
=================

The example `wg-quick.xml` file may be used for running wg-quick(8)
using SMF.

Usage
-----

Choose a name for your wg-quick config. It can be pretty much any simple string.
It will be used for naming your config file and your SMF service instance name.
The underlying tun device will be allocated dynamically.

Create `/etc/wireguard/<something>.conf`

```
# svccfg import wg-quick.xml
# svccfg -s svc:/vpn/wg-quick add something
# svcadm enable wg-quick:something
```

Helpful references
------------------

- https://blogs.warwick.ac.uk/chrismay/entry/solaris_smf_manifest/
- (archive) https://web.archive.org/web/20210613085120/https://blogs.warwick.ac.uk/chrismay/entry/solaris_smf_manifest/
- https://github.com/omniosorg/omnios-extra/blob/800489a/build/wireguard-tools/files/wg-quick.xml
- https://github.com/TritonDataCenter/pkgsrc-extra/blob/4423c14/wireguard-tools/files/smf/manifest.xml
