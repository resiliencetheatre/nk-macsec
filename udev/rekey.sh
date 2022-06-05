#!/bin/sh
/usr/bin/nk-macsec -p 123456 -g -i enp5s0 -o -r > /opt/nk-macsec/macsec.sh
chmod +x /opt/nk-macsec/macsec.sh
# /opt/nk-macsec/macsec.sh
# Optional, remove macsec.sh:
# rm /opt/nk-macsec/macsec.sh
exit 0

