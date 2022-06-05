# out-of-band macsec keying with nitrokey

Small example how to key macsec with Nitrokey Storage or Pro2 model.

Instructions

Setting keys to Nitrokey

  `nk-macsec -p [user_pin] -s -i [interface] -f [peer-mac-address-file]`

Getting keys to host

  `nk-macsec -p [user_pin] -g -i [interface]`

You can generate shell script to bring up your macsec environment:

  `nk-macsec -p [user_pin] -g -i [interface] > macsec.sh`


# Automation

Included udev rule will run nk-macsec and macsec.sh to re-key and 
setup macsec environment when Nitrokey is attached to USB port.


# Installation

Install nitrokey & argon2 library and compile with:

```
$ make
$ sudo make install
```

Edit /opt/nk-macsec/rekey.sh and change pin-code, network interface
and uncomment macsec.sh line when macsec.sh file is generated succesfully
on Nitrokey insert. 

Current udev values (/etc/udev/rules.d/90-nk-macsec.rules) are for 
Nitrokey STORAGE. Change them if you plan to use PRO2 model. 

## Fedora 

 * hidapi-devel

## libnitrokey

 * libnitrokey-dev
 * https://github.com/Nitrokey/libnitrokey

```
git clone --recursive https://github.com/Nitrokey/libnitrokey.git
# assuming current dir is ./libnitrokey/
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. 
make -j2
sudo make install
```

## argon2

 * libghc-argon2-dev
 * https://github.com/P-H-C/phc-winner-argon2
 

## pcg-random

 * https://github.com/imneme/pcg-c-basic
 * http://www.pcg-random.org/
