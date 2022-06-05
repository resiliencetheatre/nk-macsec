# Create working directory

sudo cp nk-macsec /usr/bin/
sudo mkdir /opt/nk-macsec
sudo chown $USER:$USER /opt/nk-macsec

# Copy rules in place and reload udev

sudo cp 90-nk-macsec.rules /etc/udev/rules.d/90-nk-macsec.rules
sudo udevadm control --reload-rules && sudo udevadm trigger

# nitrokey udev rules manual install

wget https://raw.githubusercontent.com/Nitrokey/libnitrokey/master/data/41-nitrokey.rules
sudo mv 41-nitrokey.rules /etc/udev/rules.d/
