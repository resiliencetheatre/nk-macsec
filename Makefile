TARGETS = nk-macsec

LDFLAGS  += -Lsrc 
LDLIBS   += -lnitrokey -lm -largon2
CFLAGS   += -Wall

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

pcg_basic.o: pcg_basic.c pcg_basic.h
nk-macsec: nk-macsec.o log.o pcg_basic.o
nk-macsec.o: nk-macsec.c log.c 

install:
	cp nk-macsec /usr/bin/
	mkdir -p /opt/nk-macsec
	chown $(USER):$(USER) /opt/nk-macsec
	cp udev/rekey.sh /opt/nk-macsec
	cp udev/90-nk-macsec.rules /etc/udev/rules.d/
	udevadm control --reload-rules
	udevadm trigger
