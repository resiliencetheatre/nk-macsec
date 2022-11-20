/*
 * Out-of-band macsec keying with Nitrokey
 *
 * Copyright (c) 2022 Resilience Theatre <info@resilience-theatre.com>
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 * 
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
 * Based on libnitrokey examples, argon2 KDF and PCG based RNG
 * 
 * * https://github.com/Nitrokey/libnitrokey/blob/master/NK_C_API.h
 * * https://www.pcg-random.org
 * * https://github.com/P-H-C/phc-winner-argon2
 * * https://github.com/imneme/pcg-c-basic
 * 
 * 
 */
 
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnitrokey/NK_C_API.h>
#include <argon2.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <netinet/in.h>
#include "pcg_basic.h"
#include "log.h"

#define HASHLEN 		16		/* 32, 16 (macsec key len) */
#define SALTLEN 		16
#define SLOT_COUNT 		16
#define GET_MODE 		0 
#define SET_MODE 		1
#define PEER_COUNT		16
#define MAC_LEN			20
#define NO_MAC_FOUND	0
#define MAC_FOUND		1
#define KDF_LEN			32
#define IFACE_NAME_LEN 	20
#define USER_PIN_LEN	10

/* Peer mac addresses (from file) */
char	mac_addr[PEER_COUNT][MAC_LEN];	
uint8_t validmacfound=NO_MAC_FOUND;

/* Peer mac addresses and KDF (from nitrokey) */
char	mac_addr_from_nitrokey[PEER_COUNT][MAC_LEN+1];	
char	kdf_key_from_nitrokey[PEER_COUNT][KDF_LEN+1];	

/* Index of my own mac address & key in nitrokey slots */
uint8_t	myid=99;
char	myinterface_name[IFACE_NAME_LEN];
char	masquerade_interface_name[IFACE_NAME_LEN];

/* Random */
pcg32_random_t rng;

void generate_shell_script(int setroute, int usesudo)
{	 
	log_info("[%d] Generating shell script", getpid() );
	for (int loop=0;loop<PEER_COUNT;loop++) {
	 if ( loop == myid ) {
		log_debug("[%d] %s - %s (my key) %s ", getpid(),mac_addr_from_nitrokey[loop],kdf_key_from_nitrokey[loop],myinterface_name );	 
	 } else {
		log_debug("[%d] %s - %s ", getpid(),mac_addr_from_nitrokey[loop],kdf_key_from_nitrokey[loop] );
	}	
	}
	
	if ( usesudo == 1 ) {
		printf(" #!/bin/sh\n"); // bash -> sh
		printf(" # Delete existing macsec0 interface and bind new one \n");
		printf(" sudo ip link set %s up \n",myinterface_name);
		printf(" sudo ip link delete macsec0 \n");
		printf(" sudo ip link add link %s macsec0 type macsec encrypt on \n",myinterface_name);
		printf(" # Set my TX key \n");
		printf(" sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 %s \n",kdf_key_from_nitrokey[myid] );
		printf(" # \n");
		printf(" # Set peer RX keys \n");
		printf(" # \n");
		for (int peerloop=0;peerloop<PEER_COUNT;peerloop++) {
		if ( peerloop != myid ) {
			printf(" # Peer: %d \n",peerloop);
			printf(" sudo ip macsec add macsec0 rx port 1 address %s \n", mac_addr_from_nitrokey[peerloop] );
			printf(" sudo ip macsec add macsec0 rx port 1 address %s sa 0 pn 1 on key 00 %s \n",mac_addr_from_nitrokey[peerloop],kdf_key_from_nitrokey[peerloop]);	 
		}
		}
		printf(" # Bring macsec up \n");
		printf(" sudo ip link set macsec0 up \n");
		printf(" sudo ip addr add 10.100.0.%d/24 dev macsec0 \n", myid + 1); 
		if (setroute) {
			printf(" sudo ip route add default via 10.100.0.1 \n");
			printf(" # sudo echo \"nameserver 1.1.1.1\" > /etc/resolv.conf \n");
		}
		printf(" exit 0\n");
		printf(" \n");
	} else {
		printf(" #!/bin/sh\n"); // bash -> sh
		printf(" # Delete existing macsec0 interface and bind new one \n");
		printf(" ip link set %s up \n",myinterface_name);
		printf(" ip link delete macsec0 \n");
		printf(" ip link add link %s macsec0 type macsec encrypt on \n",myinterface_name);
		printf(" # Set my TX key \n");
		printf(" ip macsec add macsec0 tx sa 0 pn 1 on key 01 %s \n",kdf_key_from_nitrokey[myid] );
		printf(" # \n");
		printf(" # Set peer RX keys \n");
		printf(" # \n");
		for (int peerloop=0;peerloop<PEER_COUNT;peerloop++) {
		if ( peerloop != myid ) {
			printf(" # Peer: %d \n",peerloop);
			printf(" ip macsec add macsec0 rx port 1 address %s \n", mac_addr_from_nitrokey[peerloop] );
			printf(" ip macsec add macsec0 rx port 1 address %s sa 0 pn 1 on key 00 %s \n",mac_addr_from_nitrokey[peerloop],kdf_key_from_nitrokey[peerloop]);	 
		}
		}
		printf(" # Bring macsec up \n");
		printf(" ip link set macsec0 up \n");
		printf(" ip addr add 10.100.0.%d/24 dev macsec0 \n", myid + 1); 
		if (setroute) {
			printf(" ip route add default via 10.100.0.1 \n");
			printf(" # echo \"nameserver 1.1.1.1\" > /etc/resolv.conf \n");
		} else {
			printf(" # RPi role includes masquerade between macsec0 and %s\n",masquerade_interface_name);
			printf(" echo 1 > /proc/sys/net/ipv4/ip_forward \n");
			printf(" nft add table nat \n");
			printf(" nft 'add chain nat postrouting { type nat hook postrouting priority 100 ; }' \n");
			printf(" nft add rule nat postrouting ip saddr 10.100.0.0/24 oif %s masquerade \n",masquerade_interface_name);
		}
		printf(" exit 0\n");
		printf(" \n");
	}
}

/* Read peer mac addresses from file */
uint8_t read_mac_addresses(char *filename)
{
	FILE *fp;
	char line[512];
	int cur_line = 0;
	if ((fp = fopen(filename,"r")) == NULL){
	   log_error("[%d] File open error: %s ", getpid(),filename );
	   return 1;
	}
	char linestring[20];
	while(fgets(line, 512, fp) != NULL) {     
		sscanf (line, "%s",linestring);	
		strcpy(mac_addr[cur_line],linestring);
		cur_line++;
	}
	fclose(fp);
	log_info("[%d] read mac address from file: %s ", getpid(),filename );
	return 0;
}

/* Get interface mac address */
void get_macaddress(char *interface, char *macaddress)
{
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, interface);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {	
		sprintf(macaddress,"%02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned char) s.ifr_addr.sa_data[0],
		(unsigned char) s.ifr_addr.sa_data[1],
		(unsigned char) s.ifr_addr.sa_data[2],
		(unsigned char) s.ifr_addr.sa_data[3],
		(unsigned char) s.ifr_addr.sa_data[4],
		(unsigned char) s.ifr_addr.sa_data[5]);
		validmacfound = MAC_FOUND;
	} else {
		validmacfound = NO_MAC_FOUND;
	}
}

/* pcg32 branch with simplified pcg32 */
void gen_password(char *password)
{
	uint32_t number_one = pcg32_random_r(&rng);
	uint32_t number_two = pcg32_random_r(&rng);
	sprintf(password,"%X%X",number_one,number_two);
	log_debug("[%d] get_password() %s ", getpid(),password );
}

int main(int argc, char *argv[])
{
	/* argon2 kdf parameters */
	uint8_t hash1[HASHLEN];
    uint8_t salt[SALTLEN];
	uint32_t t_cost = 2;            // 2-pass computation
	uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
	uint32_t parallelism = 1;       // number of threads and lanes
    uint32_t pwdlen;
    uint8_t *pwd=NULL;
	uint8_t* slots;
	uint8_t role = GET_MODE;
	uint8_t peer_mac_address_status=99;
	char *slotname=NULL;
	char *slotlogin=NULL;
	char *slotpassword=NULL;
	char *userpin_input=NULL;	
	char userpin[USER_PIN_LEN];
	char macaddress[MAC_LEN];
	char *interface_name=NULL;
	char *masquerade_interface=NULL;
	uint8_t setroute=0;
	uint8_t usesudo=0;
	uint8_t logging=0;
    uint8_t mymacfound=0;
    
    // This seeding as an example only, check this
    pcg32_srandom_r(&rng, time(NULL) ^ (intptr_t)&printf,(intptr_t)&printf^time(NULL));
    
	/* Set logging level (for display) */
	log_set_level(LOG_INFO);
	
	/* Log to file */
	FILE *logfile=NULL;
	
	/* Init peer mac addresses */	
	for (int init_loop=0; init_loop < PEER_COUNT; init_loop++)
	{
		memset(mac_addr[init_loop],0,MAC_LEN);
	}
	memset(macaddress,0,MAC_LEN);
	memset(myinterface_name,0,IFACE_NAME_LEN);
	memset(salt, 0x00, SALTLEN );
	memset(userpin,0,USER_PIN_LEN);
	/* Default masquerade interface */
	memset(masquerade_interface_name,0,IFACE_NAME_LEN);
	strcpy(masquerade_interface_name,"eth0"); 
	/* Command line options */
	int c;
	while ((c = getopt (argc, argv, "p:i:m:sghf:rol")) != -1)
	switch (c)
	{
		case 'p':
			userpin_input = optarg;
			sprintf(userpin,"%s",userpin_input);
			break;
		case 'i':
			interface_name = optarg;
			strcpy(myinterface_name,interface_name);
			get_macaddress(optarg,macaddress);
			log_info("[%d] interface: %s has mac address: %s ", getpid(),optarg,macaddress );
			break;
		case 'm':
			masquerade_interface = optarg;
			memset(masquerade_interface_name,0,IFACE_NAME_LEN);
			strcpy(masquerade_interface_name,masquerade_interface); 
			log_info("[%d] masquerade interface: %s for script", getpid(),masquerade_interface );
			break;
		case 'f':
			peer_mac_address_status = read_mac_addresses(optarg); 
			break;
		case 's':
			role = SET_MODE;
			break;
		case 'g':
			role = GET_MODE;
			break;	
		case 'r':
			setroute = 1;
			break;
		case 'o':
			usesudo = 1;
			break;
		case 'l':
			logging = 1;
			break;
		case 'h':
			log_info("[%d] nk-macsec - out-of-band macsec keying with Nitrokey PRO2 and Storage", getpid() );
			log_info("[%d] ", getpid() );
			log_info("[%d] Usage:", getpid() );
			log_info("[%d] ", getpid() );
			log_info("[%d] nk-macsec <parameter>", getpid() );
			log_info("[%d]           -p [user_pin]      user pin of Nitrokey", getpid() );
			log_info("[%d]           -g                 get keys from Nitrokey", getpid() );
			log_info("[%d]           -s                 set keys to Nitrokey", getpid() );
			log_info("[%d]           -i [interface]     used network interface", getpid() );
			log_info("[%d]           -f [filename]      macsec address file", getpid() );
			log_info("[%d]           -m [interface]     masquerade interface for macsec script (defaults to eth0)", getpid() );
			log_info("[%d]           -r                 output 'ip route' to shell script (use with clients)", getpid() );
			log_info("[%d]           -o                 generate shell script with 'sudo' prefix (client prefered option)", getpid() );
			log_info("[%d]           -l                 debug logging to /tmp/nk-macsec.log (exposes keys in clear text)", getpid() );
			log_info("[%d]  ", getpid() );
			log_info("[%d] Key client with: ", getpid() );
			log_info("[%d] nk-macsec -p [user_pin] -g -i [interface] -r -o > macsec.sh ", getpid() );
			log_info("[%d]  ", getpid() );
			log_info("[%d] Generate keys to Nitrokey:", getpid() );
			log_info("[%d] nk-macsec -p [user_pin] -s -i [interface] -f [peer-mac-address-file] ", getpid() );
			log_info("[%d] ", getpid() );
			log_info("[%d] * [filename] should have 16 mac addresses each on own line.", getpid() );
			log_info("[%d] * Make sure you enter valid USER PIN or you need 'nitrokey-app' to reset it", getpid() );
			log_info("[%d]   after three failed attempts. This program cannot reset USER PIN for you.", getpid() );
			log_info("[%d] * NOTE: -s (set) option overwrites your password slots on Nitrokey without asking! ", getpid() );
			if ( logging )
				fclose (logfile);
			return 1;
			break;
		default:
			break;
	}
	
	/* File logging for TRACE level */
	if ( logging ) {
		if ((logfile = fopen("/tmp/nk-macsec.log","w")) == NULL) {
		log_error("[%d] Cannot open /tmp/nk-macsec.log for writing.", getpid() );
		} else {
			log_add_fp(logfile,LOG_TRACE);
			log_info("[%d] Logging to /tmp/nk-macsec.log [security notice]", getpid() );
		}
	} 
	
	/* Combination evaluation */
	if ( role == GET_MODE && validmacfound == NO_MAC_FOUND ) {
		log_error("[%d] Unable to get mac adress of interface. Check -i [interface]. Exiting.", getpid() );
		if ( logging )
				fclose (logfile);
		return 1;
	}
	if ( role == SET_MODE && validmacfound == NO_MAC_FOUND ) {
		log_error("[%d] Unable to get mac adress of interface. Check -i [interface]. Exiting.", getpid() );
		if ( logging )
				fclose (logfile);
		return 1;
	}
	if ( role == SET_MODE && peer_mac_address_status != 0 ) {
		log_error("[%d] Could not read peer mac addresses from file.", getpid() );
		log_error("[%d] Did you forgot to give -f [peer-mac-address-file] as command line option?", getpid() );
		if ( logging )
				fclose (logfile);
		return 1;
	}
	/* Check my mac is in list */
	if ( role == SET_MODE ) {
	
		for (int t=0;t<PEER_COUNT;t++) {		
			if ( strcmp(macaddress, mac_addr[t]) == 0 )
			{
				log_info("[%d] MAC address [%d] %s (interface %s mac address)", getpid(),t,mac_addr[t],interface_name );
				mymacfound = 1;
			} else {
				log_info("[%d] MAC address [%d] %s ", getpid(),t,mac_addr[t] );
			}
		}
		if (!mymacfound) {
				log_error("[%d] Could not find mac address (%s) on provided mac address list. Exiting. ", getpid(),macaddress );
		}
	}
	/* GET Keys from Nitrokey */
	if ( role == GET_MODE )
	{
		uint8_t myslot=99;
		if (NK_login_auto() != 1) {
				log_error("[%d] No Nitrokey found. ", getpid() );
				return 1;
		}
		enum NK_device_model model = NK_get_device_model();
		switch (model) {
		case NK_PRO:
				log_info("[%d] a Nitrokey Pro", getpid() );
				break;
		case NK_STORAGE:
				log_info("[%d] a Nitrokey Storage", getpid() );
				// Feature request: if we have Nitrokey Storage - open encrypted partition and use mac.txt from there?
				break;
		case NK_LIBREM:
				log_info("[%d] a Librem Key", getpid() );
				break;
		default:
				log_error("[%d] an unsupported Nitrokey ", getpid() );
				break;
		}
		char* serial_number = NK_device_serial_number();
		if (serial_number) {
			log_info("[%d] with serial number %s", getpid(),serial_number );
		}
		else 
		{
			log_error("[%d] -- could not query serial number!", getpid() );
			return 1;
		}
		free(serial_number);
		log_info("[%d] Get Nitrokey slots", getpid());
		if ( NK_user_authenticate(userpin, "temppw") == 0 ) 
		{
			log_info("[%d] Nitrokey authentication successful.", getpid() );
		} else {
			log_error("[%d] Nitrokey authentication error pin: ", getpid(),userpin );
			return 1;
		}
		if ( NK_enable_password_safe(userpin) == 0 )
		{
			slots = NK_get_password_safe_slot_status(); 
			for (uint8_t slot = 0; slot < SLOT_COUNT; ++slot) 
			{
				if (slots[slot] == 1)
				{
					slotname=NK_get_password_safe_slot_name(slot);
					slotlogin=NK_get_password_safe_slot_login(slot);
					slotpassword=NK_get_password_safe_slot_password(slot);
					log_debug("[%d] [%d] Slotname: %s", getpid(),slot,slotname );			
					if ( strcmp(macaddress, slotlogin) == 0 ) {
						log_debug("[%d] [%d] Slot login: %s (my slot)", getpid(),slot,slotlogin );
						myslot = slot;
					} else {
						log_debug("[%d] [%d] Slot login: %s ", getpid(),slot,slotlogin );	
					}
					strcpy( mac_addr_from_nitrokey[slot],slotlogin);
					log_info("[%d] [%d] Slot password: %s", getpid(),slot,slotpassword );
					char kdf_string[1 + HASHLEN*2];
					char kdf_value[3];
					memset(kdf_string,0, 1 + HASHLEN*2);
					memset(kdf_value,0,3);
					pwd = (uint8_t *)strdup(slotpassword);
					pwdlen = strlen((char *)slotpassword);
					argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);
					for( int i=0; i<HASHLEN; ++i ) {
						sprintf(kdf_value,"%02x",hash1[i]);
						strcat(kdf_string,kdf_value);
					}
					if ( myslot == slot ) {
						log_debug("[%d] [%d] KDF: %s (my key)", getpid(),slot,kdf_string );
						myid = slot;
					} else {
						log_debug("[%d] [%d] KDF: %s", getpid(),slot,kdf_string );
					}
					strcpy( kdf_key_from_nitrokey[slot],kdf_string);
				} 
				else 
				{
					log_trace("[%d] [%d] Slot empty", getpid(),slot ); 
				}
			}
			NK_free_password_safe_slot_status(slots);
		}
		NK_logout();
		generate_shell_script(setroute,usesudo);
		if ( logging )
				fclose (logfile);
		return 0;
	}
	
	/* Set new keys to Nitrokey */
	if ( role == SET_MODE ) 
	{
		log_info("[%d] Set keying slots ", getpid());
		
		if (NK_login_auto() != 1) {
				log_error("[%d] No Nitrokey found. ", getpid() );
				if ( logging )
					fclose (logfile);
				return 1;
		}
		
		enum NK_device_model model = NK_get_device_model();
		switch (model) {
		case NK_PRO:
				log_trace("[%d] a Nitrokey Pro", getpid() );
				break;
		case NK_STORAGE:
				log_trace("[%d] a Nitrokey Storage", getpid() );
				break;
		case NK_LIBREM:
				log_trace("[%d] a Librem Key", getpid() );
				break;
		default:
				log_error("[%d] an unsupported Nitrokey ", getpid() );
				break;
		}
		
		char* serial_number = NK_device_serial_number();
		if (serial_number) {
			log_trace("[%d] with serial number %s", getpid(),serial_number );
		}
		else 
		{
			log_error("[%d] -- could not query serial number!", getpid() );
			if ( logging )
					fclose (logfile);
			return 1;
		}
		free(serial_number);
		
		log_debug("[%d] Trying to authenticate with PIN: %s", getpid(),userpin );
		
		if ( NK_user_authenticate(userpin, "temppw") == 0 ) 
		{
			log_trace("[%d] Nitrokey authentication successful.", getpid() );
		} else {
			log_error("[%d] Nitrokey authentication error pin: ", getpid(),userpin );
			if ( logging )
					fclose (logfile);
			return 1;
		}
		/* This was missing ! */
		if ( NK_enable_password_safe(userpin) == 0 )
		{
			slots = NK_get_password_safe_slot_status();
				/* Write slots */
				log_trace("[%d] Peer count: %d ", getpid(),PEER_COUNT );
				for (int set_slot_counter=0;set_slot_counter<PEER_COUNT;set_slot_counter++)
				{
					char slotname[10];
					char macaddress[MAC_LEN];
					char password[20];
					memset(slotname,0,10);
					memset(macaddress,0,MAC_LEN);
					memset(password,0,MAC_LEN);
					gen_password(password);
					sprintf(slotname,"%d",set_slot_counter); // should we have timestamp included here?
					sprintf(macaddress,"%s",mac_addr[set_slot_counter]);
					int writeret = NK_write_password_safe_slot(set_slot_counter, slotname,macaddress, password);
					if (writeret == 0 ) {
						log_info("[%d] Stored key: %d for mac: %s", getpid(),set_slot_counter,mac_addr[set_slot_counter] ); 
					} else {
						log_info("[%d] Storing key results an error: %d ", getpid(), writeret ); 
					}
					
				}
			NK_free_password_safe_slot_status(slots);	
		}
	NK_logout();			
	}
	
	if ( logging )
		fclose (logfile);
	return 0;
}
