#!/bin/bash

#set -e
set -x

appSetup () {

	# Set variables
	DOMAIN=${DOMAIN:-SAMDOM.LOCAL}
	DOMAINPASS=${DOMAINPASS:-youshouldsetapassword}
	JOIN=${JOIN:-false}
	JOINSITE=${JOINSITE:-NONE}
	MULTISITE=${MULTISITE:-false}
	NOCOMPLEXITY=${NOCOMPLEXITY:-false}
	INSECURELDAP=${INSECURELDAP:-false}
	DNSFORWARDER=${DNSFORWARDER:-NONE}
	HOSTIP=${HOSTIP:-NONE}
	TLS=${TLS:-false}
	LOGS=${LOGS:-false}
	ADLoginOnUnix=${ADLoginOnUnix:-false}
	
	LDOMAIN=${DOMAIN,,} #alllowercase
	UDOMAIN=${DOMAIN^^} #ALLUPPERCASE
	URDOMAIN=${UDOMAIN%%.*} #trim

	# If multi-site, we need to connect to the VPN before joining the domain
	if [[ ${MULTISITE,,} == "true" ]]; then
		/usr/sbin/openvpn --config /docker.ovpn &
		VPNPID=$!
		echo "Sleeping 30s to ensure VPN connects ($VPNPID)";
		sleep 30
	fi

        # Set host ip option
        if [[ "$HOSTIP" != "NONE" ]]; then
		HOSTIP_OPTION="--host-ip=$HOSTIP"
        else
		HOSTIP_OPTION=""
        fi

	# Set up samba
	mv /etc/krb5.conf /etc/krb5.conf.orig
	{
	echo "[libdefaults]" > /etc/krb5.conf
	echo "    dns_lookup_realm = false"
	echo "    dns_lookup_kdc = true"
	echo "    default_realm = ${UDOMAIN}"
	} >> /etc/krb5.conf
	if [[ ${LOGS,,} == "true" ]]; then
	{
	echo "[logging]"  >> /etc/krb5.conf
	echo "    default = FILE:/var/log/samba/krb5libs.log"
	echo "    kdc = FILE:/var/log/samba/krb5kdc.log"
	echo "    admin_server = FILE:/var/log/samba/kadmind.log" 	        
	} >> /etc/krb5.conf
	fi
	# If the finished file isn't there, this is brand new, we're not just moving to a new container
	if [[ ! -f /etc/samba/external/smb.conf ]]; then
		mv /etc/samba/smb.conf /etc/samba/smb.conf.orig
		if [[ ${JOIN,,} == "true" ]]; then
			if [[ ${JOINSITE} == "NONE" ]]; then
				samba-tool domain join "${LDOMAIN}" DC -U"${URDOMAIN}\administrator" --password="${DOMAINPASS}" --dns-backend=SAMBA_INTERNAL
			else
				samba-tool domain join "${LDOMAIN}" DC -U"${URDOMAIN}\administrator" --password="${DOMAINPASS}" --dns-backend=SAMBA_INTERNAL --site="${JOINSITE}"
			fi
		else
			samba-tool domain provision --use-rfc2307 --domain="${URDOMAIN}" --realm="${UDOMAIN}" --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass="${DOMAINPASS}" "${HOSTIP_OPTION}"
			if [[ ${NOCOMPLEXITY,,} == "true" ]]; then
				samba-tool domain passwordsettings set --complexity=off
				samba-tool domain passwordsettings set --history-length=0
				samba-tool domain passwordsettings set --min-pwd-age=0
				samba-tool domain passwordsettings set --max-pwd-age=0
			fi
		fi
		if [[ ${JOIN,,} == "true" ]]; then
		sed -i "/\[global\]/a \
		idmap_ldb:use rfc2307 = yes\\n\
		idmap config * : backend = tdb\\n\
		idmap config * : range = 1000000-1999999\\n\
		idmap config ${URDOMAIN} : backend = ad\\n\
		idmap config ${URDOMAIN} : range = 2000000-2999999\\n\
		idmap config ${URDOMAIN} : schema_mode = rfc2307\\n\
		idmap config ${URDOMAIN} : unix_nss_info = yes\\n\
		#idmap config ${URDOMAIN} : unix_primary_group = yes\\n\
		vfs objects = acl_xattr\\n\
		map acl inherit = yes\\n\
		store dos attributes = yes\
		" /etc/samba/smb.conf

		fi
		sed -i "/\[global\]/a \
		wins support = yes\\n\
		# Template settings for login shell and home directory\\n\
		template shell = /bin/bash\\n\
		template homedir = /home/%U\
		" /etc/samba/smb.conf
		if [[ $DNSFORWARDER != "NONE" ]]; then
			sed -i "/\[global\]/a \
				\\\tdns forwarder = ${DNSFORWARDER}\
				" /etc/samba/smb.conf
		fi
		if [[ ${TLS,,} == "true" ]]; then
		sed -i "/\[global\]/a \
		tls enabled  = yes\\n\
		tls keyfile  = /var/lib/samba/private/tls/key.pem\\n\
		tls certfile = /var/lib/samba/private/tls/crt.pem\\n\
		tls cafile   = /var/lib/samba/private/tls/chain.pem\\n\
		tls verify peer = ca_and_name\
		" /etc/samba/smb.conf
#	tls crlfile   = /etc/samba/tls/crl.pem\\n\
#	
#
		fi
		
		#Remove Printers ALWAYS
		sed -i "/\[global\]/a \
		load printers = no\\n\
		printing = bsd\\n\
		printcap name = /dev/null\\n\
		disable spoolss = yes\
		" /etc/samba/smb.conf
		
		if [[ ${LOGS,,} == "true" ]]; then
			sed -i "/\[global\]/a \
			log file = /var/log/samba/%m.log\\n\
			max log size = 10000\\n\
			log level = 3\
			" /etc/samba/smb.conf
		fi
		if [[ ${INSECURELDAP,,} == "true" ]]; then
			sed -i "/\[global\]/a \
			\\\tldap server require strong auth = no\
			" /etc/samba/smb.conf
		fi
		if [[ ${ADLoginOnUnix,,} == "true" ]]; then
			winbind enum users = yes
			winbind enum groups = yes
		# nsswitch anpassen
		fi
	
        #Drop privileges
		#https://medium.com/@mccode/processes-in-containers-should-not-run-as-root-2feae3f0df3b
         
         
		# Once we are set up, we'll make a file so that we know to use it if we ever spin this up again
		cp -f /etc/samba/smb.conf /etc/samba/external/smb.conf
	else
		cp -f /etc/samba/external/smb.conf /etc/samba/smb.conf
	fi
  
	# Set up supervisor
	touch /etc/supervisor/conf.d/supervisord.conf
	{
	echo "[supervisord]"
	echo "nodaemon=true"
	#Suppress CRIT Supervisor is running as root.  Privileges were not dropped because no user is specified in the config file.  If you intend to run as root, you can set user=root in the config file to avoid this message.
	echo "user=root"
	echo ""
	echo "[program:samba]"
	echo "command=/usr/sbin/samba -F"
	echo "stdout_logfile=/dev/fd/1"
	echo "stdout_logfile_maxbytes=0"
	echo "stdout_logfile_backups=0"
	echo ""
	echo "[program:ntpd]"
	echo "command=/usr/sbin/ntpd -c /etc/ntpd.conf -n"
	echo "stdout_logfile=/dev/fd/1"
	echo "stdout_logfile_maxbytes=0"
	echo "stdout_logfile_backups=0"
	} >> /etc/supervisor/conf.d/supervisord.conf
	
	#Suppress CRIT Server 'unix_http_server' running without any HTTP authentication checking
	#https://github.com/Supervisor/supervisor/issues/717
	sed -i "/\[unix_http_server\]/a \
username=dummy\\n\
password=dummy\
	" /etc/supervisor/supervisord.conf
	sed -i "/\[supervisorctl\]/a \
username = dummy\\n\
password = dummy\
	" /etc/supervisor/supervisord.conf	

	if [[ ${MULTISITE,,} == "true" ]]; then
	  if [[ -n $VPNPID ]]; then
	    kill $VPNPID	
	  fi
	{
      echo ""
	  echo "[program:openvpn]"
	  echo "command=/usr/sbin/openvpn --config /docker.ovpn"		        
	} >> /etc/supervisor/conf.d/supervisord.conf
	fi
	if [[ ${JOIN,,} == "true" ]]; then
	  # Set up ntpd
	  touch /etc/ntpd.conf
	  {
	  echo "server 127.127.1.0"
	  echo "fudge  127.127.1.0 stratum 10"
	  echo "server 0.pool.ntp.org     iburst prefer"
	  echo "server 1.pool.ntp.org     iburst prefer"
	  echo "server 2.pool.ntp.org     iburst prefer"
	  echo "driftfile       /var/lib/ntp/ntp.drift"
	  echo "logfile         /var/log/ntp"
	  echo "ntpsigndsocket  /var/lib/samba/ntp_signd/"
	  echo "restrict default kod nomodify notrap nopeer mssntp"
	  echo "restrict 127.0.0.1"
	  echo "restrict 0.pool.ntp.org   mask 255.255.255.255    nomodify notrap nopeer noquery"
	  echo "restrict 1.pool.ntp.org   mask 255.255.255.255    nomodify notrap nopeer noquery"
	  echo "restrict 2.pool.ntp.org   mask 255.255.255.255    nomodify notrap nopeer noquery"	        
	  }  >> /etc/ntpd.conf
	else
	  {
	  echo "# Local clock. Note that is not the localhost address!"
	  echo "server 127.127.1.0"
	  echo "fudge  127.127.1.0 stratum 10"
 
	  echo "# Where to retrieve the time from"
	  echo "server DC01.${LDOMAIN}    iburst prefer"
	  echo "server DC02.${LDOMAIN}    iburst"

	  echo "driftfile /var/lib/ntp/ntp.drift"
	  echo "logfile   /var/log/ntp"

	  echo "# Access control"
	  echo "# Default restriction: Disallow everything"
	  echo "restrict default ignore"

	  echo "# No restrictions for localhost"
	  echo "restrict 127.0.0.1"

	  echo "# Enable the time sources only to only provide time to this host"
	  echo "restrict DC01.${LDOMAIN}  mask 255.255.255.255    nomodify notrap nopeer noquery"
	  echo "restrict DC02.${LDOMAIN}  mask 255.255.255.255    nomodify notrap nopeer noquery"
	  echo ""
	  echo "tinker panic 0"
	  } >> /etc/ntpd.conf
		
	  # Own socket
	  mkdir -p /var/lib/samba/ntp_signd/
	  chown root:ntp /var/lib/samba/ntp_signd/
	  chmod 750 /var/lib/samba/ntp_signd/
    fi

	appStart
}

appStart () {
	/usr/bin/supervisord
}

case "$1" in
	start)
		if [[ -f /etc/samba/external/smb.conf ]]; then
			cp /etc/samba/external/smb.conf /etc/samba/smb.conf
			appStart
		else
			echo "Config file is missing."
		fi
		;;
	setup)
		# If the supervisor conf isn't there, we're spinning up a new container
		if [[ -f /etc/supervisor/conf.d/supervisord.conf ]]; then
			appStart
		else
			appSetup
		fi
		;;
esac

exit 0