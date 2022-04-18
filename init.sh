#!/bin/bash

set -e
set -x

#Todo:
#create Keytab:  net ads keytab create ${SAMBA_DEBUG_OPTION} und kerberos method = secrets and keytab
#Drop privileges: https://medium.com/@mccode/processes-in-containers-should-not-run-as-root-2feae3f0df3b
# ID_Map replication: https://wiki.samba.org/index.php/Joining_a_Samba_DC_to_an_Existing_Active_Directory#Built-in_User_.26_Group_ID_Mappings
# SYSVOL replication:
#- Add   --option='idmap_ldb:use rfc2307 = yes'       on joining a new DC to support rfc-extension
#- Bind Interface: https://github.com/moby/moby/issues/25181#issuecomment-618811417
# Add Kerberos granting ticket pw auto changer https://gitlab.com/samba-team/samba/raw/v4-15-stable/source4/scripting/devel/chgkrbtgtpass
# https://gitlab.com/samba-team/samba/-/blob/master/source4/scripting/bin/enablerecyclebin
#gpo template ntp server https://docs.microsoft.com/de-de/services-hub/health/remediation-steps-ad/configure-the-root-pdc-with-an-authoritative-time-source-and-avoid-widespread-time-skew
# Add the following line to allow a subnet to receive time service and query server statistics:  https://support.ntp.org/bin/view/Support/AccessRestrictions#Section_6.5.1.1.3.
# time sync as client (beim join)

appSetup () {

  BIND_INTERFACE=${BIND_INTERFACE:-false}
  INTERFACES=${INTERFACES:-eth0}

  # Set variables
  DOMAIN=${DOMAIN:-SAMDOM.LOCAL}
  DOMAINUSER=${DOMAINUSER:-Administrator}
  DOMAINPASS=${DOMAINPASS:-youshouldsetapassword}

  LDOMAIN=${DOMAIN,,} #alllowercase
  UDOMAIN=${DOMAIN^^} #ALLUPPERCASE
  URDOMAIN=${UDOMAIN%%.*} #trim
  #Posix
  #LDOMAIN=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]')
  #UDOMAIN=$(echo "$LDOMAIN" | tr '[:lower:]' '[:upper:]')
  #URDOMAIN=$(echo "$UDOMAIN" | cut -d "." -f1)
  #Change if hostname includes DNS/DOMAIN SUFFIX e.g. host.example.com - it should only display host

  DOMAIN_NETBIOS=${DOMAIN_NETBIOS:-$URDOMAIN}
  JOINSITE=${JOINSITE:-Default-First-Site-Name}
  JOIN=${JOIN:-false}
  MULTISITE=${MULTISITE:-false}
  NOCOMPLEXITY=${NOCOMPLEXITY:-false}
  INSECURELDAP=${INSECURELDAP:-false}
  DNSFORWARDER=${DNSFORWARDER:-NONE}
  HOSTIP=${HOSTIP:-NONE}
  HOSTNAME=${HOSTNAME:-$(hostname)}
  export HOSTNAME="$HOSTNAME"
  TLS=${TLS:-false}
  TLS_PKI=${TLS_PKI:-false}
  PKI_O=${PKI_O:-Simple Root CA}
  PKI_OU=${PKI_OU:-Samba}
  PKI_CN=${PKI_CN:-Simple Samba Root CA}
  LOGS=${LOGS:-false}

  SCHEMA_LAPS=${SCHEMA_LAPS:-true}
  RFC2307=${RFC2307:-false}

  NTPSERVERLIST=${NTPSERVERLIST:-0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org}

  MSCHAPV2=${MSCHAPV2:-false}
  DEBUG=${DEBUG:-true}
  DEBUGLEVEL=${DEBUGLEVEL:-10}

  #Check if DOMAIN_NETBIOS <15 chars and contains no "."
  if [[ ${#DOMAIN_NETBIOS} -gt 15 ]]; then
    echo "DOMAIN_NETBIOS too long => exiting"
    #exit 1
  fi
  if [[ $DOMAIN_NETBIOS == *"."* ]]; then
    echo "DOMAIN_NETBIOS contains forbiden char    .     => exiting"
    exit 1
  fi

  # Min Counter Values for NIS Attributes. Set in docker-compose if you want a different start
  # IT does nothing on DCs as they shall not use idmap settings.
  # Using the same Start and stop values on members however gets the RFC2307 attributs (NIS) rights
  # idmap config {{ URDOMAIN }} : range = {{ IDMIN }}-{{ IDMAX }}
  IMAP_ID_START=${IMAP_UID_START:-10000}
  IMAP_UID_START=${IMAP_UID_START:-$IMAP_ID_START}
  IMAP_GID_START=${IMAP_GID_START:-$IMAP_ID_START}
  #DN for LDIF
  LDAPDN=""
  IFS='.'
  for dn in ${LDOMAIN}; do
    LDAPDN="${LDAPDN},DC=$dn"
  done
  IFS=''
  # If multi-site, we need to connect to the VPN before joining the domain
  if [[ ${MULTISITE,,} = true ]]; then
    /usr/sbin/openvpn --config /docker.ovpn &
    VPNPID=$!
    echo "Sleeping 30s to ensure VPN connects ($VPNPID)";
    sleep 30
  fi

  if [[ "$RFC2307" = true ]]; then
    if [[ "$JOIN" = true ]];then
	  OPTION_RFC=--option='idmap_ldb:use rfc2307 = yes'
	else
      OPTION_RFC=--use-rfc2307	  
	fi
  fi
  if [[ "$HOSTIP" != "NONE" ]]; then
    OPTION_HOSTIP=--host-ip="${HOSTIP}"
  fi
  if [[ "$JOINSITE" != "NONE" ]]; then
    OPTION_JOIN=--site="${JOINSITE}"
  fi
  #fails due to space and wrong escaping of variables
  if [[ "$DNSFORWARDER" != "NONE" ]]; then
    OPTION_DNS_FWD=--option="dns forwarder=${DNSFORWARDER}"
  fi
  if [[ "$BIND_INTERFACE" = true ]]; then
    OPTION_INT=--option="interfaces=${INTERFACES,,} lo"
    OPTION_BIND=--option="bind interfaces only = yes"
  fi

  if [[ "$DEBUG" = true ]]; then
    SAMBA_DEBUG_OPTION="-d $DEBUGLEVEL"
    SAMBADAEMON_DEBUG_OPTION="--debug-stdout -d $DEBUGLEVEL"
    NTP_DEBUG_OPTION=""
    #NTP_DEBUG_OPTION="-D $DEBUGLEVEL"

  else
    SAMBA_DEBUG_OPTION=""
    NTP_DEBUG_OPTION=""
    SAMBADAEMON_DEBUG_OPTION=""
  fi

  sed -e "s:{{ SAMBADAEMON_DEBUG_OPTION }}:$SAMBADAEMON_DEBUG_OPTION:" -i /etc/supervisor/conf.d/supervisord.conf
  sed -e "s:{{ NTP_DEBUG_OPTION }}:$NTP_DEBUG_OPTION:" -i /etc/supervisor/conf.d/supervisord.conf

  if [[ ! -d /etc/samba/external/ ]]; then
    mkdir /etc/samba/external
  fi

  sed -e "s:{{ UDOMAIN }}:$UDOMAIN:" \
    -e "s:{{ LDOMAIN }}:$LDOMAIN:" \
    -e "s:{{ HOSTNAME }}:$HOSTNAME:" \
    -i /etc/krb5.conf

  # If the finished file (external/smb.conf) doesn't exist, this is new container with empty volume, we're not just moving to a new container
  if [[ ! -f /etc/samba/external/smb.conf ]]; then
    if [[ -f /etc/samba/smb.conf ]]; then
      mv /etc/samba/smb.conf /etc/samba/smb.conf.orig
    fi
    # NOTE: DO not escape the missing variables below with "" it will break syntax
	# Optional params without "" will break the command
    if [[ ${JOIN,,} = true ]]; then
#	  if [ "$(dig +short -t srv _ldap._tcp.$LDOMAIN.)" ] && echo "got answer"
	  n=0
      until [ "$n" -ge 10 ]
	  do
        samba-tool domain join "${LDOMAIN}" DC -U"${DOMAIN_NETBIOS}"\\"${DOMAINUSER}" ${OPTION_RFC} --password="${DOMAINPASS}" "${OPTION_JOIN}" '--dns-backend=SAMBA_INTERNAL' ${SAMBA_DEBUG_OPTION} && s=0 && break || s=$? && sleep 60
		n++
      done; (exit $s)
	  # Netlogon & sysvol readonly on secondary DC
	  {
        echo " "
        echo "[netlogon]"
        echo "path = /var/lib/samba/sysvol/test.dom/scripts"
        echo "read only = Yes"
        echo " "
        echo "[sysvol]"
        echo "path = /var/lib/samba/sysvol"
        echo "read only = Yes"
	  } >> /etc/samba/smb.conf
      #Check if Join was successfull
	  if [ host -t A $HOSTNAME.$LDOMAIN. ];then
	    echo "found DNS host record"
      else
	    echo "no DNS host record found. Running fix"
		#samba-tool dns add DC1 samdom.example.com DC2 A 10.99.0.2 -Uadministrator
	  fi
	  # [https://wiki.samba.org/index.php/Verifying_and_Creating_a_DC_DNS_Record#Verifying_and_Creating_the_objectGUID_Record]
	   # on existing DC e.g DC01
	   # objectGUIDs = ldbsearch -H /usr/local/samba/private/sam.ldb '(invocationId=*)' --cross-ncs objectguid | grep objectguid
	   #foreach objectGUID in objectGUIDs
	   # if [ host -t CNAME $objectGUID._msdcs.samdom.example.com. ];then
	     # samba-tool dns add DC1 _msdcs.samdom.example.com df4bdd8c-abc7-4779-b01e-4dd4553ca3e9 CNAME DC2.samdom.example.com -Uadministrator
		 # samba-tool dns add DC1 _msdcs.samdom.example.com $objectGUID CNAME DC2.samdom.example.com -Uadministrator -p password
	   #fi
    else
      samba-tool domain provision "--domain=${DOMAIN_NETBIOS}" "--realm=${UDOMAIN}" "${OPTION_JOIN}" "--adminpass=${DOMAINPASS}" "--host-name=${HOSTNAME}" '--server-role=dc' '--dns-backend=SAMBA_INTERNAL' ${OPTION_INT} ${OPTION_BIND} ${OPTION_HOSTIP} ${OPTION_RFC}  ${SAMBA_DEBUG_OPTION} || echo " Samba Domain Provisioning failed" && exit 1
	  {
        echo ""
        echo "[program:ChangeKRBTGT]"
        echo "command=/bin/sh /scripts/chgkrbtgtpass.sh"
        echo "stdout_logfile=/dev/fd/1"
        echo "stdout_logfile_maxbytes=0"
        echo "stdout_logfile_backups=0"
		echo "redirect_stderr=true"
        echo "priority=99"
      } >> /etc/supervisor/conf.d/supervisord.conf

      if [[ ! -d /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/ ]]; then
        mkdir -p /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/en-US
        mkdir /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/de-DE
      fi
      # Set default uid and gid for ad user and groups, based on IMAP_GID_START value
      if [[ "$RFC2307" = true ]]; then
        GID_DOM_USER=$((IMAP_GID_START))
        GID_DOM_ADMIN=$((IMAP_GID_START+1))
        GID_DOM_COMPUTERS=$((IMAP_GID_START+2))
        GID_DOM_DC=$((IMAP_GID_START+3))
        GID_DOM_GUEST=$((IMAP_GID_START+4))
        GID_SCHEMA=$((IMAP_GID_START+5))
        GID_ENTERPRISE=$((IMAP_GID_START+6))
        GID_GPO=$((IMAP_GID_START+7))
        GID_RDOC=$((IMAP_GID_START+8))
        GID_DNSUPDATE=$((IMAP_GID_START+9))
        GID_ENTERPRISE_RDOC=$((IMAP_GID_START+10))
        GID_DNSADMIN=$((IMAP_GID_START+11))
        GID_ALLOWED_RDOC=$((IMAP_GID_START+12))
        GID_DENIED_RDOC=$((IMAP_GID_START+13))
        GID_RAS=$((IMAP_GID_START+14))
        GID_CERT=$((IMAP_GID_START+15))

        UID_KRBTGT=$((IMAP_UID_START))
        UID_GUEST=$((IMAP_UID_START+1))
        UID_ADMINISTRATOR=$((IMAP_UID_START+2))

        #Next Counter value uesd by ADUC for NIS Extension GID and UID
        IMAP_GID_END=$((IMAP_GID_START+16))
        IMAP_UID_END=$((IMAP_UID_START+3))

        sed -e "s: {{ LDAPDN }}:$LDAPDN:g" \
          -e "s:{{ NETBIOS }}:${DOMAIN_NETBIOS,,}:g" \
          -e "s:{{ GID_DOM_USER }}:$GID_DOM_USER:g" \
          -e "s:{{ GID_DOM_ADMIN }}:$GID_DOM_ADMIN:g" \
          -e "s:{{ GID_DOM_COMPUTERS }}:$GID_DOM_COMPUTERS:g" \
          -e "s:{{ GID_DOM_DC }}:$GID_DOM_DC:g" \
          -e "s:{{ GID_DOM_GUEST }}:$GID_DOM_GUEST:g" \
          -e "s:{{ GID_SCHEMA }}:$GID_SCHEMA:g" \
          -e "s:{{ GID_ENTERPRISE }}:$GID_ENTERPRISE:g" \
          -e "s:{{ GID_GPO }}:$GID_GPO:g" \
          -e "s:{{ GID_RDOC }}:$GID_RDOC:g" \
          -e "s:{{ GID_DNSUPDATE }}:$GID_DNSUPDATE:g" \
          -e "s:{{ GID_ENTERPRISE_RDOC }}:$GID_ENTERPRISE_RDOC:g" \
          -e "s:{{ GID_DNSADMIN }}:$GID_DNSADMIN:g" \
          -e "s:{{ GID_ALLOWED_RDOC }}:$GID_ALLOWED_RDOC:g" \
          -e "s:{{ GID_DENIED_RDOC }}:$GID_DENIED_RDOC:g" \
          -e "s:{{ GID_RAS }}:$GID_RAS:g" \
          -e "s:{{ GID_CERT }}:$GID_CERT:g" \
          -e "s:{{ UID_KRBTGT }}:$UID_KRBTGT:g" \
          -e "s:{{ UID_GUEST }}:$UID_GUEST:g" \
          -e "s:{{ UID_ADMINISTRATOR }}:$UID_ADMINISTRATOR:g" \
          -e "s:{{ IMAP_UID_END }}:$IMAP_UID_END:g" \
          -e "s:{{ IMAP_GID_END }}:$IMAP_GID_END:g" \
          /ldif/RFC_Domain_User_Group.ldif.j2 > /ldif/RFC_Domain_User_Group.ldif

        ldbmodify -H /var/lib/samba/private/sam.ldb /ldif/RFC_Domain_User_Group.ldif -U "${DOMAINUSER}"
      fi
      #Microsoft Local Administrator Password Solution (LAPS)
      if [[ "$SCHEMA_LAPS" = true ]]; then
        sed -e "s: {{ LDAPDN }}:$LDAPDN:g" \
          /ldif/laps-1.ldif.j2 > /ldif/laps-1.ldif

        sed -e "s: {{ LDAPDN }}:$LDAPDN:g" \
          /ldif/laps-2.ldif.j2 > /ldif/laps-2.ldif

        ldbadd -H /var/lib/samba/private/sam.ldb --option="dsdb:schema update allowed"=true /ldif/laps-1.ldif -U "${DOMAINUSER}"
        ldbmodify -H /var/lib/samba/private/sam.ldb --option="dsdb:schema update allowed"=true /ldif/laps-2.ldif -U "${DOMAINUSER}"
      fi

      if [[ ${NOCOMPLEXITY,,} = true ]]; then
        samba-tool domain passwordsettings set --complexity=off "${SAMBA_DEBUG_OPTION}"
        samba-tool domain passwordsettings set --history-length=0 "${SAMBA_DEBUG_OPTION}"
        samba-tool domain passwordsettings set --min-pwd-age=0 "${SAMBA_DEBUG_OPTION}"
        samba-tool domain passwordsettings set --max-pwd-age=0 "${SAMBA_DEBUG_OPTION}"
      fi
    fi

    #Prevent https://wiki.samba.org/index.php/Samba_Member_Server_Troubleshooting => SeDiskOperatorPrivilege can't be set
    if [ ! -f /etc/samba/user.map ]; then
      echo '!'"root = ${DOMAIN}\\${DOMAINUSER}" > /etc/samba/user.map
      sed -i "/\[global\]/a \
username map = /etc/samba/user.map\
    " /etc/samba/smb.conf
    fi

    #if [ "${BIND_INTERFACE,,}" = true ]; then
      #    sed -i "/\[global\]/a \
        #interfaces =${INTERFACES,,} lo\\n\
        #bind interfaces only = yes\
        #    " /etc/samba/smb.conf
    #  printf >> "interface listen lo" /etc/ntp.conf
    #  for INTERFACE in $INTERFACES
    #  do
    #    printf >> "interface listen $INTERFACE"
    #  done

    #fi
    ###################
    # limit dynamic rpc port from 49152-65535 to 49172 so we can proxy them (otherwise we run out of memory)
    sed -i "/\[global\]/a \
rpc server dynamic port range = 49152-49172\
        " /etc/samba/smb.conf
    ###################
    if [[ $DNSFORWARDER != "NONE" ]]; then
      sed -i '/dns forwarder/d' /etc/samba/smb.conf
      sed -i "/\[global\]/a \
dns forwarder = ${DNSFORWARDER}\
        " /etc/samba/smb.conf
    fi

    if [[ ${TLS,,} = true ]]; then
	  if [ ! -f tls/key.pem ] && [ ! -f tls/cert.pem ]; then
	  
print "empty if clause - work with me"
      fi
	  if [ ! -f /var/lib/samba/private/tls/dh.key ]; then
        openssl dhparam -out /var/lib/samba/private/tls/dh.key 2048
      fi

      sed -i "/\[global\]/a \
tls enabled  = yes\\n\
tls keyfile  = tls/key.pem\\n\
tls certfile = tls/cert.pem\\n\
#tls cafile   = tls/intermediate.pem\\n\
tls cafile   = tls/ca.pem\\n\
tls dh params file = tls/dh.key\\n\
#tls crlfile   = tls/crl.pem\\n\
#tls verify peer = ca_and_name\
    " /etc/samba/smb.conf

      # Prevent downgrade attacks to md5
      sed -i "/\[global\]/a \
reject md5 clients = yes\\n\
reject md5 servers = yes\
    " /etc/samba/smb.conf
    fi

    if [[ ${MSCHAPV2,,} = true ]]; then
      sed -i "/\[global\]/a \
ntlm auth = mschapv2-and-ntlmv2-only\
    " /etc/samba/smb.conf
    fi

    sed -i "/\[global\]/a \
wins support = yes\\n\
# Template settings for login shell and home directory\\n\
template shell = /bin/bash\\n\
template homedir = /home/%U\\n\
load printers = no\\n\
printing = bsd\\n\
printcap name = /dev/null\\n\
disable spoolss = yes\
    " /etc/samba/smb.conf

#    if [[ ${LOGS,,} = true ]]; then
#      sed -i "/\[global\]/a \
#log file = /var/log/samba/%m.log\\n\
#max log size = 10000\\n\
#log level = 1\
#      " /etc/samba/smb.conf
#    else
#      sed -i "/\[global\]/a \
#log level = 0\\n\
#      " /etc/samba/smb.conf
#sed -i '/FILE:/s/^#//g' /etc/krb5.conf
#    fi

    if [[ ${INSECURELDAP,,} = true ]]; then
      sed -i "/\[global\]/a \
ldap server require strong auth = no\
      " /etc/samba/smb.conf
    fi

    # nsswitch anpassen
    sed -i "s,passwd:.*,passwd:         files winbind,g" "/etc/nsswitch.conf"
    sed -i "s,group:.*,group:          files winbind,g" "/etc/nsswitch.conf"
    sed -i "s,hosts:.*,hosts:          files dns,g" "/etc/nsswitch.conf"
    sed -i "s,networks:.*,networks:      files dns,g" "/etc/nsswitch.conf"


    # Once we are set up, we'll make a file so that we know to use it if we ever spin this up again
    cp -f /etc/samba/smb.conf /etc/samba/external/smb.conf
  else
    cp -f /etc/samba/external/smb.conf /etc/samba/smb.conf
  fi
    # https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller
  	#Test Kerberos
	if [ echo "${DOMAINPASS}" | kinit "${DOMAINUSER}" ];then
	  echo " kinit successfull"
	  klist
    fi
	# Verify Samba Fileserver is working
	smbclient -L localhost -N
	# Test Samba Auth
	smbclient //localhost/netlogon -U"${DOMAINUSER}" -c 'ls' --password "${DOMAINPASS}"
	
  # Stop VPN & write supervisor service
  if [[ ${MULTISITE,,} = true ]]; then
    if [[ -n $VPNPID ]]; then
      kill $VPNPID
    fi
    {
      echo ""
      echo "[program:openvpn]"
      echo "command=/usr/sbin/openvpn --config /docker.ovpn"
      echo "stdout_logfile=/dev/fd/1"
      echo "stdout_logfile_maxbytes=0"
      echo "stdout_logfile_backups=0"
	  echo "redirect_stderr=true"
      echo "priority=1"
    } >> /etc/supervisor/conf.d/supervisord.conf
  fi

  if [[ ! -f /var/lib/ntp/ntp.drift ]]; then
    touch /var/lib/ntp/ntp.drift
  fi

  DCs=$(echo "$NTPSERVERLIST" | tr " " "\n")
  NTPSERVER=""
  NTPSERVERRESTRICT=""
  for DC in $DCs
  do
    NTPSERVER="$NTPSERVER server ${DC}    iburst prefer\n"
    NTPSERVERRESTRICT="$NTPSERVERRESTRICT restrict ${DC} mask 255.255.255.255    nomodify notrap nopeer noquery\n"
  done

  sed -e "s:{{ NTPSERVER }}:$NTPSERVER:" \
    -e "s:{{ NTPSERVERRESTRICT }}:$NTPSERVERRESTRICT:" \
    -i /etc/ntp.conf

  # Own socket
  mkdir -p /var/lib/samba/ntp_signd/
  chown root:ntp /var/lib/samba/ntp_signd/
  chmod 750 /var/lib/samba/ntp_signd/

#  if [[ ! -d /var/lib/samba/winbindd_privileged/ ]]; then
#    mkdir /var/lib/samba/winbindd_privileged/
#    chown root:winbindd_priv /var/lib/samba/winbindd_privileged/
#    chmod 0750 /var/lib/samba/winbindd_privileged
#  else
#    chown root:winbindd_priv /var/lib/samba/winbindd_privileged/
#    chmod 0750 /var/lib/samba/winbindd_privileged
#  fi

  appFirstStart
}

appFirstStart () {
  /usr/bin/supervisord -c "/etc/supervisor/supervisord.conf"
  #You want to set SeDiskOperatorPrivilege on your member server to manage your share permissions:
  net rpc rights grant "$UDOMAIN\Domain Admins" SeDiskOperatorPrivilege -U"$UDOMAIN\${DOMAINUSER,,}" "${DEBUG_OPTION}"
}

appStart () {
  # Check for samdb errors
  samba-tool dbcheck --cross-ncs --fix --yes
  /usr/bin/supervisord
}

# If the supervisor conf isn't there, we're spinning up a new container
if [[ -f /etc/samba/external/smb.conf ]]; then
  cp /etc/samba/external/smb.conf /etc/samba/smb.conf
  appStart
else
  appSetup
fi

exit 0