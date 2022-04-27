#!/bin/bash

set -x

#Todo:
# ID_Map replication: https://wiki.samba.org/index.php/Joining_a_Samba_DC_to_an_Existing_Active_Directory#Built-in_User_.26_Group_ID_Mappings
# SYSVOL replication:
# Add the following line to allow a subnet to receive time service and query server statistics:  https://support.ntp.org/bin/view/Support/AccessRestrictions#Section_6.5.1.1.3.
# time sync as client (beim join)
config () {
  # Set variables
  DOMAIN=${DOMAIN:-SAMDOM.LOCAL}
  LDOMAIN=${DOMAIN,,} #alllowercase
  UDOMAIN=${DOMAIN^^} #ALLUPPERCASE
  URDOMAIN=${UDOMAIN%%.*} #trim
  
  DOMAIN_USER=${DOMAIN_USER:-Administrator}
  DOMAIN_PASS=${DOMAIN_PASS:-youshouldsetapassword}
  DOMAIN_NETBIOS=${DOMAIN_NETBIOS:-$URDOMAIN}

  #Posix
  #LDOMAIN=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]')
  #UDOMAIN=$(echo "$LDOMAIN" | tr '[:lower:]' '[:upper:]')
  #URDOMAIN=$(echo "$UDOMAIN" | cut -d "." -f1)

  HOSTIP=${HOSTIP:-NONE}
  #Change if hostname includes DNS/DOMAIN SUFFIX e.g. host.example.com - it should only display host
  HOSTNAME=${HOSTNAME:-$(hostname)}

  #DN for LDIF
  LDAP_SUFFIX=""
  IFS='.'
  for dn in ${LDOMAIN}; do
    LDAP_SUFFIX="${LDAP_SUFFIX},DC=$dn"
  done
  IFS=''
  LDAP_DN=$HOSTNAME$LDAP_SUFFIX

  JOIN=${JOIN:-false}
  JOIN_SITE=${JOIN_SITE:-Default-First-Site-Name}
  # One could write a service to acomplish a wireguard mesh network between docker container on different sites as an "overlay-network" - https://www.scaleway.com/en/docs/tutorials/wireguard-mesh-vpn/
  JOIN_SITE_VPN=${JOIN_SITE_VPN:-false}
  NTPSERVERLIST=${NTPSERVERLIST:-0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org}
  RECYCLEBIN=${RECYCLEBIN:-true}
  CHANGE_KRB_TGT_PW=${CHANGE_KRB_TGT_PW:-false}

  DISABLE_MD5=${DISABLE_MD5:-true}
  DISABLE_PW_COMPLEXITY=${DISABLE_PW_COMPLEXITY:-false}

  ENABLE_CUPS=${ENABLE_CUPS:-false}
  ENABLE_DNSFORWARDER=${ENABLE_DNSFORWARDER:-NONE}
  ENABLE_DYNAMIC_PORTRANGE=${ENABLE_DYNAMIC_PORTRANGE:-NONE}
  ENABLE_INSECURE_LDAP=${ENABLE_INSECURE_LDAP:-false}
  ENABLE_LAPS_SCHEMA=${ENABLE_LAPS_SCHEMA:-true}
  ENABLE_LOGS=${ENABLE_LOGS:-false}
  ENABLE_MSCHAPV2=${ENABLE_MSCHAPV2:-false}
  ENABLE_RFC2307=${ENABLE_RFC2307:-true}

  ENABLE_TLS=${ENABLE_TLS:-false}
  TLS_PKI=${TLS_PKI:-false}
  PKI_O=${PKI_O:-Simple Root CA}
  PKI_OU=${PKI_OU:-Samba}
  PKI_CN=${PKI_CN:-Simple Samba Root CA}

  ENABLE_DEBUG=${ENABLE_DEBUG:-true}
  DEBUG_LEVEL=${DEBUG_LEVEL:-0}

  ENABLE_BIND_INTERFACE=${ENABLE_BIND_INTERFACE:-false}
  BIND_INTERFACES=${BIND_INTERFACES:-eth0} # Can be a list of interfaces seperated by spaces

  # Min Counter Values for NIS Attributes. Set in docker-compose if you want a different start
  # IT does nothing on DCs as they shall not use idmap settings.
  # Using the same Start and stop values on members however gets the RFC2307 attributs (NIS) rights
  # idmap config {{ URDOMAIN }} : range = {{ IDMIN }}-{{ IDMAX }}
  IMAP_ID_START=${IMAP_UID_START:-10000}
  IMAP_UID_START=${IMAP_UID_START:-$IMAP_ID_START}
  IMAP_GID_START=${IMAP_GID_START:-$IMAP_ID_START}

  #file variables
  # DIR_SAMBA_CONF_DIR and DIR_SCRIPTS also need to be changed in the Dockerfile
  DIR_SAMBA_DATA_PREFIX=/var/lib/samba
  DIR_SAMBA_ETC=/etc/samba
  DIR_SAMBA_PRIVATE=$DIR_SAMBA_DATA_PREFIX/private
  DIR_SAMBA_CONF_DIR=$DIR_SAMBA_ETC/smb.conf.d
  DIR_SCRIPTS=/scripts
  DIR_LDIF=/ldif

  FILE_PKI_CA=$DIR_SAMBA_PRIVATE/tls/ca.pem
  FILE_PKI_CERT=$DIR_SAMBA_PRIVATE/tls/cert.pem
  FILE_PKI_CRL=$DIR_SAMBA_PRIVATE/tls/crl.pem
  FILE_PKI_DH=$DIR_SAMBA_PRIVATE/tls/dh.key
  FILE_PKI_INT=$DIR_SAMBA_PRIVATE/tls/intermediate.pem
  FILE_PKI_KEY=$DIR_SAMBA_PRIVATE/tls/key.pem

  FILE_SAMBA_CONF=$DIR_SAMBA_ETC/smb.conf
  FILE_SAMBA_CONF_EXTERNAL=$DIR_SAMBA_ETC/external/smb.conf
  FILE_SAMBA_INCLUDES=$DIR_SAMBA_ETC/includes.conf
  FILE_SAMBA_USER_MAP=$DIR_SAMBA_ETC/user.map

  FILE_SAMBA_SCHEMA_RFC=$DIR_LDIF/RFC_Domain_User_Group.ldif
  FILE_SAMBA_SCHEMA_LAPS1=$DIR_LDIF/laps-1.ldif
  FILE_SAMBA_SCHEMA_LAPS2=$DIR_LDIF/laps-2.ldif
  FILE_SAMBA_SCHEMA_WINSREPL=$DIR_LDIF/wins.ldif
  
  FILE_SUPERVISORD_CUSTOM_CONF=/etc/supervisor/conf.d/supervisord.conf
  FILE_SUPERVISORD_CONF=/etc/supervisor/supervisord.conf
  FILE_OPENVPNCONF=/docker.ovpn
  FILE_KRB5=/etc/krb5.conf
  FILE_NSSWITCH=/etc/nsswitch.conf
  FILE_SAMLDB=$DIR_SAMBA_PRIVATE/sam.ldb
  FILE_NTP=/etc/ntp.conf

  # exports for other scripts and TLS_PKI
  export HOSTNAME="$HOSTNAME"
  export LDAP_DN="$LDAP_DN"
  export LDAP_SUFFIX="$LDAP_SUFFIX"
  export DIR_SCRIPTS="$DIR_SCRIPTS"
}

appSetup () {
  # Get config parameters - moved for easier reading
  config

  sed -e "s:{{ UDOMAIN }}:$UDOMAIN:" \
    -e "s:{{ LDOMAIN }}:$LDOMAIN:" \
    -e "s:{{ HOSTNAME }}:$HOSTNAME:" \
    -i "$FILE_KRB5"

  if [[ ! -d /etc/samba/external/ ]]; then
    mkdir /etc/samba/external
  fi

  #Check if DOMAIN_NETBIOS <15 chars and contains no "."
  if [[ ${#DOMAIN_NETBIOS} -gt 15 ]]; then
    echo "DOMAIN_NETBIOS too long => exiting" && exit 1
  fi
  if [[ $DOMAIN_NETBIOS == *"."* ]]; then
    echo "DOMAIN_NETBIOS contains forbiden char    .     => exiting" && exit 1
  fi

  # If multi-site, we need to connect to the VPN before joining the domain
  if [[ ${JOIN_SITE_VPN,,} = true ]]; then
    /usr/sbin/openvpn --config ${FILE_OPENVPNCONF} &
    VPNPID=$!
    echo "Sleeping 30s to ensure VPN connects ($VPNPID)";
    sleep 30
  fi

  if [[ ${ENABLE_RFC2307,,} = true ]]; then
    if [[ "$JOIN" = true ]];then
      OPTION_RFC=--option='idmap_ldb:use rfc2307 = yes'
    else
      OPTION_RFC=--use-rfc2307
    fi
  fi

  if [[ "$HOSTIP" != "NONE" ]]; then
    OPTION_HOSTIP=--host-ip="${HOSTIP}"
  fi

  if [[ "$JOIN_SITE" != "NONE" ]]; then
    OPTION_JOIN=--site="${JOIN_SITE}"
  fi

  if [[ ${ENABLE_BIND_INTERFACE,,} = true ]]; then
    OPTION_INT=--option="interfaces=${BIND_INTERFACES,,} lo"
    OPTION_BIND=--option="bind interfaces only = yes"
  fi

  if [[ ${ENABLE_DEBUG,,} = true ]]; then
    SAMBA_DEBUG_OPTION="-d $DEBUG_LEVEL"
    SAMBADAEMON_DEBUG_OPTION="--debug-stdout -d $DEBUG_LEVEL"
    NTP_DEBUG_OPTION="-D $DEBUG_LEVEL"
    sed -e "s:{{ SAMBADAEMON_DEBUG_OPTION }}:$SAMBADAEMON_DEBUG_OPTION:" -i "${FILE_SUPERVISORD_CUSTOM_CONF}"
    sed -e "s:{{ NTP_DEBUG_OPTION }}:$NTP_DEBUG_OPTION:" -i "${FILE_SUPERVISORD_CUSTOM_CONF}"
  fi

  if [[ "$ENABLE_DNSFORWARDER" != "NONE" ]]; then
    OPTION_DNS_FWD=--option="dns forwarder=${ENABLE_DNSFORWARDER}"
  fi

  if [[ "$ENABLE_DYNAMIC_PORTRANGE" != "NONE" ]]; then
    OPTION_RPC=--option="rpc server dynamic port range = ${ENABLE_DYNAMIC_PORTRANGE}"
  fi

  # If the finished file (external/smb.conf) doesn't exist, this is new container with empty volume, we're not just moving to a new container
  if [[ ! -f /etc/samba/external/smb.conf ]]; then
    if [[ -f /etc/samba/smb.conf ]]; then
      mv /etc/samba/smb.conf /etc/samba/smb.conf.orig
    fi
    # Optional params encased with "" will break the command
    if [[ ${JOIN,,} = true ]]; then
#     if [ "$(dig +short -t srv _ldap._tcp.$LDOMAIN.)" ] && echo "got answer"
      s=1
      until [ $s = 0 ]
      do
        samba-tool domain join "${LDOMAIN}" DC -U"${DOMAIN_NETBIOS}"\\"${DOMAIN_USER}" ${OPTION_RFC} --password="${DOMAIN_PASS}" "${OPTION_JOIN}" '--dns-backend=SAMBA_INTERNAL' ${SAMBA_DEBUG_OPTION} ${OPTION_INT} ${OPTION_BIND} ${OPTION_DNS_FWD} ${OPTION_RPC} && s=0 && break || s=$? && sleep 60
      done; (exit $s)
#      # Netlogon & sysvol readonly on secondary DC
#      {
#        echo " "
#        echo "[netlogon]"
#        echo "path = /var/lib/samba/sysvol/test.dom/scripts"
#        echo "read only = Yes"
#        echo " "
#        echo "[sysvol]"
#        echo "path = /var/lib/samba/sysvol"
#        echo "read only = Yes"
#      } >> "${FILE_SAMBA_CONF}"

      #Check if Join was successfull
      if host -t A "$HOSTNAME"."$LDOMAIN".;then
        echo "found DNS host record"
      else
        echo "no DNS host record found. Pls see https://wiki.samba.org/index.php/Verifying_and_Creating_a_DC_DNS_Record#Verifying_and_Creating_the_objectGUID_Record"
      fi

    else
      samba-tool domain provision --domain="${DOMAIN_NETBIOS}" --realm="${UDOMAIN}" "${OPTION_JOIN}" --adminpass="${DOMAIN_PASS}" --host-name="${HOSTNAME}" --server-role=dc --dns-backend=SAMBA_INTERNAL ${OPTION_INT} ${OPTION_BIND} ${OPTION_HOSTIP} ${OPTION_DNS_FWD} ${OPTION_RFC} ${SAMBA_DEBUG_OPTION} ${OPTION_RPC}
#
#
#
#
#
# if hostip is set use external network ip to calc reverse zone
#add reverse zone & add site & add ip network to site
      #echo 411.311.211.111 | awk -F. '{print $4"."$3"." $2"."$1}'
      if [[ "$RECYCLEBIN" = true ]]; then
        # https://gitlab.com/samba-team/samba/-/blob/master/source4/scripting/bin/enablerecyclebin
        python3 /scripts/enablerecyclebin.py "${FILE_SAMLDB}"
      fi

      if [[ "$CHANGE_KRB_TGT_PW" = true ]]; then
        {
          echo ""
          echo "[program:ChangeKRBTGT]"
          echo "command=/bin/sh /scripts/chgkrbtgtpass.sh"
          echo "stdout_logfile=/dev/fd/1"
          echo "stdout_logfile_maxbytes=0"
          echo "stdout_logfile_backups=0"
          echo "redirect_stderr=true"
          echo "priority=99"
        } >> "${FILE_SUPERVISORD_CUSTOM_CONF}"
      fi
      
      if [[ ! -d /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/ ]]; then
        mkdir -p /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/en-US
        mkdir /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/de-DE
      fi

      # Set default uid and gid for ad user and groups, based on IMAP_GID_START value
      if [[ ${DISABLE_PW_COMPLEXITY,,} = true ]]; then
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

        sed -e "s: {{ LDAP_SUFFIX }}:$LDAP_SUFFIX:g" \
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
          "${FILE_SAMBA_SCHEMA_RFC}.j2" > "${FILE_SAMBA_SCHEMA_RFC}"

        ldbmodify -H "${FILE_SAMLDB}" "${FILE_SAMBA_SCHEMA_RFC}" -U "${DOMAIN_USER}"
      fi

      #Microsoft Local Administrator Password Solution (LAPS)
      if [[ ${DISABLE_PW_COMPLEXITY,,} = true ]]; then
        sed -e "s: {{ LDAP_SUFFIX }}:$LDAP_SUFFIX:g" \
          "${FILE_SAMBA_SCHEMA_LAPS1}.j2" > "${FILE_SAMBA_SCHEMA_LAPS1}"
        sed -e "s: {{ LDAP_SUFFIX }}:$LDAP_SUFFIX:g" \
          "${FILE_SAMBA_SCHEMA_LAPS2}.j2" > "${FILE_SAMBA_SCHEMA_LAPS2}"
        ldbadd -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_LAPS1}" -U "${DOMAIN_USER}"
        ldbmodify -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_LAPS2}" -U "${DOMAIN_USER}"
      fi

      if [[ ${DISABLE_PW_COMPLEXITY,,} = true ]]; then
        samba-tool domain passwordsettings set --complexity=off "${SAMBA_DEBUG_OPTION}"
        samba-tool domain passwordsettings set --history-length=0 "${SAMBA_DEBUG_OPTION}"
        samba-tool domain passwordsettings set --min-pwd-age=0 "${SAMBA_DEBUG_OPTION}"
        samba-tool domain passwordsettings set --max-pwd-age=0 "${SAMBA_DEBUG_OPTION}"
      fi
    fi

    #Prevent https://wiki.samba.org/index.php/Samba_Member_Server_Troubleshooting => SeDiskOperatorPrivilege can't be set
    if [ ! -f "${FILE_SAMBA_USER_MAP}" ]; then
      echo '!'"root = ${DOMAIN}\\${DOMAIN_USER}" > "${FILE_SAMBA_USER_MAP}"
      sed -i "/\[global\]/a \
        \\\tusername map = ${FILE_SAMBA_USER_MAP}\
      " "${FILE_SAMBA_CONF}"
    fi

#    if [[ ${ENABLE_DNSFORWARDER} != "NONE" ]]; then
#      sed -i '/dns forwarder/d' "${FILE_SAMBA_CONF}"
#      sed -i "/\[global\]/a \
#        \\\tdns forwarder = ${ENABLE_DNSFORWARDER}\
#      " "${FILE_SAMBA_CONF}"
#    fi

    if [[ ${ENABLE_MSCHAPV2,,} = true ]]; then
      sed -i "/\[global\]/a \
        \\\tntlm auth = mschapv2-and-ntlmv2-only\
      " "${FILE_SAMBA_CONF}"
    fi

    if [[ ${ENABLE_CUPS,,} = true ]]; then
      sed -i "/\[global\]/a \
        \\\tload printers = yes\\n\
        \\tprinting = cups\\n\
	\\tprintcap name = cups\\n\
	\\tshow add printer wizard = no\\n\
        \\tcups encrypt = no\\n\
        \\tcups options = \"raw media=a4\"\\n\
        \\t#cups server = ${CUPS_SERVER}:${CUPS_PORT}\
      " "${FILE_SAMBA_CONF}"	
	  {
	    echo ""
		echo "[printers]"
		echo "comment = All Printers"
        echo "path = /var/spool/samba"
        echo "printable = yes"
		echo "use client driver = Yes"
		echo "guest ok = Yes"
		echo "browseable = No"
	  } >> "${FILE_SAMBA_CONF}"
    else
      sed -i "/\[global\]/a \
        \\\tload printers = no\\n\
        \\tprinting = bsd\\n\
        \\tprintcap name = /dev/null\\n\
        \\tdisable spoolss = yes\
      " "${FILE_SAMBA_CONF}"
    fi

    if [[ ${DISABLE_MD5,,} = true ]]; then
      # Prevent downgrade attacks to md5
      sed -i "/\[global\]/a \
        \\\treject md5 clients = yes\\n\
        \\treject md5 servers = yes\\n\
      " "${FILE_SAMBA_CONF}"
    fi

    if [[ ${ENABLE_INSECURE_LDAP,,} = true ]]; then
      sed -i "/\[global\]/a \
        \\\tldap server require strong auth = no\
      " "${FILE_SAMBA_CONF}"
    fi

    # https://samba.tranquil.it/doc/en/samba_advanced_methods/samba_active_directory_higher_security_tips.html#generating-additional-password-hashes
    sed -i "/\[global\]/a \
      \\\t#wins support = yes\\n\
      \\tpassword hash userPassword schemes = CryptSHA256 CryptSHA512\\n\
      \\t# Template settings for login shell and home directory\\n\
      \\ttemplate shell = /bin/bash\\n\
      \\ttemplate homedir = /home/%U\
    " "${FILE_SAMBA_CONF}"

    # nsswitch anpassen
    sed -i "s,passwd:.*,passwd:         files winbind,g" "$FILE_NSSWITCH"
    sed -i "s,group:.*,group:          files winbind,g" "$FILE_NSSWITCH"
    sed -i "s,hosts:.*,hosts:          files dns,g" "$FILE_NSSWITCH"
    sed -i "s,networks:.*,networks:      files dns,g" "$FILE_NSSWITCH"

    # Once we are set up, we'll make a file so that we know to use it if we ever spin this up again
    cp -f "${FILE_SAMBA_CONF}" "${FILE_SAMBA_CONF_EXTERNAL}"
  else
    cp -f "${FILE_SAMBA_CONF_EXTERNAL}" "${FILE_SAMBA_CONF}"
  fi

  # Stop VPN & write supervisor service
  if [[ ${JOIN_SITE_VPN,,} = true ]]; then
    if [[ -n $VPNPID ]]; then
      kill $VPNPID
    fi
    {
      echo ""
      echo "[program:openvpn]"
      echo "command=/usr/sbin/openvpn --config $FILE_OPENVPNCONF"
      echo "stdout_logfile=/dev/fd/1"
      echo "stdout_logfile_maxbytes=0"
      echo "stdout_logfile_backups=0"
      echo "redirect_stderr=true"
      echo "priority=1"
    } >> "${FILE_SUPERVISORD_CUSTOM_CONF}"
  fi

   if [ "${ENABLE_TLS,,}" = true ]; then
    if [ ! -f tls/key.pem ] && [ ! -f tls/key.pem ] && [ ! -f tls/cert.pem ]; then
      print "No custom CA found. Samba will autogenerate one"
    fi
    if [ ! -f /var/lib/samba/private/tls/dh.key ]; then
      openssl dhparam -out /var/lib/samba/private/tls/dh.key 2048
    fi
    sed -i "/\[global\]/a \
      \\\ttls enabled  = yes\\n\
      \\ttls keyfile  = tls/key.pem\\n\
      \\ttls certfile = tls/cert.pem\\n\
      \\t#tls cafile   = tls/intermediate.pem\\n\
      \\ttls cafile   = tls/ca.pem\\n\
      \\ttls dh params file = tls/dh.key\\n\
      \\t#tls crlfile   = tls/crl.pem\\n\
      \\t#tls verify peer = ca_and_name\
    " "${FILE_SAMBA_CONF}"
  fi

  #NTP Settings
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
    -i "$FILE_NTP"

  # Own socket
  mkdir -p /var/lib/samba/ntp_signd/
  chown root:ntp /var/lib/samba/ntp_signd/
  chmod 750 /var/lib/samba/ntp_signd/

# Not needed on Samba 4.15 with ubuntu:devel
#  if [[ ! -d /var/lib/samba/winbindd_privileged/ ]]; then
#    mkdir /var/lib/samba/winbindd_privileged/
#    chown root:winbindd_priv /var/lib/samba/winbindd_privileged/
#    chmod 0750 /var/lib/samba/winbindd_privileged
#  else
#    chown root:winbindd_priv /var/lib/samba/winbindd_privileged/
#    chmod 0750 /var/lib/samba/winbindd_privileged
#  fi

    if [[ ${ENABLE_LOGS,,} = true ]]; then
      sed -i "/\[global\]/a \
        \\\tlog file = /var/log/samba/%m.log\\n\
        \\tmax log size = 10000\\n\
        \\tlog level = ${DEBUG_LEVEL}\
      " /etc/samba/smb.conf
	  sed -i '/FILE:/s/^#//g' "$FILE_KRB5"
	  sed -i '/FILE:/s/^#_//g' "$FILE_NTP"
    fi

    #if [ "${ENABLE_BIND_INTERFACE,,}" = true ]; then
      #    sed -i "/\[global\]/a \
        #interfaces =${BIND_INTERFACES,,} lo\\n\
        #bind interfaces only = yes\
        #    " /etc/samba/smb.conf
    #  printf >> "interface listen lo" "$FILE_NTP"
    #  for INTERFACE in $BIND_INTERFACES
    #  do
    #    printf >> "interface listen $INTERFACE"
    #  done
    #fi
  appFirstStart
}

appFirstStart () {
 source /scripts/firstrun.sh
}

appStart () {
  update-ca-certificates
  loadconfdir
  config
  /usr/bin/supervisord -c "${FILE_SUPERVISORD_CONF}"
}

#https://gist.github.com/meetnick/fb5587d25d4174d7adbc8a1ded642d3c
loadconfdir () {
# adds includes.conf file existance to smb.conf file
  if ! grep -q 'include = '"${SMB_INCLUDES}" "${FILE_SAMBA_CONF}" ; then
    sed -i "/\[global\]/a \
      \\\tinclude = ${SMB_INCLUDES}\
    " "${FILE_SAMBA_CONF}"
  fi

  # create directory smb.conf.d to store samba .conf files
  mkdir -p "$SMB_CONF_DIR"

  # populates includes.conf with files in smb.conf.d directory
  find "${DIR_SAMBA_CONF_DIR}" -maxdepth 1 | sed -e 's/^/include = /' > "$SMB_INCLUDES"
}

# If the supervisor conf isn't there, we're spinning up a new container
if [[ -f "${FILE_SAMBA_CONF_EXTERNAL}" ]]; then
  cp "${FILE_SAMBA_CONF_EXTERNAL}" "${FILE_SAMBA_CONF}"
  appStart
else
  appSetup
fi

exit 0