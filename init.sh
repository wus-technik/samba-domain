#!/bin/bash

set -x

#Todo:
# ID_Map replication: https://wiki.samba.org/index.php/Joining_a_Samba_DC_to_an_Existing_Active_Directory#Built-in_User_.26_Group_ID_Mappings
# SYSVOL replication:
# Add the following line to allow a subnet to receive time service and query server statistics:  https://support.ntp.org/bin/view/Support/AccessRestrictions#Section_6.5.1.1.3.
# time sync as client (beim join)

appSetup () {

  # Set variables
  DOMAIN=${DOMAIN:-SAMDOM.LOCAL}
  DOMAINUSER=${DOMAINUSER:-Administrator}
  DOMAINPASS=${DOMAINPASS:-youshouldsetapassword}
  DOMAIN_NETBIOS=${DOMAIN_NETBIOS:-$URDOMAIN}

  LDOMAIN=${DOMAIN,,} #alllowercase
  UDOMAIN=${DOMAIN^^} #ALLUPPERCASE
  URDOMAIN=${UDOMAIN%%.*} #trim

  #Posix
  #LDOMAIN=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]')
  #UDOMAIN=$(echo "$LDOMAIN" | tr '[:lower:]' '[:upper:]')
  #URDOMAIN=$(echo "$UDOMAIN" | cut -d "." -f1)

  #DN for LDIF
  LDAPSUFFIX=""
  IFS='.'
  for dn in ${LDOMAIN}; do
    LDAPSUFFIX="${LDAPSUFFIX},DC=$dn"
  done
  IFS=''

  NTPSERVERLIST=${NTPSERVERLIST:-0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org}

  JOINSITE=${JOINSITE:-Default-First-Site-Name}
  JOIN=${JOIN:-false}
  MULTISITE=${MULTISITE:-false}

  HOSTIP=${HOSTIP:-NONE}
  #Change if hostname includes DNS/DOMAIN SUFFIX e.g. host.example.com - it should only display host
  HOSTNAME=${HOSTNAME:-$(hostname)}
  export HOSTNAME="$HOSTNAME"

  ENABLE_TLS=${ENABLE_TLS:-false}
  TLS_PKI=${TLS_PKI:-false}
  PKI_O=${PKI_O:-Simple Root CA}
  PKI_OU=${PKI_OU:-Samba}
  PKI_CN=${PKI_CN:-Simple Samba Root CA}

  DISABLE_PRINTING=${DISABLE_PRINTING:-true}
  DISABLE_MD5=${DISABLE_MD5:-true}
  DISABLE_PWCOMPLEXITY=${DISABLE_PWCOMPLEXITY:-false}

  ENABLE_DYNAMIC_PORTRANGE=${ENABLE_DYNAMIC_PORTRANGE:-49152-49172} # Set DynamicPortRange
  ENABLE_DNSFORWARDER=${ENABLE_DNSFORWARDER:-NONE}
  ENABLE_LOGS=${ENABLE_LOGS:-false}
  ENABLE_INSECURELDAP=${ENABLE_INSECURELDAP:-false}
  ENABLE_LAPSSCHEMA=${ENABLE_LAPSSCHEMA:-true}
  ENABLE_RFC2307=${ENABLE_RFC2307:-true}
  ENABLE_MSCHAPV2=${ENABLE_MSCHAPV2:-false}
  ENABLE_RECYCLEBIN=${ENABLE_RECYCLEBIN:-false}

  ENABLE_DEBUG=${ENABLE_DEBUG:-true}
  DEBUGLEVEL=${DEBUGLEVEL:-1}

  ENABLE_BIND_INTERFACE=${ENABLE_BIND_INTERFACE:-false}
  BIND_INTERFACES=${BIND_INTERFACES:-eth0} # Can be a list of interfaces

  #file variables
  DIR_SAMBADATAPREFIX=/var/lib/samba
  DIR_SCRIPTS=/scripts
  FILE_SAMBAPRIV_BASE=$DIR_SAMBADATAPREFIX/private
  FILE_PKI_DH=$FILE_SAMBAPRIV_BASE/tls/dh.key
  FILE_PKI_CA=$FILE_SAMBAPRIV_BASE/tls/ca.pem
  FILE_PKI_KEY=$FILE_SAMBAPRIV_BASE/tls/key.pem
  FILE_PKI_CERT=$FILE_SAMBAPRIV_BASE/tls/cert.pem
  FILE_PKI_INT=$FILE_SAMBAPRIV_BASE/tls/intermediate.pem
  FILE_PKI_CRL=$FILE_SAMBAPRIV_BASE/tls/crl.pem
  FILE_SAMLDB=$FILE_SAMBAPRIV_BASE/sam.ldb
  FILE_SAMBACONF=/etc/samba/smb.conf
  FILE_SAMBACONFEXTERNAL=/etc/samba/external/smb.conf

  FILE_SUPERVISORDCONF=/etc/supervisor/conf.d/supervisord.conf
  FILE_OPENVPNCONF=/docker.ovpn
  FILE_KRB5=/etc/krb5.conf
  FILE_NSSWITCH=/etc/nsswitch.conf

  # Min Counter Values for NIS Attributes. Set in docker-compose if you want a different start
  # IT does nothing on DCs as they shall not use idmap settings.
  # Using the same Start and stop values on members however gets the RFC2307 attributs (NIS) rights
  # idmap config {{ URDOMAIN }} : range = {{ IDMIN }}-{{ IDMAX }}
  IMAP_ID_START=${IMAP_UID_START:-10000}
  IMAP_UID_START=${IMAP_UID_START:-$IMAP_ID_START}
  IMAP_GID_START=${IMAP_GID_START:-$IMAP_ID_START}

  #Check if DOMAIN_NETBIOS <15 chars and contains no "."
  if [[ ${#DOMAIN_NETBIOS} -gt 15 ]]; then
    echo "DOMAIN_NETBIOS too long => exiting" && exit 1
  fi
  if [[ $DOMAIN_NETBIOS == *"."* ]]; then
    echo "DOMAIN_NETBIOS contains forbiden char    .     => exiting" && exit 1
  fi

  # If multi-site, we need to connect to the VPN before joining the domain
  if [[ ${MULTISITE,,} = true ]]; then
    /usr/sbin/openvpn --config ${FILE_OPENVPNCONF} &
    VPNPID=$!
    echo "Sleeping 30s to ensure VPN connects ($VPNPID)";
    sleep 30
  fi

  if [[ "$ENABLE_RFC2307" = true ]]; then
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
  if [[ "$ENABLE_DNSFORWARDER" != "NONE" ]]; then
    OPTION_DNS_FWD=--option="dns forwarder=${ENABLE_DNSFORWARDER}"
  fi

  if [[ "$ENABLE_BIND_INTERFACE" = true ]]; then
    OPTION_INT=--option="interfaces=${BIND_INTERFACES,,} lo"
    OPTION_BIND=--option="bind interfaces only = yes"
  fi

  if [[ "$ENABLE_DYNAMIC_PORTRANGE" != "NONE" ]]; then
    OPTION_RPC=--option="rpc server dynamic port range = ${ENABLE_DYNAMIC_PORTRANGE}"
  fi

  if [[ "$ENABLE_DEBUG" = true ]]; then
    SAMBA_DEBUG_OPTION="-d $DEBUGLEVEL"
    SAMBADAEMON_DEBUG_OPTION="--debug-stdout -d $DEBUGLEVEL"
    NTP_DEBUG_OPTION="-D $DEBUGLEVEL"
    sed -e "s:{{ SAMBADAEMON_DEBUG_OPTION }}:$SAMBADAEMON_DEBUG_OPTION:" -i "${FILE_SUPERVISORDCONF}"
    sed -e "s:{{ NTP_DEBUG_OPTION }}:$NTP_DEBUG_OPTION:" -i "${FILE_SUPERVISORDCONF}"
  fi

  if [[ ! -d /etc/samba/external/ ]]; then
    mkdir /etc/samba/external
  fi

  sed -e "s:{{ UDOMAIN }}:$UDOMAIN:" \
    -e "s:{{ LDOMAIN }}:$LDOMAIN:" \
    -e "s:{{ HOSTNAME }}:$HOSTNAME:" \
    -i "$FILE_KRB5"

  # If the finished file (external/smb.conf) doesn't exist, this is new container with empty volume, we're not just moving to a new container
  if [[ ! -f "${FILE_SAMBACONFEXTERNAL}" ]]; then
    if [[ -f "${FILE_SAMBACONF}" ]]; then
      mv "${FILE_SAMBACONF}" "${FILE_SAMBACONF}".orig
    fi
    # NOTE: DO not escape the missing variables below with "" it will break syntax
    # Optional params without "" will break the command
    if [[ ${JOIN,,} = true ]]; then
#     if [ "$(dig +short -t srv _ldap._tcp.$LDOMAIN.)" ] && echo "got answer"
      n=0
      until [ "$n" -eq 9 ]
      do
        samba-tool domain join "${LDOMAIN}" DC -U"${DOMAIN_NETBIOS}"\\"${DOMAINUSER}" ${OPTION_RFC} --password="${DOMAINPASS}" "${OPTION_JOIN}" '--dns-backend=SAMBA_INTERNAL' ${SAMBA_DEBUG_OPTION} ${OPTION_INT} ${OPTION_BIND} ${OPTION_DNS_FWD} ${OPTION_RPC} && s=0 && break || s=$? && sleep 60
        n=$(($n+1))
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
      } >> "${FILE_SAMBACONF}"
      #Check if Join was successfull
      if host -t A "$HOSTNAME"."$LDOMAIN".;then
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
      samba-tool domain provision --domain="${DOMAIN_NETBIOS}" --realm="${UDOMAIN}" "${OPTION_JOIN}" --adminpass="${DOMAINPASS}" --host-name="${HOSTNAME}" --server-role=dc --dns-backend=SAMBA_INTERNAL ${OPTION_INT} ${OPTION_BIND} ${OPTION_HOSTIP} ${OPTION_DNS_FWD} ${OPTION_RFC} ${SAMBA_DEBUG_OPTION} ${OPTION_RPC}

      if [[ "$ENABLE_RECYCLEBIN" = true ]]; then
        # https://gitlab.com/samba-team/samba/-/blob/master/source4/scripting/bin/enablerecyclebin
        python3 /scripts/enablerecyclebin.py "${FILE_SAMLDB}"
      fi

      {
        echo ""
        echo "[program:ChangeKRBTGT]"
        echo "command=/bin/sh /scripts/chgkrbtgtpass.sh"
        echo "stdout_logfile=/dev/fd/1"
        echo "stdout_logfile_maxbytes=0"
        echo "stdout_logfile_backups=0"
        echo "redirect_stderr=true"
        echo "priority=99"
      } >> "${FILE_SUPERVISORDCONF}"

      if [[ ! -d /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/ ]]; then
        mkdir -p /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/en-US
        mkdir /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/de-DE
      fi
      # Set default uid and gid for ad user and groups, based on IMAP_GID_START value
      if [[ "$ENABLE_RFC2307" = true ]]; then
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

        sed -e "s: {{ LDAPDN }}:$LDAPSUFFIX:g" \
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

        ldbmodify -H "${FILE_SAMLDB}" /ldif/RFC_Domain_User_Group.ldif -U "${DOMAINUSER}"
      fi
      #Microsoft Local Administrator Password Solution (LAPS)
      if [[ "$ENABLE_LAPSSCHEMA" = true ]]; then
        sed -e "s: {{ LDAPDN }}:$LDAPSUFFIX:g" \
          /ldif/laps-1.ldif.j2 > /ldif/laps-1.ldif
        sed -e "s: {{ LDAPDN }}:$LDAPSUFFIX:g" \
          /ldif/laps-2.ldif.j2 > /ldif/laps-2.ldif
        ldbadd -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true /ldif/laps-1.ldif -U "${DOMAINUSER}"
        ldbmodify -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true /ldif/laps-2.ldif -U "${DOMAINUSER}"
      fi

      if [[ ${DISABLE_PWCOMPLEXITY,,} = true ]]; then
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
    " "${FILE_SAMBACONF}"
    fi

    if [[ $ENABLE_DNSFORWARDER != "NONE" ]]; then
      sed -i '/dns forwarder/d' "${FILE_SAMBACONF}"
      sed -i "/\[global\]/a \
        \\\tdns forwarder = ${ENABLE_DNSFORWARDER}\
        " "${FILE_SAMBACONF}"
    fi

    if [[ ${ENABLE_TLS,,} = true ]]; then
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
    " "${FILE_SAMBACONF}"
    fi

    if [[ ${ENABLE_MSCHAPV2,,} = true ]]; then
      sed -i "/\[global\]/a \
ntlm auth = mschapv2-and-ntlmv2-only\
    " "${FILE_SAMBACONF}"
    fi

# https://samba.tranquil.it/doc/en/samba_advanced_methods/samba_active_directory_higher_security_tips.html#generating-additional-password-hashes
    sed -i "/\[global\]/a \
#wins support = yes\\n\
password hash userPassword schemes = CryptSHA256 CryptSHA512\\n\
# Template settings for login shell and home directory\\n\
template shell = /bin/bash\\n\
template homedir = /home/%U\
    " "${FILE_SAMBACONF}"

    if [[ ${DISABLE_PRINTING,,} = true ]]; then
      sed -i "/\[global\]/a \
load printers = no\\n\
printing = bsd\\n\
printcap name = /dev/null\\n\
disable spoolss = yes\
    " "${FILE_SAMBACONF}"
    fi

    if [[ ${DISABLE_MD5,,} = true ]]; then
      # Prevent downgrade attacks to md5
      sed -i "/\[global\]/a \
reject md5 clients = yes\\n\
reject md5 servers = yes\\n\
    " "${FILE_SAMBACONF}"
    fi

    if [[ ${ENABLE_INSECURELDAP,,} = true ]]; then
      sed -i "/\[global\]/a \
ldap server require strong auth = no\
      " "${FILE_SAMBACONF}"
    fi

    # nsswitch anpassen
    sed -i "s,passwd:.*,passwd:         files winbind,g" "$FILE_NSSWITCH"
    sed -i "s,group:.*,group:          files winbind,g" "$FILE_NSSWITCH"
    sed -i "s,hosts:.*,hosts:          files dns,g" "$FILE_NSSWITCH"
    sed -i "s,networks:.*,networks:      files dns,g" "$FILE_NSSWITCH"

    # Once we are set up, we'll make a file so that we know to use it if we ever spin this up again
    cp -f "${FILE_SAMBACONF}" "${FILE_SAMBACONFEXTERNAL}"
  else
    cp -f "${FILE_SAMBACONFEXTERNAL}" "${FILE_SAMBACONF}"
  fi
    # https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller
    #Test Kerberos
    if echo "${DOMAINPASS}" | kinit "${DOMAINUSER}";then
      echo " kinit successfull"
      klist
    fi
    # Verify Samba Fileserver is working
    #smbclient -L localhost -N
    # Test Samba Auth
    #smbclient //localhost/netlogon -U"${DOMAINUSER}" -c 'ls' --password "${DOMAINPASS}"

  # Stop VPN & write supervisor service
  if [[ ${MULTISITE,,} = true ]]; then
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
    } >> "${FILE_SUPERVISORDCONF}"
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

# Not needed on Samba 4.15 with ubuntu:devel
#  if [[ ! -d /var/lib/samba/winbindd_privileged/ ]]; then
#    mkdir /var/lib/samba/winbindd_privileged/
#    chown root:winbindd_priv /var/lib/samba/winbindd_privileged/
#    chmod 0750 /var/lib/samba/winbindd_privileged
#  else
#    chown root:winbindd_priv /var/lib/samba/winbindd_privileged/
#    chmod 0750 /var/lib/samba/winbindd_privileged
#  fi

#    if [[ ${ENABLE_LOGS,,} = true ]]; then
#      sed -i "/\[global\]/a \
#log file = /var/log/samba/%m.log\\n\
#max log size = 10000\\n\
#log level = 1\
#      " /etc/samba/smb.conf
#    else
#      sed -i "/\[global\]/a \
#log level = 0\\n\
#      " /etc/samba/smb.conf
#sed -i '/FILE:/s/^#//g' "$FILE_KRB5"
#    fi

    #if [ "${ENABLE_BIND_INTERFACE,,}" = true ]; then
      #    sed -i "/\[global\]/a \
        #interfaces =${BIND_INTERFACES,,} lo\\n\
        #bind interfaces only = yes\
        #    " /etc/samba/smb.conf
    #  printf >> "interface listen lo" /etc/ntp.conf
    #  for INTERFACE in $BIND_INTERFACES
    #  do
    #    printf >> "interface listen $INTERFACE"
    #  done
    #fi
    ###################
    # limit dynamic rpc port from 49152-65535 to 49172 so we can proxy them (otherwise we run out of memory)
    #sed -i "/\[global\]/a \
#rpc server dynamic port range = 49152-49172\
#        " "${FILE_SAMBACONF}"
    ###################
  appFirstStart
}

appFirstStart () {
  #You want to set SeDiskOperatorPrivilege on your member server to manage your share permissions:
  net rpc rights grant "$UDOMAIN\Domain Admins" SeDiskOperatorPrivilege -U"$UDOMAIN\${DOMAINUSER,,}" "${DEBUG_OPTION}"
  /usr/bin/supervisord -c "/etc/supervisor/supervisord.conf"
}

appStart () {
  /usr/bin/supervisord
}

# If the supervisor conf isn't there, we're spinning up a new container
if [[ -f "${FILE_SAMBACONFEXTERNAL}" ]]; then
  cp "${FILE_SAMBACONFEXTERNAL}" "${FILE_SAMBACONF}"
  appStart
else
  appSetup
fi

exit 0