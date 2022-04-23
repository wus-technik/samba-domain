#!/bin/bash
update-ca-certificates
/usr/bin/supervisord -c "${FILE_SUPERVISORD_CONF}" &

if [[ ${JOIN,,} = false ]];then
  # Better check if net rpc is rdy
  wait 180
  #You want to set SeDiskOperatorPrivilege on your member server to manage your share permissions:
  net rpc rights grant "$UDOMAIN"\\"Domain Admins" 'SeDiskOperatorPrivilege' -U"$UDOMAIN"\\"${DOMAIN_USER,,}" ${DEBUG_OPTION}
else
  if [ -f /var/lib/private/sambe/wins_config.ldb ] && [ ENABLE_WINS = true ];then
  ldbadd -H wins_config.ldb /ldif/wins.ldif
fi
# https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller
#Test Kerberos
if echo "${DOMAIN_PASS}" | kinit "${DOMAIN_USER}";then
  echo " kinit successfull"
  klist
fi
# Verify Samba Fileserver is working
smbclient -L localhost -N
# Test Samba Auth
smbclient //localhost/netlogon -U"${DOMAIN_USER}" -c 'ls' --password "${DOMAIN_PASS}"
wait