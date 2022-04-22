#!/bin/bash
/usr/bin/supervisord -c "/etc/supervisor/supervisord.conf" &
  
#You want to set SeDiskOperatorPrivilege on your member server to manage your share permissions:
net rpc rights grant "$UDOMAIN\Domain Admins" SeDiskOperatorPrivilege -U"$UDOMAIN\${DOMAINUSER,,}" "${DEBUG_OPTION}"