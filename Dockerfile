FROM ubuntu:devel

LABEL maintainer="Fmstrat <fmstrat@NOSPAM.NO>"

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
	#openssl for dh key
    && apt-get install -y ntp pkg-config attr acl samba smbclient tdb-tools ldb-tools ldap-utils winbind libnss-winbind libpam-winbind libpam-krb5 krb5-user supervisor dnsutils \
    # line below is for multi-site config (ping is for testing later) \
    #&& apt-get install -y openvpn inetutils-ping \   
    && apt-get clean autoclean \
    && apt-get autoremove --yes \
    && rm -rf /var/lib/{apt,dpkg,cache,log}/ \
    && rm -fr /tmp/* /var/tmp/*

COPY /ldif /ldif/
COPY /etc /etc/
COPY /scripts /scripts/

RUN chmod -R +x /scripts/

# DNS
EXPOSE 53/tcp
EXPOSE 53/udp

# Kerberos
EXPOSE 88/tcp
EXPOSE 88/udp

# NTP
EXPOSE 123/udp

# End Point Mapper (DCE/RPC Locator Service) 
EXPOSE 135/tcp

# NetBIOS Name Service
EXPOSE 137/udp

# NetBIOS Datagram Service
EXPOSE 138/udp

# NetBIOS Session Service
EXPOSE 139/tcp

# LDAP
EXPOSE 389/tcp
EXPOSE 389/udp

# SMB over TCP
EXPOSE 445/tcp

# Kerberos Change/Set password
EXPOSE 464/tcp
EXPOSE 464/udp

# LDAPS
EXPOSE 636/tcp

# msft-gc, Microsoft Global Catalog
EXPOSE 3268/tcp

# msft-gc, Microsoft Global Catalog over SSL
EXPOSE 3269/tcp

# Dynamic RPC Ports # LIMITED TO 18 CONNECTIONS FOR SMALL ARM PROXY DEVICES
# EXPOSE 49152-65535/tcp
EXPOSE 49152-49170/tcp

WORKDIR /

HEALTHCHECK CMD smbcontrol smbd num-children || exit 1

ENTRYPOINT ["bash", "/scripts/init.sh"]