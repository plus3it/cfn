#!/bin/sh
#
# Description:
#    This script is intended to aid an administrator in quickly
#    setting up a baseline configuration of the Guacamole
#    management-protocol HTTP-tunneling service. When the script
#    exits successfully:
#    * The Tomcat6 servlet-service will have been downloaded and
#      enabled
#    * The Guacamole service will have been configured to tunnel
#      SSH based connections to the Guacamole host to a remote,
#      HTML 5 compliant web browser.
#    * Apache will have been configured to provide a proxy of
#      all public-facing port 80/tcp traffic to the Guacamole
#      servlet listening at localhost port 8080/tcp
#    * A internally-mapped (via /etc/guacamole/user-mapping.xml)
#      account will have been created to password protect the
#      front-end guacamole service
#    * An operating system user account will have been created
#      and password-enabled to allow login to the hosting-OS
#      from the Guacamole interface. The useraccount will also
#      have been granted passwordless sudoers access to root
#
#################################################################
/usr/sbin/useradd sshuser
/usr/sbin/usermod -p $(python -c "import random,string,crypt,getpass,pwd; randomsalt = ''.join(random.sample(string.ascii_letters,8)); print crypt.crypt('P@ssw0rd', '\$6\$%s))\$' % randomsalt)"
) sshuser
printf "sshuser\tALL=(root)\tNOPASSWD:ALL\n" > /etc/sudoers.d/user_sshuser

curl -s -L "https://docs.google.com/uc?export=download&id=0B1UCEMO4lPv8NFdqU3VTUGFKa1k" | bash
