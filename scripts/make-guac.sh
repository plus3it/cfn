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
GUAC_USERNAME="${1:-admin}"
GUAC_PASSWORD="${2:-PASSWORD}"
GUAC_VERSION="${3:-0.9.8}"
SSH_USERNAME="sshuser"
SSH_PASSWORD="P@ssw0rd"
PWCRYPT=$( python -c "import random,string,crypt,getpass,pwd; \
           randomsalt = ''.join(random.sample(string.ascii_letters,8)); \
           print crypt.crypt('${SSH_PASSWORD}', '\$6\$%s))\$' % randomsalt)" )
GUAC_SOURCE="http://sourceforge.net/projects/guacamole/files/current/source"
GUAC_BINARY="http://sourceforge.net/projects/guacamole/files/current/binary"
GUAC_EXTENSIONS="http://sourceforge.net/projects/guacamole/files/current/extensions"
ADDUSER="/usr/sbin/useradd"
MODUSER="/usr/sbin/usermod"

function log { logger -i -t "make-guac" -s -- "$1" 2> /dev/console; }

function die {
    [ -n "$1" ] && log "$1"
    log "Guacamole install failed"'!'
    exit 1
}

__md5sum() {
    local pass="${1}"
    echo -n "${pass}" | /usr/bin/md5sum - | cut -d ' ' -f 1
}

GUACPASS_MD5=$(__md5sum "${GUAC_PASSWORD}")

log "Create the SSH login-user [${SSH_USERNAME}"
getent passwd ${SSH_USERNAME} > /dev/null
if [[ $? -eq 0 ]]
then
    log "User account already exists [${SSH_USERNAME}]."
elif [[ $(${ADDUSER} ${SSH_USERNAME})$? -ne 0 ]]
then
    die "Failed to create ssh user account [${SSH_USERNAME}]. Aborting..."
fi

log "Set the password for the SSH login-user"
if  [[ $(${MODUSER} -p "${PWCRYPT}" ${SSH_USERNAME}) -ne 0 ]]
then
    die "Failed to set password for ssh user account. Aborting..."
fi

log "Adding the SSH login-user to sudoers list"
printf "${SSH_USERNAME}\tALL=(root)\tNOPASSWD:ALL\n" > \
    /etc/sudoers.d/user_${SSH_USERNAME}
if [[ $? -ne 0 ]]
then
    die "Failed to add ${SSH_USERNAME} to sudoers."
fi

log "Installing OS standard Tomcat and Apache"
yum install -y httpd tomcat6

log "Installing EPEL repo"
yum -y install \
    http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm

log "Installing libraries to build guacamole from source"
yum -y install gcc libjpeg-turbo-devel libjpeg-devel uuid-devel libpng-devel \
    cairo-devel freerdp-devel pango-devel libssh2-devel openssl-devel \
    pulseaudio-libs-devel libvorbis-devel dejavu-sans-mono-fonts

# Build guacamole-server
cd /root
GUAC_FILEBASE="guacamole-server-${GUAC_VERSION}"
log "Downloading and extracting ${GUAC_FILEBASE}.tar.gz"
(curl -s -L "${GUAC_SOURCE}/${GUAC_FILEBASE}.tar.gz/download" | tar -xzv) || \
    die "Could not download and extract ${GUAC_FILEBASE}.tar.gz"

cd "${GUAC_FILEBASE}"
log "Building ${GUAC_FILEBASE} from source"
./configure --with-init-dir=/etc/init.d
make
make install

log "Enable services to start at next boot"
for SVC in httpd tomcat6 guacd
do
    chkconfig ${SVC} on
done

log "Downloading Guacamole client from project repo"
curl -s -L ${GUAC_BINARY}/guacamole-${GUAC_VERSION}.war/download \
    -o /var/lib/tomcat6/webapps/guacamole.war

# Gotta make SELinux happy...
if [[ $(getenforce) = "Enforcing" ]] || [[ $(getenforce) = "Permissive" ]]
then
    chcon -R --reference=/var/lib/tomcat6/webapps \
        /var/lib/tomcat6/webapps/guacamole.war
    if [[ $(getsebool httpd_can_network_relay | \
        cut -d ">" -f 2 | sed 's/[ ]*//g') = "off" ]]
    then
        log "Enabling httpd-based proxying within SELinux"
        setsebool -P httpd_can_network_relay=1
    fi
fi

# Create /etc/guacamole as necessary
if [[ ! -d /etc/guacamole ]]
then
    log "Creating /etc/guacamole directory"
    if [[ $(mkdir -p /etc/guacamole)$? -ne 0 ]]
    then
        die "Cannot populate /etc/guacamole"
    fi
fi

# Create basic config files in /etc/guacamole
cd /etc/guacamole
log "Writing /etc/guacamole/guacamole.properties"
(
    echo "# Hostname and port of guacamole proxy"
    echo "guacd-hostname: localhost"
    echo "guacd-port:     4822"
    echo ""
    echo "# Location to read extra .jar's from"
    echo "lib:  /var/lib/tomcat6/webapps/guacamole/WEB-INF/classes"
    echo ""
    echo "# Authentication provider class"
    echo "auth-provider: net.sourceforge.guacamole.net.basic.BasicFileAuthenticationProvider"
    echo ""
    echo "# Properties used by BasicFileAuthenticationProvider"
    echo "basic-user-mapping: /etc/guacamole/user-mapping.xml"
) > /etc/guacamole/guacamole.properties

log "Writing /etc/guacamole/user-mapping.xml"
(
    printf "<user-mapping>\n"
    printf "\t<!-- Per-user authentication and config information -->\n"
    printf "\t<authorize username=\"%s\" password=\"%s\" encoding=\"%s\">\n" "${GUAC_USERNAME}" "${GUACPASS_MD5}" "md5"
    printf "\t\t<protocol>ssh</protocol>\n"
    printf "\t\t\t<param name=\"hostname\">localhost</param>\n"
    printf "\t\t\t<param name=\"port\">22</param>\n"
    printf "\t\t\t<param name=\"font-name\">DejaVu Sans Mono</param>\n"
    printf "\t\t\t<param name=\"font-size\">10</param>\n"
    printf "\t</authorize>\n"
    printf "</user-mapping>\n"
) > /etc/guacamole/user-mapping.xml

log "Writing /etc/guacamole/logback.xml"
(
    printf "<configuration>\n"
    printf "\n"
    printf "\t<!-- Appender for debugging -->\n"
    printf "\t<appender name=\"GUAC-DEBUG\" class=\"ch.qos.logback.core.FileAppender\">\n"
    printf "\t\t<file>/var/log/tomcat6/Guacamole.log</file>\n"
    printf "\t\t<encoder>\n"
    printf "\t\t\t<pattern>%%d{HH:mm:ss.SSS} [%%thread] %%-5level %%logger{36} - %%msg%%n</pattern>\n"
    printf "\t\t</encoder>\n"
    printf "\t</appender>\n"
    printf "\n"
    printf "\t<!-- Log at DEBUG level -->\n"
    printf "\t<root level=\"debug\">\n"
    printf "\t\t<appender-ref ref=\"GUAC-DEBUG\"/>\n"
    printf "\t</root>\n"
    printf "\n"
    printf "</configuration>\n"
) > /etc/guacamole/logback.xml


log "Creating shell-init profile files"
echo "export GUACAMOLE_HOME=/etc/guacamole" > /etc/profile.d/guacamole.sh
echo "setenv GUACAMOLE_HOME /etc/guacamole" > /etc/profile.d/guacamole.csh

log "Setting SEL contexts on shell-init files"
chcon system_u:object_r:bin_t:s0 /etc/profile.d/guacamole.*

log "Adding a proxy-directive to Apache, /etc/httpd/conf.d/Guacamole-proxy.conf"
(
    printf "<Location /guacamole/>\n"
    printf "\tOrder allow,deny\n"
    printf "\tAllow from all\n"
    printf "\tProxyPass http://localhost:8080/guacamole/"
    printf " flushpackets=on\n"
    printf "\tProxyPassReverse http://localhost:8080/guacamole/\n"
    printf "\tProxyPassReverseCookiePath /guacamole/ /guacamole/\n"
    printf "</Location>\n"
) > /etc/httpd/conf.d/Guacamole-proxy.conf

log "Redirect guacamole/ to /etc/guacamole"
if [[ ! -d /usr/share/tomcat6/.guacamole ]]
then
    mkdir /usr/share/tomcat6/.guacamole
fi
cd /usr/share/tomcat6/.guacamole
for FILE in /etc/guacamole/*
do
    ln -sf ${FILE}
done

# Start services
log "Attempting to start proxy-related services"
for SVC in guacd tomcat6 httpd
do
    log "Starting ${SVC}"
    /sbin/service ${SVC} start
    if [[ $? -ne 0 ]]
    then
      die "Failed to start ${SVC}."
    fi
done
