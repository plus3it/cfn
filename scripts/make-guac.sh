#!/bin/bash
#
# Description:
#    This script is intended to aid an administrator in quickly
#    setting up a baseline configuration of the Guacamole
#    management-protocol HTTP-tunneling service. When the script
#    exits successfully:
#    * The Tomcat8 servlet-service will have been downloaded and
#      enabled
#    * The Guacamole service will have been configured to tunnel
#      SSH based connections to the Guacamole host to a remote,
#      HTML 5 compliant web browser.
#    * Apache 2.4 will have been configured to provide a proxy of
#      all public-facing port 80/tcp traffic to the Guacamole
#      servlet listening at localhost port 8080/tcp
#
#################################################################
__ScriptName="make-guac.sh"
__GuacVersion="0.9.13-incubating"

log()
{
    logger -i -t "${__ScriptName}" -s -- "$1" 2> /dev/console
    echo "$1"
}  # ----------  end of function log  ----------


die()
{
    [ -n "$1" ] && log "$1"
    log "Guacamole install failed"'!'
    exit 1
}  # ----------  end of function die  ----------


__md5sum()
{
    local pass="${1}"
    echo -n "${pass}" | /usr/bin/md5sum - | cut -d ' ' -f 1
}  # ----------  end of function md5sum  ----------


retry()
{
    local n=0
    local try=$1
    local cmd="${@: 2}"
    [[ $# -le 1 ]] && {
    echo "Usage $0 <number_of_retry_attempts> <Command>"; }

    until [[ $n -ge $try ]]
    do
        $cmd && break || {
            echo "Command Fail.."
            ((n++))
            echo "retry $n ::"
            sleep $n;
            }
    done
}  # ----------  end of function retry  ----------


usage()
{
    cat << EOT
  Usage:  ${__ScriptName} [options]

  Note:
  If no options are specified, then Guacamole v${__GuacVersion} will be
  installed, but it will not be configured and users will not be able to
  authenticate. Specify -H (and associated options) to configure LDAP
  authentication. Specify -G (and associated options) to configure file-based
  authentication.

  Options:
  -h  Display this message.
  -H  Hostname of the LDAP server to authenticate users against
      (e.g. ldap.example.com). Using the domain DNS name is acceptable as long
      as it resolves to an LDAP server (e.g. example.com). If specified, LDAP
      authentication will be installed and configured. Requires -D.
  -D  Distinguished Name (DN) of the directory (e.g. DN=example,DN=com).
      Required by -H.
  -U  The base of the DN for all Guacamole users. This is prepended to the
      directory DN (-D) to create the full DN to the user container. This will
      be appended to the username when a user logs in. Default is "CN=Users".
  -R  The base of the DN for all Guacamole roles. This is used by the LDAP
      plugin to search for groups the user is a member of. Using this option
      will enable Roles Based Access Control (RBAC) support. This is prepended
      to the directory DN (-D) to create the full DN to the RBAC container.
  -A  The attribute which contains the username and which is part of the DN
      for all Guacamole users. Usually, this will be "uid" or "cn". This is
      used together with the user base DN (-U) to derive the full DN of each
      user logging in. Default is "cn".
  -C  The base of the DN for all Guacamole configurations. Each configuration
      is analogous to a connection. This is prepended to the directory DN (-D)
      to create the full DN to the configuration container. Default is
      "CN=GuacConfigGroups". NOTE: This default value does not exist by
      default in the LDAP directory and will need to be created, or a
      different value will need to be provided.
  -P  Port on which to connect to the LDAP server. Default is "389".
  -v  Version of Guacamole to build, install, and configure.
      Default is "${__GuacVersion}".
  -G  A username authorized to use the Guacamole service that will be
      authenticated using the basic file authentication provider.
  -g  Password for the Guacamole user (-G). If -G is provided, then this
      parameter is required.
  -S  An Operating System (OS) username that will be created and allowed to
      login via SSH. This parameter is only valid if -G is specified, as well.
      If this parameter is not provided but -G is, then the -G username will
      be used for the OS user.
  -s  Password for the OS user (-S). If -S is specified, then this parameter
      is required.
  -L  URL for first link to be included in Guac login page. If -T is specified,
      then this parameter is required for successful modification.
  -T  Text to be displayed for the URL provided with -L.  If -L is specified,
      then this parameter is required for successful modification.
  -l  URL for second link to be included in Guac login page. If -t is specified,
      then this parameter is required for successful modification.
  -t  Text to be displayed for the URL provided with -l.  If -l is specified,
      then this parameter is required for successful modification.
  -B  Text for branding of the homepage. Default is "Apache Guacamole".
EOT
}  # ----------  end of function usage  ----------


#Guac manifest file for using extensions
write_manifest()
{
    log "Writing Guac manifest file"
    (
        printf "{\n"
        printf "\"guacamoleVersion\" : \"$GUAC_VERSION\",\n"
        printf "\"name\" : \"Custom Extension\",\n"
        printf "\"namespace\" : \"custom-extension\",\n"
        printf "\"html\" : [ \"custom-urls.html\" ],\n"
        printf "\"translations\" : [ \"translations/en.json\" ]\n"
        printf "}\n"
    ) > /etc/guacamole/extensions/guac-manifest.json
    if ! ( [[ -n "${URL_1}" ]] || [[ -n "${URL_2}" ]] )
    then
        sed -i '/html/d' /etc/guacamole/extensions/guac-manifest.json
    fi
    cd "/etc/guacamole/extensions"
    zip -u "custom.jar" "guac-manifest.json"
}  # ----------  end of function write_manifest  ----------


#Guac links extension file
write_links()
{
    log "Writing Guac html extension file to add in custom URLs"
    (
        printf "<meta name=\"after\" content=\".login-ui .login-dialog\">\n"
        printf "\n"
        printf "<div class=\"welcome\">\n"
        printf "<p>\n"
        printf "<a target=\"_blank\" href=\"${URL_1}\">${URLTEXT_1}</a>\n"
        printf "</p>\n"
        printf "<p>\n"
        printf "<a target=\"_blank\" href=\"${URL_2}\">${URLTEXT_2}</a>\n"
        printf "</p>\n"
        printf "</div>\n"
    ) > /etc/guacamole/extensions/custom-urls.html
    cd "/etc/guacamole/extensions"
    zip -u "custom.jar" "custom-urls.html"
    log "Successfully added URL(s) to Guacamole login page"
}  # ----------  end of function write_links  ----------

#Guac branding extension file
write_brand()
{
    log "Writing Guac translations extension file to add in custom branding text"
    mkdir -p /etc/guacamole/extensions/translations
    (
        printf "{\n"
        printf "\"APP\" : { \"NAME\" : \"${BRANDTEXT}\" }\n"
        printf "}\n"
    ) > /etc/guacamole/extensions/translations/en.json
    cd "/etc/guacamole/extensions"
    zip -u "custom.jar" translations/en.json
    log "Successfully added branding text to Guacamole login page"
}  # ----------  end of function write_brand  ----------


# Define default values
LDAP_HOSTNAME=
LDAP_DOMAIN_DN=
LDAP_USER_BASE="CN=Users"
LDAP_USER_ATTRIBUTE="cn"
LDAP_CONFIG_BASE="CN=GuacConfigGroups"
LDAP_GROUP_BASE="CN=Users"
LDAP_PORT="389"
GUAC_VERSION="${__GuacVersion}"
GUAC_USERNAME=
GUAC_PASSWORD=
SSH_USERNAME=
SSH_PASSWORD=
URL_1=
URLTEXT_1=
URL_2=
URLTEXT_2=
BRANDTEXT=


# Parse command-line parameters
while getopts :hH:D:U:R:A:C:P:v:G:g:S:s:L:T:l:t:B: opt
do
    case "${opt}" in
        h)
            usage
            exit 0
            ;;
        H)
            LDAP_HOSTNAME="${OPTARG}"
            ;;
        D)
            LDAP_DOMAIN_DN="${OPTARG}"
            ;;
        U)
            LDAP_USER_BASE="${OPTARG}"
            ;;
        R)
            LDAP_GROUP_BASE="${OPTARG}"
            ;;
        A)
            LDAP_USER_ATTRIBUTE="${OPTARG}"
            ;;
        C)
            LDAP_CONFIG_BASE="${OPTARG}"
            ;;
        P)
            LDAP_PORT="${OPTARG}"
            ;;
        v)
            GUAC_VERSION="${OPTARG}"
            ;;
        G)
            GUAC_USERNAME="${OPTARG}"
            ;;
        g)
            GUAC_PASSWORD="${OPTARG}"
            ;;
        S)
            SSH_USERNAME="${OPTARG}"
            ;;
        s)
            SSH_PASSWORD="${OPTARG}"
            ;;
        L)
            URL_1="${OPTARG}"
            ;;
        T)
            URLTEXT_1="${OPTARG}"
            ;;
        l)
            URL_2="${OPTARG}"
            ;;
        t)
            URLTEXT_2="${OPTARG}"
            ;;
        B)
            BRANDTEXT="${OPTARG}"
            ;;
        \?)
            usage
            echo "ERROR: unknown parameter \"$OPTARG\""
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))


# Validate parameters
if [ -n "${LDAP_HOSTNAME}" ]
then
    if [ -z "${LDAP_DOMAIN_DN}" ]
    then
        die "LDAP Hostname was provided (-H), but the LDAP Domain DN was not (-D)"
    fi
elif [ -n "${LDAP_DOMAIN_DN}" ]
then
    die "LDAP Domain DN was provided (-D), but the LDAP Hostname was not (-H)"
fi

if [ -n "${GUAC_USERNAME}" ]
then
    if [ -z "${GUAC_PASSWORD}" ]
    then
        die "Guacamole username was provided (-G), but the password was not (-s)"
    fi
    if [ -z "${SSH_USERNAME}" ]
    then
        SSH_USERNAME="${GUAC_USERNAME}"
        SSH_PASSWORD="${GUAC_PASSWORD}"
    fi
fi


# Validate parameter pairs of URL and URLTEXT are appropriately populated
if [ -n "${URL_1}" ]
then
    if [ -z "${URLTEXT_1}" ]
    then
        die "URL1 was provided (-L), but the partner URLTEXT was not (-T), login page unmodified; exiting"
    fi
elif [ -n "${URLTEXT_1}" ]
then
    die "URLTEXT1 was provided (-T), but the URL was not (-L), login page unmodified; exiting"
fi

if [ -n "${URL_2}" ]
then
    if [ -z "${URLTEXT_2}" ]
    then
        die "URL2 was provided (-l), but the partner URLTEXT was not (-t), login page unmodified; exiting"
    fi
elif [ -n "${URLTEXT_2}" ]
then
    die "URLTEXT2 was provided (-t), but the URL was not (-l), login page unmodified; exiting"
fi


# Set internal variables
PWCRYPT=$( python -c "import random,string,crypt,getpass,pwd; \
           randomsalt = ''.join(random.sample(string.ascii_letters,8)); \
           print crypt.crypt('${SSH_PASSWORD}', '\$6\$%s))\$' % randomsalt)" )
GUACPASS_MD5=$(__md5sum "${GUAC_PASSWORD}")
GUAC_SOURCE="https://s3.amazonaws.com/app-chemistry/files"
GUAC_BINARY="https://s3.amazonaws.com/app-chemistry/files"
GUAC_EXTENSIONS="https://s3.amazonaws.com/app-chemistry/files"
FREERDP_REPO="git://github.com/FreeRDP/FreeRDP.git"
FREERDP_BRANCH="stable-1.1"
ADDUSER="/usr/sbin/useradd"
MODUSER="/usr/sbin/usermod"


# Start the real work
log "Installing EPEL repo"
retry 2 yum -y install \
    http://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm

retry 5 yum -y install yum-utils yum-plugin-fastestmirror wget

log "Ensuring the CentOS Base repo is available"
retry 5 curl -s --show-error --retry 5 -L "https://raw.githubusercontent.com/plus3it/cfn/master/scripts/CentOS-Base.repo" \
    -o "/etc/yum.repos.d/CentOS-Base.repo"

retry 5 curl -s --show-error --retry 5 -L "https://raw.githubusercontent.com/plus3it/cfn/master/scripts/RPM-GPG-KEY-CentOS-6" \
    -o "/etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6"

log "Enabling the EPEL and base repos"
yum-config-manager --enable epel base

log "Clean yum cache"
retry 5 yum clean all

log "Installing OS standard Tomcat"
retry 5 yum -y install tomcat8 || die "Failed to install tomcat"

log "Installing utils and libraries to build freerdp from source"
retry 5 yum -y install git gcc cmake openssl-devel libX11-devel libXext-devel \
    libXinerama-devel libXcursor-devel libXi-devel libXdamage-devel \
    libXv-devel libxkbfile-devel alsa-lib-devel cups-devel ffmpeg-devel \
    glib2-devel \
    || die "Failed to install packages required to build freerdp"

# Build freerdp
cd /root
FREERDP_BASE=$(basename ${FREERDP_REPO} .git)
rm -rf "${FREERDP_BASE}"
git clone "${FREERDP_REPO}" || \
    die "Could not clone ${FREERDP_REPO}"
cd "${FREERDP_BASE}"
git checkout "${FREERDP_BRANCH}" || \
    die "Could not checkout branch ${FREERDP_BRANCH}"
log "Building ${FREERDP_BASE} from source"
cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_SSE2=ON -DWITH_DEBUG_ALL=ON .
make
make install
(
    printf "/usr/local/lib/freerdp\n"
    printf "/usr/local/lib64/freerdp\n"
    printf "/usr/local/lib\n"
    printf "/usr/local/lib64\n"
) > /etc/ld.so.conf.d/freerdp.conf
ldconfig


log "Installing libraries to build guacamole from source"
retry 5 yum -y install gcc cairo-devel libjpeg-turbo-devel libjpeg-devel libpng-devel \
    uuid-devel pango-devel libssh2-devel pulseaudio-libs-devel openssl-devel \
    libvorbis-devel dejavu-sans-mono-fonts libwebp-devel \

# Build guacamole-server
cd /root
GUAC_FILEBASE="guacamole-server-${GUAC_VERSION}"
rm -rf "${GUAC_FILEBASE}"
log "Downloading and extracting ${GUAC_FILEBASE}.tar.gz"
retry 5 wget --timeout=10 "${GUAC_SOURCE}/${GUAC_FILEBASE}.tar.gz" || \
    die "Could not download ${GUAC_FILEBASE}.tar.gz"
tar -xvf ${GUAC_FILEBASE}.tar.gz || \
    die "Could not extract ${GUAC_FILEBASE}.tar.gz"

cd "${GUAC_FILEBASE}"
log "Building ${GUAC_FILEBASE} from source"
./configure --with-init-dir=/etc/init.d
make
make install
ldconfig

log "Enabling services to start at next boot"
for SVC in tomcat8 guacd
do
    chkconfig ${SVC} on
done

# Create guacamole directories as necessary
for GUAC_DIR in "/etc/guacamole" "/etc/guacamole/extensions" "/etc/guacamole/lib"
do
    if [[ ! -d "${GUAC_DIR}" ]]
    then
        log "Creating ${GUAC_DIR} directory"
        if [[ $(mkdir -p "${GUAC_DIR}")$? -ne 0 ]]
        then
            die "Cannot populate ${GUAC_DIR}"
        fi
    fi
done


# Install the Guacamole client
log "Downloading Guacamole client from project repo"
cd /root
retry 5 wget --timeout=10 ${GUAC_BINARY}/guacamole-${GUAC_VERSION}.war || \
    die "Could not download ${GUAC_BINARY}"
mv guacamole-${GUAC_VERSION}.war /var/lib/tomcat8/webapps/ROOT.war || \
    die "Could not move ${GUAC_BINARY}"


# Gotta make SELinux happy...
if [[ $(getenforce) = "Enforcing" ]] || [[ $(getenforce) = "Permissive" ]]
then
    chcon -R --reference=/var/lib/tomcat8/webapps \
        /var/lib/tomcat8/webapps/ROOT.war
    if [[ $(getsebool httpd_can_network_relay | \
        cut -d ">" -f 2 | sed 's/[ ]*//g') = "off" ]]
    then
        log "Enabling httpd-based proxying within SELinux"
        setsebool -P httpd_can_network_relay=1
    fi
fi


# Create basic config files in /etc/guacamole
cd /etc/guacamole
log "Writing /etc/guacamole/guacamole.properties"
(
    echo "# Hostname and port of guacamole proxy"
    echo "guacd-hostname: localhost"
    echo "guacd-port:     4822"
) > /etc/guacamole/guacamole.properties
log "Writing /etc/guacamole/logback.xml"
(
    printf "<configuration>\n"
    printf "\n"
    printf "\t<!-- Appender for debugging -->\n"
    printf "\t<appender name=\"GUAC-DEBUG\" class=\"ch.qos.logback.core.FileAppender\">\n"
    printf "\t\t<file>/var/log/tomcat8/guacamole.log</file>\n"
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
log "Writing /etc/guacamole/guacd.conf"
(
    printf "# guacd configuration file\n\n"
    printf "[daemon]\n"
    printf "log_level = debug\n"
) > /etc/guacamole/guacd.conf
log "Writing /etc/rsyslog.d/00-guacd.conf"
(
    printf "# Log guacd generated log messages to file\n"
    printf ":syslogtag, startswith, \"guacd\" /var/log/guacd.log\n\n"
    printf "# comment out the following line to allow GUACD messages through.\n"
    printf "# Doing so means you'll also get GUACD messages in /var/log/syslog\n"
    printf "& ~\n"
) > /etc/rsyslog.d/00-guacd.conf

if [ -n "${GUAC_USERNAME}" ]
then
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

    log "Adding the basic user mapping setting to guacamole.properties"
    (
        echo ""
        echo "# Properties used by BasicFileAuthenticationProvider"
        echo "basic-user-mapping: /etc/guacamole/user-mapping.xml"
    ) >> /etc/guacamole/guacamole.properties

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
fi

if [ -n "${LDAP_HOSTNAME}" ]
then

    # Install the Guacamole LDAP auth extension
    log "Downloading Guacmole ldap extension"
    GUAC_LDAP="guacamole-auth-ldap-${GUAC_VERSION}"
    cd /root
    retry 5 wget --timeout=10 \
        "${GUAC_EXTENSIONS}/${GUAC_LDAP}.tar.gz" || \
        die "Could not download ldap extension"

    log "Extracting Guacamole ldap extension"
    cd /root
    tar -xvf "${GUAC_LDAP}.tar.gz" || \
        die "Could not extract Guacamole ldap plugin"

    log "Installing Guacamole ldap .jar file in the extensions directory"
    # Can only have one extension at a time, so ensure the directory is empty
    rm -rf "/etc/guacamole/extensions/*"
    cp "${GUAC_LDAP}/${GUAC_LDAP}.jar" "/etc/guacamole/extensions"

    log "Adding the LDAP auth settings to guacamole.properties"
    (
        echo ""
        echo "# Properties used by the LDAP Authentication plugin"
        echo "ldap-hostname:           ${LDAP_HOSTNAME}"
        echo "ldap-port:               ${LDAP_PORT}"
        echo "ldap-user-base-dn:       ${LDAP_USER_BASE},${LDAP_DOMAIN_DN}"
        echo "ldap-username-attribute: ${LDAP_USER_ATTRIBUTE}"
        echo "ldap-config-base-dn:     ${LDAP_CONFIG_BASE},${LDAP_DOMAIN_DN}"
    ) >> /etc/guacamole/guacamole.properties

    if [ -n "$LDAP_GROUP_BASE" ]
    then
        log "Adding the LDAP group base DN, RBAC is enabled."
        (
            echo "ldap-group-base-dn:      ${LDAP_GROUP_BASE},${LDAP_DOMAIN_DN}"
        ) >> /etc/guacamole/guacamole.properties

        if [[ "$GUAC_VERSION" == "0.9.7" || "$GUAC_VERSION" == "0.9.9" ]]
        then
            log "Enabling custom RBAC jar for ${GUAC_VERSION}"
            rm -rf "/etc/guacamole/extensions/*"
            cd "/etc/guacamole/extensions/"
            curl -s --show-error --retry 5 -O "https://s3.amazonaws.com/app-chemistry/files/guacamole-auth-ldap-${GUAC_VERSION}.jar" || \
                die "Unable to download ${GUAC_VERSION} custom plugin from s3 bucket"
            if [[ $(file "/etc/guacamole/extensions/guacamole-auth-ldap-${GUAC_VERSION}.jar" | grep -q "Zip archive data")$? -ne 0 ]]
            then
                die "Error: Detected /etc/guacamole/extensions/guacamole-auth-ldap-${GUAC_VERSION}.jar is not zip archive data!"
            fi
        else
            log "Warning: Unknown RBAC support in this GUAC version, ${GUAC_VERSION}. Only 0.9.7 or 0.9.9 are known to work!"
        fi
    fi
fi


log "Creating shell-init profile files"
echo "export GUACAMOLE_HOME=/etc/guacamole" > /etc/profile.d/guacamole.sh
echo "setenv GUACAMOLE_HOME /etc/guacamole" > /etc/profile.d/guacamole.csh


log "Setting SEL contexts on shell-init files"
chcon system_u:object_r:bin_t:s0 /etc/profile.d/guacamole.*


log "Ensuring freerdp plugins are linked properly"
if [[ ! -d /usr/lib64/freerdp ]]
then
    mkdir /usr/lib64/freerdp
fi
cd /usr/lib64/freerdp
for FILE in /usr/local/lib/freerdp/*
do
    ln -sf ${FILE}
done
if [[ ! -d /usr/local/lib64/freerdp ]]
then
    mkdir /usr/local/lib64/freerdp
fi
cd /usr/local/lib64/freerdp
for FILE in /usr/local/lib/freerdp/*
do
    ln -sf ${FILE}
done


log "Creating directory for file transfers"
if [[ ! -d /var/tmp/guacamole ]]
then
    mkdir /var/tmp/guacamole
fi


#Add custom URLs to Guacamole login page using Guac extensions.
if ( [[ -n "${URL_1}" ]] || [[ -n "${URL_2}" ]] )
then
    write_manifest
    write_links
else
    log "URL parameters were blank, not adding links"
fi


#Add custom branding text to title page.
if [[ -n "${BRANDTEXT}" ]]
then
    log "Writing Guac translations extension file to add in custom branding text"
    mkdir -p /etc/guacamole/extensions/translations
    if [ ! -f "/etc/guacamole/extensions/guac-manifest.json" ]
    then
        write_manifest
    fi
    write_brand
else
   log "Branding text was blank, keeping default text"
fi


# Start services
log "Attempting to start proxy-related services"
for SVC in  rsyslog tomcat8 guacd
do
    log "Stopping and starting ${SVC}"
    /sbin/service ${SVC} stop && /sbin/service ${SVC} start
    if [[ $? -ne 0 ]]
    then
      die "Failed to start ${SVC}."
    fi
done
