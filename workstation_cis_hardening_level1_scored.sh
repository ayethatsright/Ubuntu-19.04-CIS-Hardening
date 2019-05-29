#! /bin/bash

# This script hardens the workstation in line with CIS Benchmark (for Level 1)
# It only includes CIS Workstation LEVEL 1 which are scored
# There are separate scripts to add the 'NOT scored' controls (workstation_cis_hardening_level1_NOT_scored.sh)

#########################################################################################################################################

#THIS SECTIONS CONFIRMS THAT THE SCRIPT HAS BEEN RUN WITH SUDO

if [[ $UID -ne 0 ]]; then
	echo "Need to run this script as root (with sudo)"
	exit 1
fi

echo "[I] Beginning hardening script now"

#########################################################################################################################################

echo "[i] Beginning hardening process"

# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)

echo "[i] Disabling the mounting of cramfs filesystems"
echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
rmmod cramfs
sleep 1

#########################################################################################################################################

# 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored)

echo "[I] Disabling the mounting of freevxfs filesystems"
echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf
rmmod freevxfs
sleep 1

#########################################################################################################################################

# 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored)

echo "[I] Disabling the mounting of jffs2 filesystems"
echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf
rmmod jffs2
sleep 1

#########################################################################################################################################

# 1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored)

echo "[I] Disabling the mounting of hfs filesystems"
echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf
rmmod hfs
sleep 1

#########################################################################################################################################

# 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored)

echo "[I] Disabling the mounting of hfsplus filesystems"
echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
rmmod hfsplus
sleep 1

#########################################################################################################################################


# 1.1.1.6 Ensure mounting of udf filesystems is disabled (Scored)

echo "[I] Disabling the mounting of udf filesystems"
echo "install udf /bin/true" > /etc/modprobe.d/udf.conf
rmmod udf
sleep 1

#########################################################################################################################################

# 1.1.3 Ensure nodev option set /tmp partition (Scored)
# 1.1.4 Ensure nosuid option set on /tmp partition (Scored)

echo "[i] Ensuring that nodev & nosuid are set on the /tmp partition"

LINETMP="tmpfs /tmp tmpfs nosuid,noexec,nodev,relatime,rw 0 0"

grep -F "$LINETMP" /etc/fstab || echo "$LINETMP" | tee -a /etc/fstab > /dev/null

#########################################################################################################################################

# 1.1.7 Ensure nodev option set on /var/tmp partition (Scored)
# 1.1.8 Ensure nosuid option set on /var/tmp partition (Scored)
# 1.1.9 Ensure noexec option set on /var/tmp partition (Scored)

echo "[i] Ensuring that nodev, nosuid & noexec are set on the /var/tmp partition"

LINEVARTMP="tmpfs /var/tmp tmpfs nosuid,noexec,nodev 0 0"

grep -F "$LINEVARTMP" /etc/fstab || echo "$LINEVARTMP" | tee -a /etc/fstab > /dev/null

#########################################################################################################################################

# 1.1.13 Ensure nodev option set on /home partition (Scored)

echo "[i] Ensuring that the nodev option is set on the /home partition"

echo "[i] If you have a separate home partition, you need to provide it's name"
echo "[i] If a separate home partition doesn't exist, leave this blank."
echo "[i] Home partition example: /dev/xvda1"
read -p "[?] Enter home partition: " HOME_PARTITION

if [ -b $HOME_PARTITION ]
then

    LINEHOME="$HOME_PARTITION /home ext4 rw,relatime,nodev,data=ordered 0 0"

    grep -F "$LINEHOME" /etc/fstab || echo "$LINEHOME" | tee -a /etc/fstab > /dev/null

fi

#########################################################################################################################################

# 1.1.14 Ensure nodev option set on /dev/shm partition (Scored)
# 1.1.15 Ensure nosuid option set on /dev/shm partition (Scored)
# 1.1.16 Ensure noexec option set on /dev/shm partition (Scored)

echo "[i] Ensuring that nodev, nosuid & noexec is set on the /dev/shm partition"

LINEDEVSHM="tmpfs /dev/shm tmpfs nosuid,noexec,nodev,relatime,rw 0 0"

grep -F "$LINEDEVSHM" /etc/fstab || echo "$LINEDEVSHM" | tee -a /etc/fstab > /dev/null

#########################################################################################################################################

# 1.1.20 Ensure sticky bit is set on all world-writable directories (Scored)

echo "[i] Ensuring that sticky bit is set on all world-writable directories"

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

#########################################################################################################################################

# 1.3.1 Ensure AIDE is installed

echo "[i] Installing AIDE"

apt-get install --assume-yes aide aide-common && aideinit

echo "[i] Generating AIDE config file"

update-aide.conf
cp /var/lib/aide/aide.conf.autogenerated /etc/aide/aide.conf

echo "[i] Adding necessary config items to the AIDE config file"

LINESAIDE=( "!/var/lib/lxcfs" "!/var/lib/private/systemd" "!/var/log/journal" )
AIDECONFFILE=/etc/aide/aide.conf

for current_line in "${LINESAIDE[@]}"
do
    grep -F "$current_line" "$AIDECONFFILE" || echo "$current_line" | tee -a "$AIDECONFFILE" > /dev/null
done

#########################################################################################################################################

# 1.3.2 Ensure filesystem integrity is regularly checked (Scored)

echo "[i] Creating a cron job to regularly check filesystem integrity using AIDE"

LINEAIDECRON="0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"
AIDECRONFILE=/home/tmp.cron

crontab -l -u root 2>/dev/null

if [ $? -eq 0 ]
then
    crontab -u root -l > $AIDECRONFILE
else
    touch $AIDECRONFILE
fi

grep -qF "$LINEAIDECRON" "$AIDECRONFILE" || echo "$LINEAIDECRON" | tee -a "$AIDECRONFILE" > /dev/null

crontab -u root $AIDECRONFILE

rm $AIDECRONFILE

fi

#########################################################################################################################################

# 1.4.1 Ensure permissions on bootloader config are configured (Scored)

echo "[i] Setting correct permissions for the bootloader config"

chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

#########################################################################################################################################

# 1.4.2 Ensure bootloader password is set (Scored)

echo "[i] Setting bootloader password"

SAFE_SSH=1

if [ $SAFE_SSH != 1 ]
then
    if ( grep -q "^set superusers" /boot/grub/grub.cfg )
    then
        echo "Superusers: EXIST"
    else
        echo "Superusers: I sleep."

        FILE=/home/out

        # Create boot password for boot loader.
        grub-mkpasswd-pbkdf2 | sudo tee "$FILE"

        enc_pass=$( grep .sha512 "$FILE" | awk -F "is " '{print $2}' )

        # Remove out file
        rm "$FILE"

        FILE=/etc/grub.d/40_custom
        LINE="set superusers=\"root\""

        enc_pass="password_pbkdf2 root $enc_pass"

        # Append superusers and password if not exist.
        grep -qF "$LINE" "$FILE" || echo "$LINE" | sudo tee --append "$FILE" > /dev/null
        grep -qF "$enc_pass" "$FILE" || echo "$enc_pass" | sudo tee --append "$FILE" > /dev/null

        # Update grub config file
        update-grub

    fi
fi

#########################################################################################################################################

# 1.4.3 Ensure authentication required for single user maode (Scored)

echo "[i] Checking if the root user already has a password set"

if ! grep ^root:[*\!]: /etc/shadow
then
	echo "[i] root user already has a password set"
	echo "[i] no further action required"
else
	echo "[i] root user hasn't got a password set"
	echo "[i] Setting a password for the root user"
	passwd root
fi

#########################################################################################################################################

# 1.5.1 Ensure core dumps are restricted (Scored)

echo "[i] Ensuring core dumps are restricted"

DUMPLINE="* hard core 0"
DUMPFILE=/etc/security/limits.conf

grep -qF "$DUMPLINE" "$DUMPFILE" || echo "$DUMPLINE" | tee -a "$DUMPFILE" > /dev/null

DUMPABLELINE="fs.suid_dumpable=0"
DUMPABLEFILE=/etc/sysctl.conf

grep -qF "$DUMPABLELINE" "$DUMPABLEFILE" || echo "$DUMPABLELINE" | tee -a "$DUMPABLEFILE" > /dev/null

sysctl -w fs.suid_dumpable=0

#########################################################################################################################################

# 1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored)

echo "[i] Ensuring address space layout randomization (ASLR) is enabled"

ASLRLINE="kernel.randomize_va_space = 2"
ASLRFILE=/etc/sysctl.d/99-walson-hardening.conf

touch "$ASLRFILE"

grep -qF "$ASLRLINE" "$ASLRFILE" || echo "$ASLRLINE" | tee -a "$ASLRFILE" > /dev/null

sysctl -w kernel.randomize_va_space=2

#########################################################################################################################################

# 1.5.4 Ensure prelink is disabled (Scored)

echo "[i] Restoring the prelink binaries to normal"
prelink -ua

echo "[i] Uninstalling prelink"
apt-get remove prelink

#########################################################################################################################################

# 1.7.1.1 Ensure message of the day is configured properly (Scored)

echo "[i] Creating the message of the day"
echo "Unauthorised use of this system is an offence under the Computer Misuse Act 1990. All activity may be monitored and reported." > /etc/motd

#########################################################################################################################################

# 1.7.1.2 Ensure local login warning banner is configured properly (Scored)

echo "[i] Creating the local login warning banner"
echo "Unauthorised use of this system is an offence under the Computer Misuse Act 1990. All activity may be monitored and reported." > /etc/issue

#########################################################################################################################################

# 1.7.1.3 Ensure remote login warning banner is configured properly (Scored)

echo "[i] Creating the remote login warning banner"
echo "Unauthorised use of this system is an offence under the Computer Misuse Act 1990. All activity may be monitored and reported." > /etc/issue.net

#########################################################################################################################################

# 1.7.1.4 Ensure permissions on /etc/motd are configured (Scored)

echo "[i] Setting correct permissions on /etc/motd"
chown root:root /etc/motd
chmod 644 /etc/motd

#########################################################################################################################################

# 1.7.1.5 Ensure permissions on /etc/issue are configured (Scored)

echo "[i] Setting correct permissions on /etc/issue"
chown root:root /etc/issue
chmod 644 /etc/issue

#########################################################################################################################################

# 1.7.1.6 Ensure permissions on /etc/issue.net are configured (Scored)

echo "[i] Setting correct permissions on /etc/issue.net"
chown root:root /etc/issue.net
chmod 644 /etc/issue.net

#########################################################################################################################################

# 1.7.2 Ensure GDM login banner is configured (Scored)

echo "[i] Setting the GDM login banner"
echo "[org/gnome/login-screen]" > /etc/gdm3/greeter.dconf-defaults
echo "banner-message-enable=true" >> /etc/gdm3/greeter.dconf-defaults
echo "banner-message-text='Unauthorised use of this system is an offence under the Computer Misuse Act 1990. All activity may be monitored and reported." >> /etc/gdm3/greeter.dconf-defaults

#########################################################################################################################################

# 2.1.1 Ensure chargen services are not enabled (Scored)
# 2.1.2 Ensure daytime services are not enabled (Scored)
# 2.1.3 Ensure discard services are not enabled (Scored)
# 2.1.4 Ensure echo services are not enabled (Scored)
# 2.1.5 Ensure time services are not enabled (Scored)
# 2.1.6 Ensure rsh server is not enabled (Scored)
# 2.1.7 Ensure talk server is not enabled (Scored)
# 2.1.8 Ensure telnet server is not enabled (Scored)
# 2.1 9 Ensure tftp server is not enabled (Scored)

# All the above are only valid if inetd is installed but it isn't installed by default in Ubuntu.  Therefore, none of the hardening is being performed.  I might create an extra inetd hardening script for anyone who has installed it and needs it disabling! 
# The 'workstation_cis_hardening_level1_CHECK.sh' script will highlight if inetd services are enabled and need to be disabled (but they shouldn't be).

#########################################################################################################################################

# 2.1.10 Ensure xinetd is not enabled (Scored)

echo "[i] Disabling xinetd"
systemctl disable xinetd

#########################################################################################################################################

# 2.1.11 Ensure openbsd-inetd is not installed

echo "[i] Removing openbsd-inetd"
apt-get remove openbsd-inetd

#########################################################################################################################################

# 2.2.1.2 Ensure ntp is configured

echo "[i] Configuring ntp"

sed -i 's/^restrict -4.*/restrict -4 default kod nomodify notrap nopeer noquery/' /etc/ntp.conf
sed -i 's/^restrict -6.*/restrict -6 default kod nomodify notrap nopeer noquery/' /etc/ntp.conf

# Adding NTP servers for the UK

if grep -q "^server.*" /etc/ntp.conf; then
	sed '/^server.*/d' /etc/ntp.conf
	echo "server 0.uk.pool.ntp.org" >> /etc/ntp.conf
	echo "server 1.uk.pool.ntp.org" >> /etc/ntp.conf
	echo "server 2.uk.pool.ntp.org" >> /etc/ntp.conf
	echo "server 3.uk.pool.ntp.org" >> /etc/ntp.conf
else
	echo "server 0.uk.pool.ntp.org" >> /etc/ntp.conf
	echo "server 1.uk.pool.ntp.org" >> /etc/ntp.conf
	echo "server 2.uk.pool.ntp.org" >> /etc/ntp.conf
	echo "server 3.uk.pool.ntp.org" >> /etc/ntp.conf
fi

# Adding ntp user as the RUNAS user in the /etc/init.d/ntp file

if grep -q "^RUNASUSER=" /etc/init.d/ntp; then 
	sed -i 's/^RUNASUSER=.*/RUNASUSER=ntp/' /etc/init.d/ntp
else
    echo "RUNASUSER=ntp" >> /etc/init.d/ntp
fi

#########################################################################################################################################

# 2.2.1.3 Ensure chrony is configured (Scored)

echo "[i] Configuring chrony"

# Adding NTP servers for the UK

if grep -q "^server.*" /etc/chrony/chrony.conf; then
	sed '/^server.*/d' /etc/chrony/chrony.conf
	echo "server 0.uk.pool.ntp.org" >> /etc/chrony/chrony.conf
	echo "server 1.uk.pool.ntp.org" >> /etc/chrony/chrony.conf
	echo "server 2.uk.pool.ntp.org" >> /etc/chrony/chrony.conf
	echo "server 3.uk.pool.ntp.org" >> /etc/chrony/chrony.conf
else
	echo "server 0.uk.pool.ntp.org" >> /etc/chrony/chrony.conf
	echo "server 1.uk.pool.ntp.org" >> /etc/chrony/chrony.conf
	echo "server 2.uk.pool.ntp.org" >> /etc/chrony/chrony.conf
	echo "server 3.uk.pool.ntp.org" >> /etc/chrony/chrony.conf
fi

#########################################################################################################################################

# 2.2.3 Ensure Avahi Server is not enabled (Scored)

echo "[i] Disabling Avahi Server"

systemctl disable avahi-daemon

#########################################################################################################################################

# 2.2.5 Ensure DHCP Server is not enabled (Scored)

echo "[i] Disabling DHCP Server"

systemctl disable isc-dhcp-server
systemctl disable isc-dhcp-server6

#########################################################################################################################################

# 2.2.6 Ensure LDAP server is not enabled (Scored)

echo "[i] Disabling LDAP server"

systemctl disable slapd

#########################################################################################################################################

# 2.2.7 Ensure NFS and RPC are not enabled (Scored)

echo "[i] Disabling NFS and RPC"

systemctl disable nfs-server
systemctl disable rpcbind

#########################################################################################################################################

# 2.2.8 Ensure DNS Server is not enabled (Scored)

echo "[i] Disabling DNS Server"

systemctl disable bind9

#########################################################################################################################################

# 2.2.9 Ensure FTP Server is not enabled (Scored)

echo "[i] Disabling FTP Server"

systemctl disable vsftpd

#########################################################################################################################################

# 2.2.10 Ensure HTTP Server is not enabled (Scored)

echo "[i] Disabling HTTP Server"

systemctl disable apache2

#########################################################################################################################################

# 2.2.11 Ensure IMAP and POP3 server is not enabled (Scored)

echo "[i] Disabling IMAP and POP3 Server"

systemctl disable dovecot

#########################################################################################################################################

# 2.2.12 Ensure Samba is not enabled (Scored)

echo "[i] Disabling Samba"

systemctl disable smbd

#########################################################################################################################################

# 2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)

echo "[i] Disabling HTTP Proxy Server"

systemctl disable squid

#########################################################################################################################################

# 2.2.14 Ensure SNMP Server is not enabled (Scored)

echo "[i] Disabling SNMP Server"

systemctl disable snmpd

#########################################################################################################################################

# 2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)

echo "[i] Configuring mail transfer agent for local-only mode"

if grep -q "^inet_interfaces = " /etc/postfix/main.cf; then 
	sed -i 's/^inet_interfaces.*/inet_interface = loopback-only/' /etc/postfix/main.cf
else
    echo "inet_interfaces = loopback-only" >> /etc/postfix/main.cf
fi

systemctl restart postfix

#########################################################################################################################################

# 2.2.16 Ensure rsync service is not enabled (Scored)

echo "[i] Disabling rsync service"

systemctl disable rsync

#########################################################################################################################################

# 2.2.17 Ensure NIS Server is not enabled (Scored)

echo "[i] Disabling NIS Server"

systemctl disable nis

#########################################################################################################################################

# 2.3.1 Ensure NIS Client is not installed (Scored)

echo "[i] Uninstalling NIS client"

apt remove -y nis

#########################################################################################################################################

# 2.3.2 Ensure rsh client is not installed (Scored)

echo "[i] Uninstalling the rsh client"

apt remove -y rsh-client rsh-redone-client

#########################################################################################################################################

# 2.3.3 Ensure talk client is not installed (Scored)

echo "[i] Uninstalling the talk client"

apt remove -y talk

#########################################################################################################################################

# 2.3.4 Ensure telnet client is not installed (Scored)

echo "[i] Uninstalling the telnet client"

apt remove -y telnet

#########################################################################################################################################

# 2.3.5 Ensure LDAP client is not installed (Scored)

echo "[i] Uninstalling the LDAP client"

apt remove -y ldap-utils

#########################################################################################################################################

# 3.1.1 Ensure IP forwarding is disabled (Scored)
# 3.1.2 Ensure packet redirect sending is disabled (Scored)

# This are only required if the system is to act as a host only.  If needed, run the workstation_cis_hardening_level1_scored_HOSTONLY.sh script to apply these controls

#########################################################################################################################################



#########################################################################################################################################



#########################################################################################################################################



#########################################################################################################################################



#########################################################################################################################################



#########################################################################################################################################



#########################################################################################################################################



#########################################################################################################################################



#########################################################################################################################################



#########################################################################################################################################
