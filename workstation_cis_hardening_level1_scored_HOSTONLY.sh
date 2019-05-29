#! /bin/bash

# This script sets the network parameter controls that are needed if the system is only acting as a host.
# It only includes the two controls not included in the main workstation_cis_hardening_level1_scored.sh script

#########################################################################################################################################

# THIS SECTIONS CONFIRMS THAT THE SCRIPT HAS BEEN RUN WITH SUDO

if [[ $UID -ne 0 ]]; then
	echo "Need to run this script as root (with sudo)"
	exit 1
fi

echo "[I] Beginning hardening script now"

#########################################################################################################################################

# 3.1.1 Ensure IP forwarding is disabled (Scored)

echo "[i] Disabling IP forwarding"

if grep -q "^net.ipv4.ip_forward.*" /etc/sysctl.conf; then
	sed '/^net.ipv4.ip_forward.*/d' /etc/sysctl.conf
	echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
else
	echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
fi

sysctl -w net.ipv4.ip forward=0
sysctl -w net.ipv4.route.flush=1

#########################################################################################################################################

# 3.1.2 Ensure packet redirect sending is disabled (Scored)

echo "[i] Disabling packet redirect sending"

if grep -q "^net.ipv4.conf.all.send redirects.*" /etc/sysctl.conf; then
	sed '/^net.ipv4.conf.all.send redirects.*/d' /etc/sysctl.conf
	echo "net.ipv4.conf.all.send redirects = 0" >> /etc/sysctl.conf
else
	echo "net.ipv4.conf.all.send redirects = 0" >> /etc/sysctl.conf
fi

if grep -q "^net.ipv4.conf.default.send.redirects.*" /etc/sysctl.conf; then
	sed '/^net.ipv4.conf.default.send redirects.*/d' /etc/sysctl.conf
	echo "net.ipv4.conf.default.send redirects = 0" >> /etc/sysctl.conf
else
	echo "net.ipv4.conf.default.send redirects = 0" >> /etc/sysctl.conf
fi

sysctl -w net.ipv4.conf.all.send_redirects=0 
sysctl -w net.ipv4.conf.default.send_redirects=0 
sysctl -w net.ipv4.route.flush=1

##########################################################################################################################################
