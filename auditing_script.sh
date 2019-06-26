#! /bin/bash

# This script has been written to automate the auditing of all the scored level 1 controls that have been applied by the hardening scipt: 
# workstation_cis_hardening_level1_scored.sh	

# The script will generate an 'audit_results.txt' file which should be provided for review.


#########################################################################################################################################

# Confirming that the script has been run with sudo

if [[ $EUID -ne 0 ]]; then
	echo "You need to run this script as root (with sudo)"
	exit
fi

echo "[i] Beginning the auditing process"


#########################################################################################################################################

# 1.1.3 Ensure nodev option set /tmp partition (Scored)
# 1.1.4 Ensure nosuid option set on /tmp partition (Scored)

echo "[i] Ensuring that nodev & nosuid are set on the /tmp partition"


grep -F "$LINETMP" /etc/fstab || echo "$LINETMP" | tee -a /etc/fstab > /dev/null


touch ./audit_results.txt
echo "[i] Getting the current system time and date: " | tee -a ./audit_results.txt
date | tee -a ./audit_results.txt
echo ""
echo "[i]This script has been run on the following machine: " | tee -a ./audit_results.txt
hostname | tee -a ./audit_results.txt
echo ""
echo "[i] Getting a list of all non-system users: " | tee -a ./audit_results.txt
eval getent passwd {$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)} | cut -d: -f1 | tee -a ./audit_results.txt
