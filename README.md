# Ubuntu-18.04-LTS-CIS-Hardening
Hardening guides and scripts for Ubuntu 18.04 LTS which is compliant with the CIS Benchmark


The 'Level 1 - scored' script is now completed and has been tested on a HP Pavillion running Ubuntu 19.04 with no issues.

The 'Level 1 - scored - HOST ONLY' script is also complete and tested.

I'll finish the other scripts when I get chance.

## auditing_script.sh
This script should run as `sudo` and it will install some libraries onto the system, and after running the scans, in the end it will be prompting for password again to clean up the installed libraries so that the machine will return to its original state.
```
sudo ./auditing_script.sh ^C
```
The machine will then forced to reboot and after rebooting, there will be a file called `audit_results.txt` generated on the same directory as `auditing script.sh`
