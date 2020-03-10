# Detection-and-Prevention-of-Dos-and-DDoS-using-Python
Detection and Prevention of Dos and DDoS attack using Python

1: Network Topology: Created a network topology using GNS3 and VMware workstation pro to demonstrate the detection and prevention of Dos and DDos attacks. Used two virtual machines with ubuntu-16 as an OS. One acting as an Attacker and other acting as a Victim. Both connecting each other via a legacy cisco router separating the two networks and also acting as Basic Firewall between the two networks.

2: Creating python script for Attacker: Created a python script for DDos attack where the Attacker bombard thousands of ping packets to the victim’s machine with 4 different IPs on all 65,536 ports one by one. For dos attack we can generate a script which will send thousands of ping packets to the Victim machine using one IP only on all 65,536 ports one by one.

3: Creating python script for Victim: Created a python script for detecting Dos and DDos attack. The logic used to create this script is if the victim receives 15 or more ping packets within a time span of 120 secs, then this script will detect the same and alert the victim about a Dos or DDos attack. The same script also logs the list of IP addresses that are used to generate the attacks and generates a text file on the victim’s machine.

4: Network Automation (Pushing ACL to the Router): A part of the Detection script being used on victim also contains a code which generates and push ACL(Access-Lists) directly to the legacy cisco router. This part of the script uses the Text file that is logged on victim machine containing the blocked attackers IP’s. The router then blocks the attackers IP on real time basis within few seconds instead of manually generating the ACL’s which might take several minutes.
