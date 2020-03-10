import socket
import struct
from datetime import datetime
from netmiko import ConnectHandler
import getpass


#To prevent Dos or DDOS attack
def block_ip(IP):
	cisco_switch = {
		'device_type': 'cisco_ios',
      		'ip': '10.0.0.1',
      		'username': 'cisco',
      		'password': 'cisco',
      		'secret' : 'cisco',
      		'verbose' : True,	
   	}

   	#start ssh session
   	net_connect = ConnectHandler(**cisco_switch)
   	net_connect.enable()
   
   	#create list of commands
   	config_commands=['ip access-list standard 10', 'no permit any']
   	output = net_connect.send_config_set(config_commands)
   
   	config_commands=['access-list 10 deny %s log'%(IP)]
   	output = net_connect.send_config_set(config_commands)
      
   	config_commands=['ip access-list standard 10', 'permit any']
   	output = net_connect.send_config_set(config_commands)
   
   	output = net_connect.send_command('show access-list 10')
   	print output

   	#disconnects ssh session
   	net_connect.disconnect()


s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)

#For IP to count dictionary
IP_count = {}

#For IP to timestamp dictionary
time_stamp = {}

#Set of blocked IP
blocked_ip = set()

#Set of white listed IP
white_ip= ('127.0.0.1','192.168.200.1','10.0.0.1','192.168.104.1')

#Create file to store attacked data 
file_txt = open("attack_DDoS.txt",'w')

#Timestamp for detection script
script_timestamp = str(datetime.now())
file_txt.writelines(script_timestamp)
file_txt.writelines("\n")

#No_of_IPs = 15


while True:
	#Capturing packet information
	pkt = s.recvfrom(2048)  	
	ip_time= datetime.now()
   	ipheader = pkt[0][14:34]
   	ip_hdr = struct.unpack("!8sB3s4s4s",ipheader)
   	IP = socket.inet_ntoa(ip_hdr[3])
   
 	#Condition for blocked and white listed IP  
   	if IP not in blocked_ip and IP not in white_ip:
      		print "The Source of the IP is:", IP
      		
		#Condition for IP count
      		if IP in IP_count:
         		IP_count[IP] = IP_count[IP]+1
         		print IP_count[IP]
         		
			#Condition IP timestamp update
         		if IP_count[IP] % 15 == 1:
				time_stamp[IP]= ip_time 

			#Condition to detect and prevent attack
         		if(IP_count[IP] == 15) and (ip_time - time_stamp[IP]).seconds < 120:
				line = "DDOS attack is Detected: "
            			file_txt.writelines(line)
            			file_txt.writelines(IP)
            			file_txt.writelines("\n")
            			block_ip(IP)
	    			blocked_ip.add(IP)
 			
			#Condition to restart IP count
         		if IP_count[IP] == 15:
            			IP_count[IP] = 0
         			
      		else:
         		IP_count[IP] = 1
			
			#Condition to update timestamp for first time IP
         		if IP_count[IP] % 15 == 1:
            			time_stamp[IP]= ip_time 





