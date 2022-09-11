import multiprocessing
from scapy.all import *

from monitor_ifc2 import Monitor

class ConnectionPhase:

	"""
	Establish a connection to the AP 
	"""

	def __init__(self, monitor_ifc,sta_mac,bssid):
		self.state = "Not Connected"
		self.mon_ifc = monitor_ifc
		self.sta_mac = sta_mac
		self.bssid = bssid

	def send_authentication(self):

		# sends authentication request and wait for response

		packet = Dot11(
			addr1=self.bssid,
			addr2=self.sta_mac,
			addr3=self.bssid) / Dot11Auth(
			algo=0, seqnum=0x0001,status=0x0000)
		packet.show()

		jobs = list()
		result_queue = multiprocessing.Queue()
		receive_process = multiprocessing.Process(
			target=self.mon_ifc.search_auth,
			args=(result_queue,))
		jobs.append(receive_process)
		send_process = multiprocessing.Process(
			target=self.mon_ifc.send_packet,
			args=(packet,))
		jobs.append(send_process)

		for job in jobs:
			job.start()
		for job in jobs:
			job.join()

		if result_queue.get():
			self.state = "Authenticated"


	def send_assoc_request(self, ssid):

		# sends association request and wait for response

		if self.state != "Authenticated":
			print("Wrong connection state for Assocation, client not authenticated")
			return 1


		packet = Dot11(
			addr1=self.bssid,
			addr2=self.sta_mac,
			addr3=self.bssid) / Dot11AssoReq(
				cap=0x1100, listen_interval=0x00a) / Dot11Elt(
					ID=0, info="{}".format(ssid))
		packet.show()

		jobs = list()
		result_queue = multiprocessing.Queue()
		receive_process = multiprocessing.Process(target=self.mon_ifc.search_assoc_resp,args=(result_queue,))
		jobs.append(receive_process)
		send_process = multiprocessing.Process(target=self.mon_ifc.send_packet,args=(packet, "AssoReq",))
		jobs.append(send_process)

		for job in jobs:
			job.start()
		for job in jobs:
			job.join()

		if result_queue.get():
			self.state = "Associated"

def main():
	monitor_ifc = "wlan0"
	sta_mac = "90:4c:e5:1b:f0:ba"
	#bssid = "90:35:6e:17:19:d0"
	bssid = "90:4c:e5:1b:f0:bf"
	conf.iface = monitor_ifc

	# convert the MAC in lowercase
	mon_ifc = Monitor(monitor_ifc,sta_mac.lower(),bssid.lower())
	connection = ConnectionPhase(mon_ifc,sta_mac,bssid)
	connection.send_authentication()
	if connection.state == "Authenticated":
		print("STA is authenticated to the AP!")
	else:
		print("STA is NOT authenticated to the AP!")
	time.sleep(1)
	connection.send_assoc_request(ssid="Rogue SSID")

	if connection.state == "Associated":
		print("STA is connected to the AP!")
	else:
		print("STA is NOT connected to the AP!")

if __name__ == "__main__":
	sys.exit(main())
