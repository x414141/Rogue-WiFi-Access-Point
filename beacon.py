from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

netSSID = 'Rogue SSID' # network name
iface = 'wlan0' # interface that will advertise the network

dot11 = Dot11(type=0,subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2='90:4C:E5:1B:F0:BF',
				addr3='90:4C:E5:1B:F0:BF')
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

frame = RadioTap()/dot11/beacon/essid#/rsn
frame.show()
print("\nHexDump of frame:")
hexdump(frame)
raw_input("\nPress enter to start broadcasting\n")

sendp(frame, iface=iface, inter=0.100, loop=1)