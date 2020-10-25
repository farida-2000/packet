import struct
import socket
import string
import time
import argparse
import binascii
import textwrap
from getmac import get_mac_address
ishttp=0
def ip(data):
 maindata=data
 data=struct.unpack('!BBHHHBBH4s4s',data[:20])
 return[(data[0]>>4),(data[0] & 0xF)*4,data[1],data[2],data[3],data[4]>>13,data[4] &0x1FFF,data[5],data[6],hex(data[7]),socket.inet_ntoa(data[8]),socket.inet_ntoa(data[9]),maindata[((data[0] & 0xF)*4):]]

def icmp(data):
 types,code,checksum=struct.unpack('!BBH',data[:4])
 return[types,code,hex(checksum),repr(data[4:])]
def ether(data):
 dest_mac,src_mac,proto=struct.unpack('! 6s 6s H',data[:14])
 return[get_mac_address(dest_mac),get_mac_address(src_mac),socket.htons(proto),data[14:]]
class dns:
 def __init__(self,data):
  datacp=data
  data=struct.unpack('!HHHHHH',data[:12])
  self.id=data[0]
  self.flag(data[1])
  self.query=data[2]
  self.answer=data[3]
  self.athority=data[4]
  self.extra=data[5]
  self.data=datacp[12:]
  print("id:")
  print(self.id)
  print( "query: ")
  print(self.query)
  print( "answer: ")
  print(self.answer)
  print("extra inf: ")
  print(self.extra)
  print( "DATA:  ")
  print( data)
 def flag(self,bits):
  self.QR=(bits & 0x8000) >> 15
  self.OP=(bits & 0x8700) >> 11
  self.AA=(bits & 0x0400) >> 16
  self.TC=(bits & 0x0200) >> 9
  self.RD=(bits & 0x0100) >> 8
  self.RA=(bits & 0x0080) >> 7
  self.z=(bits & 0x0070) >> 4
  self.code=bits & 0x000F
  print("DNS flags are QR,OP,AA,TC,RD,RA,z,code  : " )
  print(self.QR)
  print(self.OP)
  print(self.AA)
  print(self.TC)
  print(self.RD)
  print(self.RA)
  print(self.z)
  print(self.code)
def eth_addr (a) :
 b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
 return b
class pcap:
 def __init__(self,filename,linktype=1):
  self.pcapfile=open('capture.pcap','wb')
  self.pcapfile.write(struct.pack('@IHHiIII',0xa1b2c3d4,2,4,0,0,65535,linktype))
 def write(self,data):
  sec,usec=map(int,str(time.time()).split('.'))
  length=len(data)
  self.pcapfile.write(struct.pack('@IIII',sec,usec,length,length))
  self.pcapfile.write(data)
 def close(self):
  self.pcapfile.close()
#def ipv4(data):
 #version_header=str(data[0])
 #version=version_header>>4
# headerlen=(version_header & 15)*4
 #ttl,proto,src,targer=struct.unpack('! 8x B B 2x 4s 4s',data[:20])
 #return version,headerlen,ttl,proto,ipv4(src),ipv4(target),data[headerlen:]
class ARP:
 def __init__(self):
  flag=1

 def arp(self,packetcp):
  (a ,b ,c ,d ,e ,f ,g ,h ,i ) = struct.unpack('2s2s1s1s2s6s4s6s4s',packet[14:42])

  hw_type=(binascii.hexlify(a)).decode('utf-8')
  proto_type=(binascii.hexlify(b)).decode('utf-8')
  hw_size=(binascii.hexlify(c)).decode('utf-8')
  proto_size=(binascii.hexlify(d)).decode('utf-8')
  opcode=(binascii.hexlify(e)).decode('utf-8')
  return (hw_type,proto_type,hw_size,proto_size,opcode,socket.inet_ntoa(g),socket.inet_ntoa(i))
class tcp:
 
  def __init__(self):
flag=1

  def tcp_protocol(self,packetcp):

  (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', packetcp[:14])
        offset = (offset_reserved_flags >> 12) * 4
      flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
    print("src port:" + str( src_port))
  print("dest port:" +str(dest_port))
print("seq num: "+str( sequence))
print("ack: "+str( acknowledgment))
print("flaf_urg: "+str( flag_urg))
print("flag_ack: " +str( flag_ack))
print("flag_psh: "+str( flag_psh))
print("flag_rst:"+ str( flag_rst))
  print("falg_syn: "+str( flag_syn))
print("flag_fin: "+str( flag_fin))
if dest_port==80 or src_port==80:
ishttp=1
data=packet[offset:]
return dest_port,src_port
class ICMP:
 def __init__(self):
  flag=1
 def icmp_protocol(self,packet,iph_length,eth_length):
  u = iph_length + eth_length
icmph_length = 4
icmp_header = packet[u:u+4]

#now unpack them :)
icmph = struct.unpack('!BBH' , icmp_header)

icmp_type = icmph[0]
code = icmph[1]
checksum = icmph[2]
print("ICMP")
print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

h_size = eth_length + iph_length + icmph_length
data_size = len(packet) - h_size
class UDP:
 def __init__(self):
  flag=1
 def udp_protocol(self,packet,iph_length , eth_length):
  u = iph_length + eth_length
udph_length = 8
udp_header = packet[u:u+8]

#now unpack them :)
udph = struct.unpack('!HHHH' , udp_header)

source_port = udph[0]
dest_port = udph[1]
length = udph[2]
checksum = udph[3]
print("UDP: ")
print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
h_size=eth_length+u


class HTTP:
 def __init__(self,raw_data):
   print("HTTP DATA: ")
   try:
    self.data=raw_data.decode('utf-8')
print(self.data)
   except:
self.data=raw_data
print(self.data)
   
   

 
   
   
 
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
packet = s.recvfrom(65565)

packet =packet[0]

packetcp=packet
#ether proccess and then call each class depending on protocol num,...
eth_length = 14

eth_header = packet[:eth_length]
eth = struct.unpack('!6s6sH' , eth_header)
ethertype=eth[2]
eth_protocol = socket.ntohs(eth[2])
print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12])
ether_header=ether(packet)
ip_head=ip(ether_header[3])
#Parse IP packets, IP Protocol number = 8 for IPV4
if eth_protocol == 8 :

ip_header = packet[eth_length:20+eth_length]


iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

version_ihl = iph[0]
version = version_ihl >> 4
ihl = version_ihl & 0xF

iph_length = ihl * 4

ttl = iph[5]
protocol = iph[6]
s_addr = socket.inet_ntoa(iph[8]);
d_addr = socket.inet_ntoa(iph[9]);

print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)


#TCP protocol
                        if protocol == 6 :


       tcp_obj=tcp()
tcp_obj.tcp_protocol(packetcp)
if ishttp==1:
   
http_obj=HTTP(iph)

else:
print("TCP data: ")
print(ether(packet)[3:])



#ICMP Packets
                        elif protocol == 1 :


print ("ICMP data: ")

icmp_header=icmp(ip_head[-1])
print(icmp_header)
icmp_obj=ICMP()
icmp_obj.icmp_protocol(packetcp,iph_length,eth_length)

#UDP packets
elif protocol == 17 :
udp_obj=UDP()
udp_obj.udp_protocol(packetcp,iph_length , eth_length)
print("UDP DATA:")
print(iph[8:])

else:
dns_obj=dns(packetcp)

if ethertype==2054:  
  arp_obj=ARP()
  print("ARP : ")
  print(arp_obj.arp(packetcp))
           



#pcap file frmt

pcap_obj=pcap('capture.pcap')
pcap_obj.write(packet)
pcap_obj.close()
