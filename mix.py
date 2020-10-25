import socket
import string
import sys, random
from struct import *
import binascii
import time
import argparse
import textwrap
import raw
import threading,thread
#from extra import *
import datetime
#import queue
#from services import services
import argparse
from Queue import Queue
delaywait=0
target2=""
queue = Queue()
open_ports = [] 
portss=[] 
class tcp:
 
  def __init__(self):
     flag=1

  def tcp_protocol(self,packetcp):
        (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = unpack('! H H L L H', packetcp[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        return flag_rst
  def calculate_win(self,packetcp):
  
        ip_header = packetcp[14:20+14]
        iph =unpack('!BBHHHBBH4s4s' , ip_header)
        winsize=ip_header[15]
        return winsize
class Packet:
    def __init__(self, src_ip, dest_ip, dest_port):
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0x28
        self.identification = 0xabcd
        self.flags = 0x0
        self.fragment_offset = 0x0
        self.ttl = 0x40
        self.protocol = 0x6
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.f_fo = (self.flags << 13) + self.fragment_offset
      #TCPSEG
        self.src_port = 0x3039
        self.dest_port = dest_port      
        self.seq_no = 0x0
        self.ack_no = 0x0
        self.data_offset = 0x5
        self.reserved = 0x0
        self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0
        self.window_size = 0x7110
        self.checksum = 0x0
        self.urg_pointer = 0x0
        self.data_offset_res_flags = (self.data_offset << 12) + (self.reserved << 9) + (self.ns << 8) + (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin
        
        ########
        # packet
        self.tcp_header = b""
        self.ip_header = b""
        self.packet = b""
       
       
    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (ord(msg[i]) << 8) + ord(msg[i+1])
            s = s + w
       # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

        
    def generate_tmp_ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                          self.identification, self.f_fo,
                                          self.ttl, self.protocol, self.header_checksum,
                                          self.src_addr,
                                          self.dest_addr)
        return tmp_ip_header


    def generate_tmp_tcp_header(self):
        tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                       self.seq_no,
                                       self.ack_no,
                                       self.data_offset_res_flags,              self.window_size,                        
                                       self.checksum, self.urg_pointer)
        return tmp_tcp_header


    def generate_packet(self):
        # IP header + checksum
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                                self.identification, self.f_fo,
                                                self.ttl, self.protocol, self.calc_checksum(self.generate_tmp_ip_header()),
                                                self.src_addr,
                                                self.dest_addr)
        # TCP header + checksum
        tmp_tcp_header = self.generate_tmp_tcp_header()
        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol, len(tmp_tcp_header))
        psh = pseudo_header + tmp_tcp_header
        final_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                             self.seq_no,
                                             self.ack_no,
                                             self.data_offset_res_flags, self.window_size,
                                             self.calc_checksum(psh), self.urg_pointer)
        
        self.ip_header = final_ip_header
        self.tcp_header = final_tcp_header
        self.packet = final_ip_header + final_tcp_header

    def send_packet(self):
        soo = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        soo.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        soo.sendto(self.packet, (self.dest_ip, 0))
        data = soo.recv(1024)
        soo.close()
        return data
def check_if_open(port, response):
    cont = binascii.hexlify(response)
    key=0  
    for key in raw.services:
          if raw.services[key]==port:
             serv=key
             print(serv)
    if cont[65:68] == b"012":
        print("Port "+str(port)+" is: open")
    else:
        print("Port "+str(port)+" is: closed")
class Packetack:
    def __init__(self, src_ip, dest_ip, dest_port):
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0x28
        self.identification = 0xabcd
        self.flags = 0x0
        self.fragment_offset = 0x0
        self.ttl = 0x40
        self.protocol = 0x6
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.f_fo = (self.flags << 13) + self.fragment_offset
      #TCPSEG
        self.src_port = 0x3039
        self.dest_port = dest_port      
        self.seq_no = 0x0
        self.ack_no = 0x0
        self.data_offset = 0x5
        self.reserved = 0x0
        self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
        self.window_size = 0x7110
        self.checksum = 0x0
        self.urg_pointer = 0x0
        self.data_offset_res_flags = (self.data_offset << 12) + (self.reserved << 9) + (self.ns << 8) + (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin
        
        ########
        # packet
        self.tcp_header = b""
        self.ip_header = b""
        self.packet = b""
       
       
    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (ord(msg[i]) << 8) + ord(msg[i+1])
            s = s + w
       # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

        
    def generate_tmp_ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                          self.identification, self.f_fo,
                                          self.ttl, self.protocol, self.header_checksum,
                                          self.src_addr,
                                          self.dest_addr)
        return tmp_ip_header


    def generate_tmp_tcp_header(self):
        tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                       self.seq_no,
                                       self.ack_no,
                                       self.data_offset_res_flags,              self.window_size,                        
                                       self.checksum, self.urg_pointer)
        return tmp_tcp_header


    def generate_packet(self):
        # IP header + checksum
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                                self.identification, self.f_fo,
                                                self.ttl, self.protocol, self.calc_checksum(self.generate_tmp_ip_header()),
                                                self.src_addr,
                                                self.dest_addr)
        # TCP header + checksum
        tmp_tcp_header = self.generate_tmp_tcp_header()
        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol, len(tmp_tcp_header))
        psh = pseudo_header + tmp_tcp_header
        final_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                             self.seq_no,
                                             self.ack_no,
                                             self.data_offset_res_flags, self.window_size,
                                             self.calc_checksum(psh), self.urg_pointer)
        
        self.ip_header = final_ip_header
        self.tcp_header = final_tcp_header
        self.packet = final_ip_header + final_tcp_header

        
    def send_packet(self):
        soo = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        soo.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        soo.sendto(self.packet, (self.dest_ip, 0))
        data = soo.recv(1024)
        soo.close()
        return data
def check_if_openack(port, response):
    cont = binascii.hexlify(response)
    key=0  
    for key in raw.services:
          if raw.services[key]==port:
             serv=key
             print(serv)
    obj=tcp()
    rst=obj.tcp_protocol(response)
    if  rst== 1:
        print("Port "+str(port)+" is: open")
    else:
        print("Port "+str(port)+" is: closed")
class Packetfin:
    def __init__(self, src_ip, dest_ip, dest_port):
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0x28
        self.identification = 0xabcd
        self.flags = 0x0
        self.fragment_offset = 0x0
        self.ttl = 0x40
        self.protocol = 0x6
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.f_fo = (self.flags << 13) + self.fragment_offset
      #TCPSEG
        self.src_port = 0x3039
        self.dest_port = dest_port      
        self.seq_no = 0x0
        self.ack_no = 0x0
        self.data_offset = 0x5
        self.reserved = 0x0
        self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1
        self.window_size = 0x7110
        self.checksum = 0x0
        self.urg_pointer = 0x0
        self.data_offset_res_flags = (self.data_offset << 12) + (self.reserved << 9) + (self.ns << 8) + (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin
        
        ########
        # packet
        self.tcp_header = b""
        self.ip_header = b""
        self.packet = b""
       
       
    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (ord(msg[i]) << 8) + ord(msg[i+1])
            s = s + w
       # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

        
    def generate_tmp_ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                          self.identification, self.f_fo,
                                          self.ttl, self.protocol, self.header_checksum,
                                          self.src_addr,
                                          self.dest_addr)
        return tmp_ip_header


    def generate_tmp_tcp_header(self):
        tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                       self.seq_no,
                                       self.ack_no,
                                       self.data_offset_res_flags,              self.window_size,                        
                                       self.checksum, self.urg_pointer)
        return tmp_tcp_header


    def generate_packet(self):
        # IP header + checksum
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                                self.identification, self.f_fo,
                                                self.ttl, self.protocol, self.calc_checksum(self.generate_tmp_ip_header()),
                                                self.src_addr,
                                                self.dest_addr)
        # TCP header + checksum
        tmp_tcp_header = self.generate_tmp_tcp_header()
        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol, len(tmp_tcp_header))
        psh = pseudo_header + tmp_tcp_header
        final_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                             self.seq_no,
                                             self.ack_no,
                                             self.data_offset_res_flags, self.window_size,
                                             self.calc_checksum(psh), self.urg_pointer)
        
        self.ip_header = final_ip_header
        self.tcp_header = final_tcp_header
        self.packet = final_ip_header + final_tcp_header   
    def send_packet(self):
        soo = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        soo.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        soo.sendto(self.packet, (self.dest_ip, 0))
        data = soo.recv(1024)
        soo.close()
        return data
def check_if_openfin(port, response):
    cont = binascii.hexlify(response)
    key=0  
    for key in raw.services:
          if raw.services[key]==port:
             serv=key
             print(serv)
    obj=tcp()
    rst=obj.tcp_protocol(response)
    if rst==1:
        print("Port "+str(port)+" is: closed")
    else:
        print("Port "+str(port)+" is: open")
def local_ip():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.connect(('8.8.8.8',1))
    return s.getsockname()[0]

def dedicate_local_port():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.bind(('',0))
    return s.getsockname()[1]

class Packetwin:
    def __init__(self, src_ip, dest_ip, dest_port):
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0x28
        self.identification = 0xabcd
        self.flags = 0x0
        self.fragment_offset = 0x0
        self.ttl = 0x40
        self.protocol = 0x6
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.f_fo = (self.flags << 13) + self.fragment_offset
      #TCPSEG
        self.src_port = 0x3039
        self.dest_port = dest_port      
        self.seq_no = 0x0
        self.ack_no = 0x0
        self.data_offset = 0x5
        self.reserved = 0x0
        self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
        self.window_size = 0x7110
        self.checksum = 0x0
        self.urg_pointer = 0x0
        self.data_offset_res_flags = (self.data_offset << 12) + (self.reserved << 9) + (self.ns << 8) + (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin
        
        ########
        # packet
        self.tcp_header = b""
        self.ip_header = b""
        self.packet = b""
       
       
    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (ord(msg[i]) << 8) + ord(msg[i+1])
            s = s + w
       # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

        
    def generate_tmp_ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                          self.identification, self.f_fo,
                                          self.ttl, self.protocol, self.header_checksum,
                                          self.src_addr,
                                          self.dest_addr)
        return tmp_ip_header


    def generate_tmp_tcp_header(self):
        tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                       self.seq_no,
                                       self.ack_no,
                                       self.data_offset_res_flags,              self.window_size,                        
                                       self.checksum, self.urg_pointer)
        return tmp_tcp_header


    def generate_packet(self):
        # IP header + checksum
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                                self.identification, self.f_fo,
                                                self.ttl, self.protocol, self.calc_checksum(self.generate_tmp_ip_header()),
                                                self.src_addr,
                                                self.dest_addr)
        # TCP header + checksum
        tmp_tcp_header = self.generate_tmp_tcp_header()
        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol, len(tmp_tcp_header))
        psh = pseudo_header + tmp_tcp_header
        final_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                             self.seq_no,
                                             self.ack_no,
                                             self.data_offset_res_flags, self.window_size,
                                             self.calc_checksum(psh), self.urg_pointer)
        
        self.ip_header = final_ip_header
        self.tcp_header = final_tcp_header
        self.packet = final_ip_header + final_tcp_header

        
    def send_packet(self):
        soo = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        soo.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        soo.sendto(self.packet, (self.dest_ip, 0))
        data = soo.recv(1024)
        soo.close()
        return data
def check_if_openwin(port, response):
    cont = binascii.hexlify(response)
    key=0  
    for key in raw.services:
          if raw.services[key]==port:
             serv=key
             print(serv)
    obj=tcp()
    rst=obj.tcp_protocol(response)
    winf=obj.calculate_win(response)
    if rst == 1 and winf!=0:
        print("Port "+str(port)+" is: open")
    elif rst==1 and winf==0:
        print("Port "+str(port)+" is: closed")
    else:
        print("Port "+str(port)+" is: filtered")
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    target =raw_input('enter the target command: ')
    global i
    i=0
    while i<(len(target)):
        if target[i]=='-' and target[i+1]=='t':
            i=i+3
            sp=i
            f=i
            ip=""
            host=""
            i2=i
            while i2<(len(target)):      
                if target[i2]==' ':
                    break
                else:
                    f=f+1
                    fp=f
                    i2=i2+1
            host=target[sp:fp]
            i=i2
            ip=socket.gethostbyname(host)
            target2=ip
            print(ip)
        if target[i]=='-' and target[i+1]=='p':
            i=i+3
            sp=i
            f=i
            firstport=0
            secondport=0
            port=""
            i2=i
            while i2<(len(target)):      
                if target[i2]==' ':
                    break
                else:
                    f=f+1
                    fp=f
                    i2=i2+1
            port=target[sp:fp]
            i=i2
            f=0
            sfirst=""
            ssecond=""
            while f<(len(port)):
                if port[f]=='-':
                    f=f+1
                    break
                else:
                    f=f+1
                    fp=f
            sfirst=port[0:fp]
            ssecond=port[f:len(port)]
            firstport=int(sfirst, base=10)
            secondport=int(ssecond, base=10)
            if secondport>65535:
                 secondport=65535
            if firstport<0:
                 firstport=0
            print(firstport,secondport)
        if target[i]=='-' and target[i+1]=='s':
            type=""
            i=i+3
            type=target[i:i+2]
            i=i+1
            print(type)
        if target[i]=='-' and target[i+1]=='d':
            i=i+3
            sp=i
            f=i
            sdelay=""
            i2=i
            while i2<(len(target)):      
                if i2>=(len(target)) or target[i2]==' ':
                    break
                else:
                    f=f+1
                    fp=f
                    i2=i2+1
            sdelay=target[sp:fp]
            i=i2
            delay=int(sdelay, base=10)
            delaywait=delay
            print(delay)
        i=i+1
    scan(ip,firstport,secondport,type,delay)
def scan(ip,firstport,secondport,type,delay):
    if type=="CS":
        csfunc(ip,firstport,secondport,type,delay)
    if type=="AS":
        asfunc(ip,firstport,secondport,type,delay)
    if type=="SS":
        ssfunc(ip,firstport,secondport,type,delay)
    if type=="FS":
        fsfunc(ip,firstport,secondport,type,delay)
    if type=="WS":
        wsfunc(ip,firstport,secondport,type,delay)
def csfunc(ip,firstport,secondport,type,delay):
    start=time.time()    
    so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secondport=secondport+1
    for port in range(firstport,secondport):
             key=0  
             for key in raw.services:
                 if raw.services[key]==port:
                     serv=key
                     print(serv)                                                
             try:
                   so.connect((ip, port))
                   print("Port open: " + str(port))
                   so.close()
             except:
                   print("Port closed: " + str(port))
             time.sleep(delay)
  
def asfunc(ip,firstport,secondport,type,delay):
   hostname = socket.gethostname()    
   IPAddr = socket.gethostbyname(hostname)
   for port in range(firstport,secondport+1):
     pck = Packetack(IPAddr, ip, port)
     pck.generate_packet()
     result = pck.send_packet()
     check_if_openack(port, result)
     time.sleep(delay)
def ssfunc(ip,firstport,secondport,type,delay):
  hostname = socket.gethostname()    
  IPAddr = socket.gethostbyname(hostname)
  for port in range(firstport,secondport+1):
     p = Packet(IPAddr, ip, port)
     p.generate_packet()
     result = p.send_packet()
     check_if_open(port, result)
     time.sleep(delay) 
def fsfunc(ip,firstport,secondport,type,delay):
  hostname = socket.gethostname()    
  IPAddr = socket.gethostbyname(hostname)
  for port in range(firstport,secondport+1):
     p = Packetfin(IPAddr, ip, port)
     p.generate_packet()
     result = p.send_packet()
     check_if_openfin(port, result)
     time.sleep(delay)
 
def wsfunc(ip,firstport,secondport,type,delay):
  hostname = socket.gethostname()    
  IPAddr = socket.gethostbyname(hostname)
  for port in range(firstport,secondport+1):
     p = Packetwin(IPAddr, ip, port)
     p.generate_packet()
     result = p.send_packet()
     check_if_openwin(port, result)
     time.sleep(delay)

main()
