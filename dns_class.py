
import socketserver
import struct
import time
import json
from random import randint
from httpdns_api import *
#import _thread
import threading
from black_list import black_list as blist
def rand_ip():
    return str(randint(0,255))+"."+str(randint(0,255))+"."+str(randint(0,255))+"."+str(randint(0,255))
class SinDNSQuery:
    def __init__(self, data):
        i = 1
        self.name = ''
        while True:
            d = data[i]
            if d == 0:
                break;
            if d < 32:
                self.name = self.name + '.'
            else:
                self.name = self.name + chr(d)
            i = i + 1
        self.querybytes = data[0:i + 1]
        (self.type, self.classify) = struct.unpack('>HH', data[i + 1:i + 5])
        self.len = i + 5
    def getbytes(self):
        return self.querybytes + struct.pack('>HH', self.type, self.classify)

# DNS Answer RRS
# this class is also can be use as Authority RRS or Additional RRS 
class SinDNSAnswer:
    def __init__(self, ip,ttl=3600*2):
        self.name = 49164
        self.type = 1
        self.classify = 1
        self.timetolive = ttl
        self.datalength = 4
        self.ip = ip
    def getbytes(self):
        res = struct.pack('>HHHLH', self.name, self.type, self.classify, self.timetolive, self.datalength)
        s = self.ip.split('.')
        res = res + struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
        return res
 
# DNS frame
# must initialized by a DNS query frame
class SinDNSFrame:
    def __init__(self, data):
        (self.id, self.flags, self.quests, self.answers, self.author, self.addition) = struct.unpack('>HHHHHH', data[0:12])
        self.query = SinDNSQuery(data[12:])
    def getname(self):
        return self.query.name
    def setip(self, ip,ttl=3600*2):
        self.answer = SinDNSAnswer(ip,ttl=ttl)
        self.answers = 1
        self.flags = 33152
    def getbytes(self):
        res = struct.pack('>HHHHHH', self.id, self.flags, self.quests, self.answers, self.author, self.addition)
        res = res + self.query.getbytes()
        if self.answers != 0:
            res = res + self.answer.getbytes()
        return res
# A UDPHandler to handle DNS query
class SinDNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        dns = SinDNSFrame(data)
        ip_OK=False
        Blocked=False
        socket = self.request[1]
        cli_addr=self.client_address
        #namemap = SinDNSServer.namemap
        if(dns.query.type==1):
            # If this is query a A record, then response it
            name = dns.getname();
            
            if not DNSblack.check_host(name):#检查不在黑名单
                if DNSserver.in_que(name):
                    print('Already finding %s'%(name))
                    return
                toip=DNSserver.get_name(name)
                DNSserver.out_que(name)
                if not toip:#检查缓存没有
                    #从httpdns获取
                    toip,ttl=httpdns(name)
                    if toip:#httpdns有
                        ip_OK=True
                        DNSserver.add_name(name,toip,ttl)
                else:#缓存有
                    ip_OK=True
            else:
                Blocked=True
            
        else:
            socket.sendto(data, self.client_address)
            return
        #发送
        if ip_OK:
            print(('%s: %s-->%s '%(self.client_address[0], name, toip)))
            dns.setip(toip)
        elif Blocked:
            toip=rand_ip()
            print(('Fatal %s: %s-->%s (%d)'%(self.client_address[0], name or 'none' , toip,dns.query.type)))
            dns.setip(toip,3600*24*35)
        else:
            print(('Noip %s: %s-->none (%d)'%(self.client_address[0], name or 'none',dns.query.type)))
            return
        socket.sendto(dns.getbytes(), self.client_address)
                
            

# DNS Server
# It only support A record query
# user it, U can create a simple DNS server
class SinDNSServer:
    def __init__(self, port=53):
        with open("hosts_ip.json","r") as f:
            self.namemap=json.load(f)
        with open("hosts_ttl.json","r") as f:
            self.ttlmap=json.load(f)
        #SinDNSServer.namemap = {}
        #SinDNSServer.ttlmap = {}
        self.lock=threading.Lock()
        self.qlock=threading.Lock()
        self.port = port
        self.cque=[]
    def add_name(self, name, ip,ttl=3600):
        self.lock.acquire()
        self.namemap[name] = ip
        self.ttlmap[name]=time.time()+ttl
        self.lock.release()
    def get_name(self,name):
        self.lock.acquire()
        if self.namemap.__contains__(name) and self.ttlmap.__contains__(name):
            if self.ttlmap[name]>time.time():
                print(name," - get from cache(",len(self.ttlmap),')')
                self.lock.release()
                return self.namemap[name]
            else:
                del self.namemap[name]
                del self.ttlmap[name]
                print(name," - overtime")
                self.lock.release()
                return False
        self.lock.release()
        return False
        
    def start(self):
        HOST, PORT = "0.0.0.0", self.port
        server = socketserver.ThreadingUDPServer((HOST, PORT), SinDNSUDPHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            self.end()
    def end(self):
        with open("hosts_ip.json","w") as f:
            json.dump(self.namemap,f)
        with open("hosts_ttl.json","w") as f:
            json.dump(self.ttlmap,f)
    def in_que(self,name):
        self.qlock.acquire()
        if self.cque.__contains__(name):
            self.qlock.release()
            return True
        else:
            self.cque.append(name)
            self.qlock.release()
            return False
    def out_que(self,name):
        self.qlock.acquire()
        if self.cque.__contains__(name):
            self.cque.remove(name)
        self.qlock.release()

DNSserver = SinDNSServer()
DNSblack = blist()