import struct
import socket

import time

from Crypto.Random.random import Random

from utils import Block
from tls import TLS
"""
from tls2 import TLS
"""

from certs import Certificates,certASN12PEM,certPEM2ASN1,certGetPubKey
from torcrypto import publicPEM2ASN1,sign_RSA_SHA256,new_HMAC_SHA256,new_AES_CTR_128,new_SHA256,new_PKCS1_OAEP,getKeySizeRSA,new_SHA1


class Cell:
    
    CELL_PADDING=0
    CELL_CREATE=1
    CELL_CREATED=2
    CELL_RELAY=3
    CELL_DESTROY=4
    CELL_CREATE_FAST=5
    CELL_CREATED_FAST=6
    CELL_VERSIONS=7
    CELL_NETINFO=8
    CELL_RELAY_EARLY=9
    CELL_CREATE2=10
    CELL_CREATED2=11
    
    CELL_VPADDING=128
    CELL_CERTS=129
    CELL_AUTH_CHALLENGE=130
    CELL_AUTHENTICATE=131
    CELL_AUTHORIZE=132
    CELL_COMMAND_MAX_=132
    
    
    CELL_MAX_NETWORK_SIZE = 514
    CELL_PAYLOAD_SIZE = 509
    
    AUTHTYPE_RSA_SHA256_TLSSECRET = 1
    
    ONION_HANDSHAKE_TYPE_TAP = 0
    
        
    def __init__(self,ip,port):
        self.ip=ip
        self.port=port
        self.send_digest=new_SHA256()
        self.recv_digest=new_SHA256()
        self.tls=TLS(self.ip, self.port)

    def isVarLen(self,cmd):
        if cmd==self.CELL_VERSIONS:
            return True
        if cmd>=128:
            return True
        return False
    
    def connect(self):
        self.tls.connect()
        
    def packCELL(self,cmd,payload,circID=0,isWideID=True):

        if self.isVarLen(cmd):
            l=struct.pack('>H',len(payload))
        else:
            l=''
            payload=payload+'\x00'*(self.CELL_PAYLOAD_SIZE-len(payload))
            
        if isWideID:
            id=struct.pack('>I',circID)
        else:
            id=struct.pack('>H',circID)
            
        msg=id+chr(cmd)+l+payload
        return msg
    
    def unpackCELL(self,data,isWideID=True):
        if isWideID:
            circID,cmd,size=struct.unpack(">IBH",data[:7])
            return circID,cmd,size,data[7:7+size]
        else:
            circID,cmd,size=struct.unpack(">HBH",data[:5])
            return circID,cmd,size,data[5:5+size]
    

    def sendCELL(self,cmd,payload,circID=0,isWideID=True):
        msg=self.packCELL(cmd, payload,circID,isWideID)
        self.send_digest.update(msg)
        self.tls.write(msg)


    def recvCELL(self):
        msg=self.tls.read(3)
        self.recv_digest.update(msg)
        circId,cmd=struct.unpack(">HB",msg)
        if circId==0 and cmd==self.CELL_VERSIONS:
            data=self.tls.read(2)
            self.recv_digest.update(data)
            size,=struct.unpack(">H",data)
            data=self.tls.read(size)
            self.recv_digest.update(data)
            return circId,cmd,data

        m=self.tls.read(2)
        self.recv_digest.update(m)
        msg+=m
        circId,cmd=struct.unpack(">IB",msg)
        if self.isVarLen(cmd)==False:
            m=self.tls.read(self.CELL_PAYLOAD_SIZE)
            self.recv_digest.update(m)
            return circId,cmd,m
        
        m=self.tls.read(2)
        self.recv_digest.update(m)
        size,=struct.unpack(">H",m)
        m=self.tls.read(size)
        self.recv_digest.update(m)
        return circId,cmd,m

    
    
    def sendVERSIONS(self,versions=[]):
        b=Block()
        for v in versions:
            b.u16(v)
        self.sendCELL(self.CELL_VERSIONS, b.get(),isWideID=False)
            
    def unpackVERSION(self,data):
        versions=[]
        b=Block(data)
        while b.isEmpty():
            v=b.u16()
            versions.append(v)
        return versions
        
    
    def ip2int(self,addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]
    
    
    def int2ip(self,addr):                                                               
        return socket.inet_ntoa(struct.pack("!I", addr))
    
    def packADDR(self,ip):
        return struct.pack(">BBI",4,4,self.ip2int(ip))
    
    def sendNETINFO(self):
        b=Block()
        b.u32(time.time())
        b.push(self.packADDR(self.ip))
        b.u8(0)
        msg=b.get()
        msg=msg
        self.sendCELL(self.CELL_NETINFO,msg,circID=0)
        
        
    def unpackADDR(self,b):
        typeIP=b.u8()
        sizeIP=b.u8()
        ip=b.pop(sizeIP)
        return (typeIP,ip)
        
    def unpackNETINFO(self,data):
        b=Block(data)
        myIP=None
        timeNow=b.u32()
        
        
        (typeMyIP,myIP)=self.unpackADDR(b)
        
        addresses=[]
        n=b.u8()
        for i in range(0,n):
            (typeIP,ip)=self.unpackADDR(b)
            addresses.append((typeIP,ip))
        
        return timeNow,(typeMyIP,myIP),addresses
    
    def unpackCERTS(self,data):
        b=Block(data)
        certs=[]
        n=b.u8()
        for i in range(0,n):
            cType=b.u8()
            cLen=b.u16()
            cert=b.pop(cLen)
            certs.append((cType,certASN12PEM(cert)))
        return certs
    
    def unpackAUTH_CHALLENGE(self,data):
        b=Block(data)
        challenge=b.pop(32)
        n=b.u16()
        methods=[]
        for i in range(0,n):
            methods.append(b.u16())
        return challenge,methods
    
    
    def sendCERTS(self,certs):
        b=Block()
        b.u8(len(certs))
        for typeCert,cert in certs:
            cert=certPEM2ASN1(cert)
            b.u8(typeCert)
            b.u16(len(cert))
            b.push(cert)
            
        self.sendCELL(self.CELL_CERTS, b.get())
    
    def sendAUTHENTICATE(self,certs,certsMy):
        idCert=None
        linkCert=None
        for typeCert,cert in certs:
            if typeCert==Certificates.OR_CERT_TYPE_ID_1024:
                idCert=cert
            if typeCert==Certificates.OR_CERT_TYPE_TLS_LINK:
                linkCert=cert
                
        if not idCert or not linkCert:
            raise Exception('invalid certs')
                
        b=Block()
        b.u16(self.AUTHTYPE_RSA_SHA256_TLSSECRET)
        auth=Block()
        auth.push('AUTH0001')
        pk=certGetPubKey(certsMy.idCert)
        
        auth.push(new_SHA256(publicPEM2ASN1(pk)).digest())
        pk=certGetPubKey(idCert)
        auth.push(new_SHA256(publicPEM2ASN1(pk)).digest())
        auth.push(self.recv_digest.digest())
        auth.push(self.send_digest.digest())
        auth.push(new_SHA256(certPEM2ASN1(linkCert)).digest())
        
        tlssecret=Block()
        tlssecret.push(self.tls.conn.client_random())
        tlssecret.push(self.tls.conn.server_random())
        tlssecret.push("Tor V3 handshake TLS cross-certification\x00")

        auth.push(new_HMAC_SHA256(self.tls.conn.master_key(),tlssecret.get()).digest())
        auth.push(Random.new().read(24))
        
        sign=sign_RSA_SHA256(certsMy.authKey, auth.get())
        
        
        auth.push(sign)
        b.u16(len(auth.get()))
        b.push(auth.get())        
        self.sendCELL(self.CELL_AUTHENTICATE, b.get())
        
    def sendAUTH_CHALLENGE(self,methods=[]):
        b=Block()
        b.push(Random.new().read(32))
        
        b.u16(len(methods))
        for i in methods:
            b.u16(i)
               
        self.sendCELL(self.CELL_AUTH_CHALLENGE,b.get())
        

    def sendCREATE(self,msg,circID=0):
        b=Block()
        b.push(msg)
        self.sendCELL(self.CELL_CREATE,b.get(),circID)
        
    def sendRELAY(self,msg,circID=0):
        self.sendCELL(self.CELL_RELAY,msg,circID)

    def send_RELAY_EARLY(self,msg,circID=0):
        self.sendCELL(self.CELL_RELAY_EARLY,msg,circID)
