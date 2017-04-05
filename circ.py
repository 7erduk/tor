import struct
from certs import Certificates
from onion import Onion
from cell import Cell
from desc import Descriptors
import socket

class Circ:
    def __init__(self,routers,n=3,idKey=None,linkKey=None,authKey=None,idCert=None,authCert=None,linkCert=None):
        if n==0:
            raise Exception('invalid length circ')
        self.n=n
        self.desc=Descriptors(routers)
        self.certsMy=None
        if idKey and linkKey and authKey and idCert and authCert and linkCert:
            self.certsMy=Certificates()
            self.certsMy.loadCerts(idKey,linkKey,authKey,idCert,authCert,linkCert)
        

    def auth(self,ip,port):
        self.cell=Cell(ip, port)
        self.cell.connect()
        
        self.cell.sendVERSIONS([3,4])
        circId,cmd,data=self.cell.recvCELL()
        if cmd!=self.cell.CELL_VERSIONS:
            raise Exception('error cell CELL_VERSIONS')
        versions=self.cell.unpackVERSION(data)
        print "auth cell versions are",versions
        
        circId,cmd,data=self.cell.recvCELL()
        if cmd!=self.cell.CELL_CERTS:
            raise Exception('error cell CELL_CERTS')
        certs=self.cell.unpackCERTS(data)


        circId,cmd,data=self.cell.recvCELL()
        if cmd!=self.cell.CELL_AUTH_CHALLENGE:
            raise Exception('error cell CELL_AUTH_CHALLENGE')
        print "auth challenge is",data.encode('hex')
        self.cell.unpackAUTH_CHALLENGE(data)
        
        if self.certsMy:
            self.certsMy.verifyCerts(certs)
            
            typeCert,cert=certs[0]
            typeCert2,cert2=certs[1]
            print "cell certificates are",certs
            
            self.cell.sendCERTS([(Certificates.OR_CERT_TYPE_AUTH_1024,self.certsMy.authCert),
                            (Certificates.OR_CERT_TYPE_ID_1024,self.certsMy.idCert)
                            ])
            
            
            self.cell.sendAUTHENTICATE(certs,self.certsMy)
        
        
        circId,cmd,data=self.cell.recvCELL()
        if cmd!=self.cell.CELL_NETINFO:
            raise Exception('error CELL_NETINFO')
        timeNow,(typeMyIP,myIP),addresses=self.cell.unpackNETINFO(data)
        if typeMyIP==4:
            print "my remote ip is",socket.inet_ntoa(myIP)
        self.cell.sendNETINFO()
        
        
    def make(self,circId,ip=None,port=None,fingerprint=None):
        self.cicrId=circId
        self.onions=[]
        
        print "circ is creating"
        
        r=self.desc.randRouter()
        
        self.auth(r['address'], r['or_port'])
        
        
        onion=Onion(r['onion_key'])
        skin=onion.makeSkin()
        self.cell.sendCREATE(skin,self.cicrId)
        circId,cmd,data=self.cell.recvCELL()
        if cmd!=self.cell.CELL_CREATED:
            raise Exception('error CELL_CREATED')
        onion.getSharedKey(data)
        
        r['onion']=onion
        self.onions.append(r)
               
        print 'the first cell auth is good'
        
        
        for i in range(1,self.n):#step create onions
            print "cell number %d is creating" % i
            if i==self.n-1:
                if ip and port:
                    r=self.desc.randRouter(ip,port)
                elif fingerprint:
                    r=self.desc.routers.get(fingerprint)
                    if r==None:
                        raise Exception('error fingerprint of router')
                else:
                    r=self.desc.randRouter()
            else:
                r=self.desc.randRouter()
            o=Onion(r['onion_key'])
            skin=o.makeSkin()
            msg=self.onions[i-1]['onion'].packRELAY_EXTEND(r['address'], r['or_port'], skin,r['signing_key'])
            
            for r2 in self.onions[:i][::-1]:
                msg=r2['onion'].encrypt(msg)
                
            self.cell.send_RELAY_EARLY(msg,self.cicrId)
            circId,cmd,msg=self.cell.recvCELL()
            if cmd!=self.cell.CELL_RELAY_EARLY and cmd!=self.cell.CELL_RELAY:
                raise Exception('error RELAY')
            
            for r2 in self.onions[:i]:
                msg=r2['onion'].decrypt(msg)
            
            cmd,streamID,msg=self.onions[i-1]['onion'].unpackRELAY(msg)
            if cmd != Onion.RELAY_EXTENDED:
                raise Exception('error RELAY_EXTENDED')
            o.getSharedKey(msg)
            r['onion']=o
            self.onions.append(r)
        
        if len(self.onions)!=self.n:
            raise Exception('error create circ')
        print 'circ has done'


    def make2(self,ip,port,circId):
        self.cicrId=circId
        self.onions=[]
        for i in range(0,self.n-1):
            o={}
            r=self.desc.randRouter()
            if r==None:
                raise Exception('no router')
            
            o['or_port']=r['or_port']
            o['address']=r['address']
            o['onion_key']=r['onion_key']
            o['signing_key']=r['signing_key']
            o['onion']=Onion(o['onion_key'])
            self.onions.append(o)
        
        o={}
        r=self.desc.randRouter(ip,port)
        if r==None:
            raise Exception('no router')
        o['or_port']=r['or_port']
        o['address']=r['address']
        o['onion_key']=r['onion_key']
        o['signing_key']=r['signing_key']
        o['onion']=Onion(o['onion_key'])
        self.onions.append(o)
        
        r=self.onions[0]
        
        self.cell=Cell(r['address'], r['or_port'])
        self.cell.connect()
        
        self.cell.sendVERSIONS([3,4])
        circId,cmd,data=self.cell.recvCELL()
        if cmd!=self.cell.CELL_VERSIONS:
            raise Exception('error cell CELL_VERSIONS')
        versions=self.cell.unpackVERSION(data)
        print versions
        
        circId,cmd,data=self.cell.recvCELL()
        if cmd!=self.cell.CELL_CERTS:
            raise Exception('error cell CELL_CERTS')
        certs=self.cell.unpackCERTS(data)


        circId,cmd,data=self.cell.recvCELL()
        if cmd!=self.cell.CELL_AUTH_CHALLENGE:
            raise Exception('error cell CELL_AUTH_CHALLENGE')
        print data.encode('hex')
        print self.cell.unpackAUTH_CHALLENGE(data)
        
        if self.certsMy:
            self.certsMy.verifyCerts(certs)
            
            typeCert,cert=certs[0]
            typeCert2,cert2=certs[1]
            print certs
            
            self.cell.sendCERTS([(Certificates.OR_CERT_TYPE_AUTH_1024,self.certsMy.authCert),
                            (Certificates.OR_CERT_TYPE_ID_1024,self.certsMy.idCert)
                            ])
            
            
            self.cell.sendAUTHENTICATE(certs,self.certsMy)
        
        
        circId,cmd,data=self.cell.recvCELL()
        if cmd!=self.cell.CELL_NETINFO:
            raise Exception('error CELL_NETINFO')
        print self.cell.unpackNETINFO(data)
    
        self.cell.sendNETINFO()

        r=self.onions[0]
        onion=r['onion']
        skin=onion.makeSkin()
        self.cell.sendCREATE(skin,self.cicrId)
        circId,cmd,data=self.cell.recvCELL()
        if cmd!=self.cell.CELL_CREATED:
            raise Exception('error CELL_CREATED')
        onion.getSharedKey(data)
        
        print 'auth good'
        
        
        for i in range(1,self.n):#step create onions
            r=self.onions[i]
            o=r['onion']
            skin=o.makeSkin()
            msg=self.onions[i-1]['onion'].packRELAY_EXTEND(r['address'], r['or_port'], skin,r['signing_key'])
            
            for r2 in self.onions[:i][::-1]:
                msg=r2['onion'].encrypt(msg)
                
            self.cell.send_RELAY_EARLY(msg,self.cicrId)
            circId,cmd,msg=self.cell.recvCELL()
            if cmd!=self.cell.CELL_RELAY_EARLY and cmd!=self.cell.CELL_RELAY:
                raise Exception('error RELAY')
            
            for r2 in self.onions[:i]:
                msg=r2['onion'].decrypt(msg)
            
            cmd,streamID,msg=self.onions[i-1]['onion'].unpackRELAY(msg)
            if cmd != Onion.RELAY_EXTENDED:
                raise Exception('error RELAY_EXTENDED')
            o.getSharedKey(msg)
        
        print 'circ done'

    
    def encrypt(self,msg):
        for r in self.onions[::-1]:
            msg=r['onion'].encrypt(msg)
        return msg
        
            
    def decrypt(self,msg):
        for r in self.onions:
            msg=r['onion'].decrypt(msg)
        return msg        
        
    def sendRELAY_EARLY(self,cmd,streamId,msg):
        r=self.onions[self.n-1]
        msg=r['onion'].packPELAY(cmd,streamId,msg)
        msg=self.encrypt(msg)
        self.cell.send_RELAY_EARLY(msg, circID=self.cicrId)
        
    def recvRELAY_EARLY(self):
        circId,cmd,msg=self.cell.recvCELL()
        if cmd!=self.cell.CELL_RELAY_EARLY and cmd!=self.cell.CELL_RELAY:
            raise Exception('error RELAY')
        if circId!=self.cicrId:
            raise Exception('error circId')
        msg=self.decrypt(msg)
        r=self.onions[self.n-1]
        cmd,streamID,msg=r['onion'].unpackRELAY(msg)
        return cmd,streamID,msg
    
    def sendRELAY_BEGIN_IPv4(self,sId,ip,port):
        self.sendRELAY_EARLY(Onion.RELAY_BEGIN,sId,"%s:%d\x00" % (ip,port)+struct.pack(">I",0))
        cmd,streamId,msg=self.recvRELAY_EARLY()
        if cmd != Onion.RELAY_CONNECTED  or streamId!=sId:
            raise Exception('error RELAY_CONNECTED')
        return cmd,streamId,msg
    
    def sendRELAY_RESOLVE(self,sId,host):
        self.sendRELAY_EARLY(Onion.RELAY_RESOLVE,sId,host+"\x00")
        cmd,streamId,msg=self.recvRELAY_EARLY()
        if cmd != Onion.RELAY_RESOLVED  or streamId!=sId:
            raise Exception('error RELAY_CONNECTED')
        t,l=struct.unpack(">BB",msg[:2])
        msg=msg[2:]
        if t==4:
            ip=socket.inet_ntoa(msg[:l])
            msg=msg[l:]
            ttl,=struct.unpack(">I",msg[:4])
            return ip
        raise Exception("error resolving")


    def sendRELAY_BEGIN_DIR(self,sId):
        self.sendRELAY_EARLY(Onion.RELAY_BEGIN_DIR,sId,"")
        cmd,streamId,msg=self.recvRELAY_EARLY()
        if cmd != Onion.RELAY_CONNECTED  or streamId!=sId:
            raise Exception('error RELAY_CONNECTED')
        return cmd,streamId,msg
    
    
    def sendRELAY_DATA(self,sId,msg):
        self.sendRELAY_EARLY(Onion.RELAY_DATA,sId,msg)
        
    def recvRELAY_DATA(self,sId):
        cmd,streamId,msg=self.recvRELAY_EARLY()
        if cmd != Onion.RELAY_DATA or streamId!=sId:
            raise Exception('error RELAY_DATA')
        return cmd,streamId,msg

    def sendRELAY_END(self,sId):
        self.sendRELAY_EARLY(Onion.RELAY_END,sId,struct.pack('>B',Onion.REASON_DONE))
        
    
    
    

        