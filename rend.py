import requests
import base64
import time
import struct
import socket
import re
from desc import Descriptors
from torcrypto import new_SHA1
from circ import Circ
from desc import Descriptors
from Crypto.Util.number import long_to_bytes,bytes_to_long
from stem.descriptor.hidden_service_descriptor import HiddenServiceDescriptor
from onion import Onion
from Crypto.Random.random import Random
from utils import Block
from torcrypto import new_SHA1,publicPEM2ASN1


text2="""rendezvous-service-descriptor uoah2tg4hnaaa2z4g2qcuv2b57kzrfcp
version 2
permanent-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJipOXoDq939m1c1tuQuydWo28pKhFBC/7cmYhYaUZbVa+uqlDiktzpZ
+LdEtb4SPzSSo0dTxJkngO3rPC5q19UwBV7GA5IlG0PTgYCYCvmj4bAe+6g901ZQ
Dt3IG/huzN0d7awimKOOkm5/AxrGUPRefL1P2SvTMP7qv+MdiLdfAgMBAAE=
-----END RSA PUBLIC KEY-----
secret-id-part wjargp6q6l6geivq7olnfkeund7ozpt6
publication-time 2016-09-05 15:00:00
protocol-versions 2,3
introduction-points
-----BEGIN MESSAGE-----
aW50cm9kdWN0aW9uLXBvaW50IGdqN3ZxaTJkcm9obXEzd2Rnbms0Y3I2eWl2bmxk
cWtsCmlwLWFkZHJlc3MgOTMuMTE1LjkxLjY2Cm9uaW9uLXBvcnQgNDQzCm9uaW9u
LWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTGtJ
b2hMVlIrejNyVHArTmxYRWZzei9NSEp4cU91MzN6dFkvMSswR2x5Z0t2QXoySzNu
NERhRQord05ERWZ1TXUxNDdRd3p5dUdpTXNmSzdKdmNyQS9yZzVOam5sN01mWHFp
UVR2WmloUlo4NHhUSWloV3J0djN0CjBURW5GeVVNRDhYQ3phdjNNMHUrWjBoOTVv
anBBUnNqTlpIYnVCS2xTVW1VaDJzVDFzZTNBZ01CQUFFPQotLS0tLUVORCBSU0Eg
UFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJ
QyBLRVktLS0tLQpNSUdKQW9HQkFNNW40MVZFQUpabWdSWmVSNldrUkR4ZzZyaVhp
MTRaczhFeU5BSEV5Vm5wQjRzMXBsbXEvQktkClpaMXBmWVdSK0R6UkViTWp5b0J4
RitScVhFb3I1eWtrdnExN3lzMzU0ZEwzZ3BwMXVTaWVJOS9OZ0l0S2c3OGoKM3Br
L3NHeGVVMVZPYThiMkp1aWN4ZlYzL2JXQjVoWUNsZkZJbnQ3eVlmK2E5ZWFkOHNU
ckFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0
aW9uLXBvaW50IGdseGpjaG13cnByNmFmeG11dnpsd2h3cXZoeGVoN2JwCmlwLWFk
ZHJlc3MgMTA5LjEwNS4xMDkuMTYyCm9uaW9uLXBvcnQgNjA3ODQKb25pb24ta2V5
Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFLYndUT0g1
NzdEV3RCWTZMS1VEcEFWS2grRE45bncwLzZpUDFFQkpTNGc4RW85cHRZcHNVVnRl
ClpWNmlscGdiMVBCYWJYeWRZdHdOY3RHa1h1Z1NMY2s0U1RrdksxWkhkNTNyTWZ6
d2o5ajdHSGJNWkJ4aFNDR3MKMmVFNDFEOS85WjQwdVpPdTUvZ2VRcFRFVUJjRExD
SGhaNmVGeHYxdUNQeHIwN2FBeEJXZkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJM
SUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtF
WS0tLS0tCk1JR0pBb0dCQU1hSGhJLzgxNHB5Y1FObjd5WEtOU3RMUkFnRWFJTlQz
Mk5nNnQzWG5hektDaytqcHNoYXhrNkIKL0N2R0w3Z3dXRk13amtOTXFZd2JyOEkw
VDRGMzZzMXZiMVFzZ1p4MU95UVdEUHNBSERVNmV4YnZmM2s2ZFk5TgpMRk1oQkxM
dTZYZlUyRDZHYzNFdXduYlMzNTI3RklYUXhqMzY3NE5IM1phTUgwZVk5ajBuQWdN
QkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24t
cG9pbnQgZWZhbmlmM2h5Mjc2Ym51aXBuZXhoczVib3ByN3pncjQKaXAtYWRkcmVz
cyA4OS4xNjMuMjQ1LjExNgpvbmlvbi1wb3J0IDkwMDEKb25pb24ta2V5Ci0tLS0t
QkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFNRENpalp6ZVJCYzhw
ckxQQURua1lybUJFNWc4cE96cjBUTU01djhzY0RxVTNlTlh3YnNxZ29ZCnRPNU5B
bEE1UkhsQTFybjJjN0JVclZkaEhUY21vLzlFU1pBT21XYkRhMzJwdFZYUC9jeXZ2
QmpOcXV1ekJSUFQKbDhQN0hTTllpOHZ4SGhGS2sxMVh4dEdoSGtFcmVxNS9iVi8x
cktiV3p0YzdkeUppcmdFRkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZ
LS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0t
Ck1JR0pBb0dCQU01QjdrMjlRQ3FrT3UrbHRMWEl3Vkk4VzhDMVhpM1dRWFl4QWpO
Y0ViQzFjM25XczlEY2Y0NEIKUmd5ZUMzeG9XUEgvSEhXdWdKbG13cTFXdDFONVZ1
T05ZZUVSSkIwblBwWTJGajN2eFE4WmNwSXVPUlZpR2N1bwo1bVpNazNQS0dlLzNK
MEFUQ1VYbVhVd1kwaUVsbk51dlFUSGQxeFRJMFRvekJFck9SZmJkQWdNQkFBRT0K
LS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQoK
-----END MESSAGE-----
signature
-----BEGIN SIGNATURE-----
ghBJg3aBiInm42UhQ8EvCkCTQ7Xd1GCsWb1vUuxv+/t8n2V5XtTZTXj7IkDYw89O
9EbQouNSxp3vnlgaPEISmBarE64Yf/s6OvrR6QQYTYNkqOMh2y8sV3LCwT5/XsWB
yMgcOb99S8SRGKqbBhNq1QNWKWnLeAbWgOy9t1oZprU=
-----END SIGNATURE-----
"""

def rend_compute_v2_desc_id(host,descriptor_cookie,replica):
    current_time=int(time.time())
    name=host.split('.')[0]
    permanent_id=base64.b32decode(name.upper())
    time_period=(current_time + ord(permanent_id[0]) * 86400 / 256)/ 86400
    h=new_SHA1()
    h.update(struct.pack('>I',time_period))
    h.update(descriptor_cookie)
    h.update(struct.pack(">B",replica))
    
    h2=new_SHA1()
    h2.update(permanent_id)
    h2.update(h.digest())
    print "host fingerprint",host,"is",h2.digest().encode('hex').upper()
    return base64.b32encode(h2.digest()).lower()
    


class Rend:

    RELAY_COMMAND_ESTABLISH_INTRO = 32
    RELAY_COMMAND_ESTABLISH_RENDEZVOUS = 33
    RELAY_COMMAND_INTRODUCE1 = 34
    RELAY_COMMAND_INTRODUCE2 = 35
    RELAY_COMMAND_RENDEZVOUS1 = 36
    RELAY_COMMAND_RENDEZVOUS2 = 37
    RELAY_COMMAND_INTRO_ESTABLISHED = 38
    RELAY_COMMAND_RENDEZVOUS_ESTABLISHED = 39
    RELAY_COMMAND_INTRODUCE_ACK = 40

    
    def __init__(self,routers):
        self.routers=routers
        self.desc=Descriptors(routers)
        self.circ=Circ(routers,3)   
        self.circR=Circ(routers,3)   
        self.circI=Circ(routers,3)   
        self.cookie = Random.new().read(20)
    
    
    def getCloseHashes(self,id,n=3):
        id=base64.b32decode(id.upper())
        def cmpXOR(x):
            return bytes_to_long(x.decode('hex'))^bytes_to_long(id)
        keys=[]
        keys=self.routers.keys()
        sort=sorted(keys,key=cmpXOR)        
        return sort[:n]
        
    def sendRendezvous(self):
        self.circR.make(0x80000125)
        self.circR.sendRELAY_EARLY(self.RELAY_COMMAND_ESTABLISH_RENDEZVOUS, 0x125, self.cookie)
        cmd,streamID,msg=self.circR.recvRELAY_EARLY()
        if cmd!=self.RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
            raise Exception('error RELAY_COMMAND_RENDEZVOUS_ESTABLISHED')
                
    def sendINTRODUCE1(self):
        for intro in self.hsd.introduction_points():
            try:
                fingerprint=base64.b32decode(intro.identifier.upper()).encode('hex').upper()
                
                self.circI.make(0x80000126,fingerprint=fingerprint)
                b=Block()
                
                b.u8(3)
                b.u8(0)
                b.u32(0)#time.time())
                b.push(socket.inet_aton(intro.address))
                b.u16(intro.port)
                identityID=new_SHA1(publicPEM2ASN1(self.circR.onions[self.circR.n-1]['signing_key'])).digest()
                b.push(identityID)
                rendOnionKey=publicPEM2ASN1(self.circR.onions[self.circR.n-1]['onion_key'])
                b.u16(len(rendOnionKey))
                b.push(rendOnionKey)
                b.push(self.cookie)
                self.onionR=Onion(intro.service_key)
                
                b.push(self.onionR.getKeyDH())
                msg=self.onionR.makeSkinHybrid(b.get())
                msg=new_SHA1(publicPEM2ASN1(intro.service_key)).digest()+msg
                self.circI.sendRELAY_EARLY(self.RELAY_COMMAND_INTRODUCE1, 0x125, msg)
                cmd,streamID,msg=self.circI.recvRELAY_EARLY()
                if cmd!=self.RELAY_COMMAND_INTRODUCE_ACK and len(msg)!=0:
                    raise Exception('error RELAY_COMMAND_INTRODUCE_ACK')
                break
            except Exception,e:
                pass
    
    def recvRENDEZVOUS2(self):
        cmd,streamID,msg=self.circR.recvRELAY_EARLY()
        self.onionR.getSharedKey(msg)
        r={}
        r['onion']=self.onionR
        self.circR.onions.append(r)
        self.circR.n+=1
        
    def sendRELAY_BEGIN_IPv4(self,sId,ip,port):
        self.circR.sendRELAY_BEGIN_IPv4(sId, ip, port)
        
    def sendRELAY_DATA(self,sId, msg):
        self.circR.sendRELAY_DATA(sId, msg)
    
    def recvRELAY_DATA(self,sId):
        return self.circR.recvRELAY_DATA(sId)

    def sendRELAY_END(self,sId):
        self.circR.sendRELAY_END(sId)
    
    
    def connectToOnion(self,host):
        try:
            self.getHiddenServiceDescriptor(host)
        except Exception,e:
            self.getHiddenServiceDescriptor(host,1)
        
        print "got rendezvous-service-descriptor"
        for i in range(10):
            try:
                self.sendRendezvous()
                print "sent rendezvous"
                break
            except Exception,e:
                pass
        
        self.sendINTRODUCE1()
        print "sent INTRODUCE1"
        self.recvRENDEZVOUS2()
        print "recv RENDEZVOUS2"

        
    
    def getHiddenServiceDescriptor(self,host,replica=0):
        id=rend_compute_v2_desc_id(host,'',replica)
        nodes=self.getCloseHashes(id,20)
        body=''
        for fingerprint in nodes:
            try:
                print 'the closest router is',fingerprint
                self.circ.make(0x80000124,fingerprint=fingerprint)
                self.circ.sendRELAY_BEGIN_DIR(0x123)
                
                print 'connected to directory server',fingerprint
                
                id=rend_compute_v2_desc_id(host, '', 0)

                r=self.circ.onions[self.circ.n-1]
                req='GET /tor/rendezvous2/%s HTTP/1.0\r\nHost: %s:%d\r\n\r\n' % (id,str(r['address']),r['or_port'])

                print "http request of rendezvous2 hidden service sescriptor"
                print req
                self.circ.sendRELAY_DATA(0x123,req)

                m=''
                cmd,streamId,msg=self.circ.recvRELAY_DATA(0x123)
                m+=msg

                body=''
                print "http response"
                print m
                if m.find('HTTP/1.0 200')!=-1:
                    i=m.find('\r\n\r\n')
                    if i!=-1:
                        header=m[:i+4]
                        body=m[i+4:]
                        r=re.search('Content-Length: ([0-9]+)',header)
                        if r:
                            size,=r.groups()
                            size=int(size)
                        else:
                            raise Exception('invalid http length')       
                else:
                    raise Exception('invalid http code')       
                        
                while len(body)<size:
                    cmd,streamId,msg=self.circ.recvRELAY_DATA(0x123)
                    body+=msg

                self.circ.sendRELAY_END(0x123)
                break
            except Exception,e:
                print e

        if len(body)==0:
            raise Exception('descriptor is empty')
        self.hsd=HiddenServiceDescriptor(body)
        return self.hsd
    
if __name__=="__main__":
    pass
