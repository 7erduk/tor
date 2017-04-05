import struct
import socket
from Crypto.Random.random import Random
from Crypto.Util.number import bytes_to_long,long_to_bytes


from utils import Block
from dh import DiffieHellman
from torcrypto import new_SHA1,new_AES_CTR_128,getKeySizeRSA,new_PKCS1_OAEP
from torcrypto import publicPEM2ASN1

class Onion:
    __PKCS1_OAEP_PADDING_OVERHEAD = 42
    KEY_LEN=16
    HASH_LEN=20
    
    
    RELAY_BEGIN = 1
    RELAY_DATA = 2
    RELAY_END = 3
    RELAY_CONNECTED = 4
    RELAY_SENDME = 5 
    RELAY_EXTEND = 6
    RELAY_EXTENDED = 7
    RELAY_TRUNCATE =8 
    RELAY_TRUNCATED = 9
    RELAY_DROP = 10
    RELAY_RESOLVE = 11
    RELAY_RESOLVED = 12
    RELAY_BEGIN_DIR = 13
    RELAY_EXTEND2 = 14
    RELAY_EXTENDED2 = 15
    
    CELL_PAYLOAD_SIZE = 509
    
    
    REASON_DONE=6
    
    def __init__(self,onion_key):
        self.rsa=onion_key
        self.dh=DiffieHellman()
        self.iv='\x00'*self.KEY_LEN
        self.key=Random.new().read(self.KEY_LEN)
        
        self.hashDf=new_SHA1()
        self.hashDb=new_SHA1()
        
    
    def getKeyDH(self):
        return long_to_bytes(self.dh.publicKey)
    
    def makeSkin(self):
        sizeRSA=getKeySizeRSA(self.rsa)/8+1
        sizeDH=len(self.getKeyDH())
        sizePK=sizeRSA-len(self.key)-self.__PKCS1_OAEP_PADDING_OVERHEAD
        sizeAES=sizeDH-sizePK
        r=new_PKCS1_OAEP(self.rsa)
        msg=r.encrypt(self.key+self.getKeyDH()[:sizePK])
        
        e=new_AES_CTR_128(self.key, self.iv)
        msg+=e.encrypt(self.getKeyDH()[sizePK:])
        return msg


    def makeSkinHybrid(self,data):
        sizeRSA=getKeySizeRSA(self.rsa)/8+1
        sizeDH=len(data)
        sizePK=sizeRSA-len(self.key)-self.__PKCS1_OAEP_PADDING_OVERHEAD
        sizeAES=sizeDH-sizePK
        r=new_PKCS1_OAEP(self.rsa)
        msg=r.encrypt(self.key+data[:sizePK])
        
        e=new_AES_CTR_128(self.key, self.iv)
        msg+=e.encrypt(data[sizePK:])
        return msg

    
    def getKeyTAP(self,secret):
        k=''
        
        sizeTAP=self.KEY_LEN*2+self.HASH_LEN*3
        i=0
        while sizeTAP>0:
            h=new_SHA1()
            h.update(secret+chr(i))
            if sizeTAP>=self.HASH_LEN:
                k+=h.digest()
            else:
                k+=h.digest()[:sizeTAP]
            sizeTAP-=self.HASH_LEN
            i+=1
        return k
    
    def getSharedKey(self,data):
        b=Block(data)
        pub=b.pop(128)
        h=b.pop(20)
        secret=long_to_bytes(self.dh.generateKey(bytes_to_long(pub)))
        k=self.getKeyTAP(secret)
        self.KH,self.Df,self.Db,self.Kf,self.Kb=struct.unpack("<20s20s20s16s16s",k)
        if self.KH==h:
            self.hashDf.update(self.Df)
            self.hashDb.update(self.Db)

            self.cryptKf=new_AES_CTR_128(self.Kf, self.iv)
            self.cryptKb=new_AES_CTR_128(self.Kb, self.iv)
            
            
            return self.KH,self.Df,self.Db,self.Kf,self.Kb
        raise Exception('invalid shared key')

    def encrypt(self,data):
        return self.cryptKf.encrypt(data)

    def decrypt(self,data):
        return self.cryptKb.decrypt(data)
    
    def unpackRELAY(self,data):
        b=Block(data)
        cmd=b.u8()
        recognized=b.u16()
        streamID=b.u16()
        digest = b.pop(4)
        length= b.u16()
        payload=b.pop(length)
        
        m=struct.pack(">BHHIH",cmd,0,streamID,0,len(payload))+payload
        m+='\x00'*(self.CELL_PAYLOAD_SIZE-len(m))
        
        self.hashDb.update(m)
        if digest==self.hashDb.digest()[:4]:
            return cmd,streamID,payload
        raise Exception('invalid relay data')        
        
    def packPELAY(self,cmd,streamID,msg,recognized=0):
        msg=msg[:498]
        m=struct.pack(">BHHIH",cmd,recognized,streamID,0,len(msg))+msg
        m+='\x00'*(self.CELL_PAYLOAD_SIZE-len(m))
        self.hashDf.update(m)
        hash,=struct.unpack('>I',self.hashDf.digest()[:4])
        m=struct.pack(">BHHIH",cmd,0,streamID,hash,len(msg))+msg
        m+='\x00'*(self.CELL_PAYLOAD_SIZE-len(m))
        return m
    
    def packRELAY_BEGIN_IPv4(self,streamId,ip,port):
        return self.packPELAY(self.RELAY_BEGIN,streamId,"%s:%d\x00" % (ip,port)+struct.pack(">I",0))

    def packRELAY_EXTEND(self,ip,port,skin,signing_key):
        h=new_SHA1(publicPEM2ASN1(signing_key)).digest()
        return self.packPELAY(self.RELAY_EXTEND, 0, socket.inet_aton(ip)+struct.pack('>H',port)+skin+h)
    
    def packRELAY_DATA(self,streamId,data):
        return self.packPELAY(self.RELAY_DATA,streamId,data)