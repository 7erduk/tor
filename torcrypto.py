from Crypto.Util import asn1
import base64
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256,HMAC
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP


from Crypto.Hash import SHA256

algorithmIdentifier = asn1.DerSequence([('\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01'),asn1.DerNull().encode() ]).encode()


def PEM2DER(key):
    key=''.join(key.split('\n')[1:-1])
    return base64.b64decode(key)

#ASN1 without algorithm identifier public key
def publicPEM2ASN1(key):
    k=PEM2DER(key)
    der=asn1.DerSequence()
    der.decode(k)
    if der.hasOnlyInts():
        n,e=tuple(der[:])
    if der[0] == algorithmIdentifier:
        bitmap = asn1.DerObject()
        bitmap.decode(der[1], True)
        if bitmap.isType('BIT STRING') and ord(bitmap.payload[0])==0x00:
            der.decode(bitmap.payload[1:], True)
            if len(der)==2 and der.hasOnlyInts():
                n,e=tuple(der[:])
    derPK = asn1.DerSequence([n,e]).encode()
    return derPK

def sign_RSA_SHA256(pem,msg):
    rsa=RSA.importKey(pem)
    h=hashlib.new('SHA256')
    h.update(msg)
    sizeRSA=rsa.size()/8
    sign=rsa.decrypt("\x01"+'\xFF'*(sizeRSA-2-len(h.digest()))+"\x00"+h.digest())
    return sign

def new_HMAC_SHA256(key,data=None):
    h=HMAC.new(key,digestmod=SHA256)
    if data:
        h.update(data)
    return h

def new_SHA256(data=None):
    h=SHA256.new()
    if data:
        h.update(data)
    return h

def new_AES_CTR_128(key,iv):
    ctr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
    return AES.new(key,counter=ctr,mode=AES.MODE_CTR)
    
def new_PKCS1_OAEP(pub):
    rsa=RSA.importKey(pub)
    return PKCS1_OAEP.new(rsa)
    
def getKeySizeRSA(key):
    rsa=RSA.importKey(key)
    return rsa.size()

def new_SHA1(data=None):
    h=hashlib.new('SHA1')
    if data:
        h.update(data)
    return h

if __name__=="__main__":
    pub=open('ident.key','rb').read()
    PEM2ASN1(pub)
    pub=open('onion.pub','rb').read()
    PEM2ASN1(pub)    