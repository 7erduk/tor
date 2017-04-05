from OpenSSL import crypto
from Crypto.Random.random import Random

def certASN12PEM(asn):
    cert=crypto.load_certificate(crypto.FILETYPE_ASN1,asn)
    return crypto.dump_certificate(crypto.FILETYPE_PEM,cert)

def certPEM2ASN1(pem):
    cert=crypto.load_certificate(crypto.FILETYPE_PEM,pem)
    return crypto.dump_certificate(crypto.FILETYPE_ASN1,cert)

def certGetPubKey(pem):
    cert=crypto.load_certificate(crypto.FILETYPE_PEM,pem)
    return crypto.dump_publickey(crypto.FILETYPE_PEM,cert.get_pubkey())


class Certificates:
    
    OR_CERT_TYPE_TLS_LINK=1
    OR_CERT_TYPE_ID_1024=2
    OR_CERT_TYPE_AUTH_1024=3    
    
    def __init__(self):
        self.linkCert=None
        self.idCert=None
        self.authCert=None
        
    
    def randomName(self):
        abc=range(ord('a'),ord('z'))
        n=Random.random.randint(8, 20)
        s=''
        for i in range(0,n):
            j=Random.random.randint(0,len(abc)-1)
            s+=chr(abc[j])
        return s
    
    def genKeys(self):
        sk = crypto.PKey()
        sk.generate_key(crypto.TYPE_RSA, 1024)
        return crypto.dump_privatekey(crypto.FILETYPE_PEM,sk)
    
    def createCerts(self):
        self.idKey=self.genKeys()
        self.linkKey=self.genKeys()
        self.authKey=self.genKeys()
        nickname="www."+self.randomName()+".net"
        nn2="www."+self.randomName()+".com"
        self.idCert=self.genCert(self.idKey, nn2, 3600*24*2)        
        self.authCert=self.genCert(self.authKey, nickname, 3600*24*2,self.idKey,self.idCert)
        self.linkCert=self.genCert(self.linkKey, nickname, 3600*24*2,self.idKey,self.idCert)
        
    def loadCerts(self,idKey,linkKey,authKey,idCert,authCert,linkCert):
        self.idKey=idKey
        self.linkKey=linkKey
        self.authKey=authKey
        self.idCert=idCert
        self.authCert=authCert
        self.linkCert=linkCert
                
    
    def genCert(self,sk,cname,certLifeTime,issuerSK=None,issuerCert=None):
        sk=crypto.load_privatekey(crypto.FILETYPE_PEM,sk)
        if issuerSK:
            issuerSK=crypto.load_privatekey(crypto.FILETYPE_PEM,issuerSK)
        if issuerCert:
            issuerCert=crypto.load_certificate(crypto.FILETYPE_PEM,issuerCert)
        r=Random.new()
        serial=Random.random.bytes_to_long(r.read(8))
        r.close()
    
        cert = crypto.X509()
        cert.get_subject().CN = cname
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(certLifeTime)
        
        
        
        if issuerCert:
            cert.set_issuer(issuerCert.get_subject())
        else:
            cert.set_issuer(cert.get_subject())
            
        cert.set_pubkey(sk)
        
        if issuerSK:
            cert.sign(issuerSK, 'sha1')
        else:            
            cert.sign(sk, 'sha1')
        return crypto.dump_certificate(crypto.FILETYPE_PEM,cert)
    
    
    def verifyCerts(self,certs):
        certId=None
        for typeCert,cert in certs:
            if typeCert==self.OR_CERT_TYPE_ID_1024:
                certId=cert
                break
        
        if not certId:
            raise Exception("not found cert ID")
        
        certId=crypto.load_certificate(crypto.FILETYPE_PEM,certId)
        st=crypto.X509Store()
        st.add_cert(certId)
        
        for typeCert,cert in certs:
            cert=crypto.load_certificate(crypto.FILETYPE_PEM,cert)
            ctx=crypto.X509StoreContext(st, cert)
            ctx.verify_certificate()
            if cert.has_expired():
                raise Exception("cert expired")
            
            if cert.get_pubkey().bits()<1024:
                raise Exception("invalid rsa key size")
