import hashlib
from random import randint
from binascii import hexlify
 
class DiffieHellman(object):
 
    # The following is the prime safe enough 
    # 6,144 bits introduced in RFC3526 (Might take some time to calculate DH)
    # predefined_p = 2^6144 - 2^6080 - 1 + 2^64 * { [2^6014 pi] + 929484 }
    # More values available in https://www.ietf.org/rfc/rfc3526.txt
    predefined_p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
    predefined_g = 2
    
    # p, g, and publicKey should be open to the other party
    def __init__(self, p = None, g = None, privateKey = None, publicKey = None):
        if p is None or g is None:
            self.p = self.predefined_p
            self.g = self.predefined_g
        else:
            self.p = p
            self.g = g
        if privateKey is None or publicKey is None :
            self.privateKey = self.generatePriKey()
            self.publicKey = self.generatePubKey()
        else:
            self.privateKey = privateKey
            self.publicKey = publicKey
 
    def generatePriKey(self):
        return randint(2, self.p - 1)
 
    def generatePubKey(self):
        return pow(self.g, self.privateKey, self.p)
 
    def generateKey(self, anotherKey):
        self.sharedSecret = pow(anotherKey, self. privateKey, self.p)
        return self.sharedSecret
 
    def getKey(self):
        return hexlify(self.key)
        
    def getKeySize(self):
        return len(self.key) * 8
 
    def showDHKeyExchange(self):
        print "Prime (p): ", self.p
        print "Generator (g): ", self.g
        print "Private key: ", self.privateKey
        print "Public key: ", self.publicKey
        print "Shared secret: ", self.sharedSecret
        print "Shared key: ", self.getKey()
        print "Size of the key (bits):", self.getKeySize()
 
if __name__ == '__main__':
 
    # TEST SET : DiffieHellman Key Exchange
    # alice = DiffieHellman(0x7fffffff, 2)
    # bob = DiffieHellman(0x7fffffff, 2)
    
    alice = DiffieHellman()
    bob = DiffieHellman()
 
    alice.generateKey(bob.publicKey)
    bob.generateKey(alice.publicKey)
 
    if(alice.getKey() == bob.getKey()):
        print "=============== Alice ==============="
        alice.showDHKeyExchange()
        print "===============  Bob  ==============="
        bob.showDHKeyExchange()
    else:
        print "Something is wrong!! Shared keys does not match!!"