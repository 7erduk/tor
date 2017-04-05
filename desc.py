import re
import stem.descriptor
from stem.exit_policy import ExitPolicy
import StringIO
import marshal
import random

class Descriptors:
    def __init__(self,routers={}):
        self.routers=routers
    
    def loadTextDesc(self,fname):
        f=open(fname,'rb')
        desc=stem.descriptor.parse_file(f,'server-descriptor 1.0')
        self.routers={}
        for d in desc:
            router={}
            router['nickname']=d.nickname
            router['address']=d.address
            router['or_port']=d.or_port
            router['exit_policy']=str(d.exit_policy)
            router['onion_key']=d.onion_key
            router['signing_key']=d.signing_key
            router['dir_port']=d.dir_port
            self.routers[d.fingerprint]=router
        return self.routers


        
    def getExitPoliceRouters(self,ip,port):
        routers={}
        for r in self.routers:
            e=ExitPolicy(self.routers[r]['exit_policy'])
            if e.can_exit_to(ip,port):
                routers[r]=self.routers[r]
        return routers
                
            
    def saveDesc(self,fname):
        open(fname,'wb+').write(marshal.dumps(self.routers))
        
    def loadDesc(self,fname):
        self.routers=marshal.loads(open(fname,'rb').read())
        return self.routers
        
    def randRouter(self,ip=None,port=None):
        keys=self.routers.keys()
        random.shuffle(keys)
        routers={}
        for r in keys:
            if ip and port:
                e=ExitPolicy(self.routers[r]['exit_policy'])
                if e.can_exit_to(ip,port):
                    return self.routers[r]
            else:
                return self.routers[r]
        return None


if __name__=="__main__":
    d=Descriptors()
    #d.loadTextDesc('all.z')
    #d.saveDesc('all.m')
    d.loadDesc('all.m')
    r=d.randRouter('8.8.8.8',4444)
    print r['nickname']
    r=d.randRouter('8.8.8.8',4444)
    print r['nickname']
