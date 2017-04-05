import sys; sys.path.append("..")

from desc import Descriptors
from circ import Circ
import requests
from certs import Certificates


d=Descriptors()



#"https://torstatus.blutmagie.de/", dirport 9030
print "downloading directory information all.z"
r=requests.get("http://faravahar.redteam.net/tor/server/all.z")
if r and r.status_code==200:
    open("all.z",'wb+').write(r.content)
    d.loadTextDesc('all.z')
    d.saveDesc('all.m')
    print "downloaded all.z"


cr=Certificates()
cr.createCerts()

routers=d.loadDesc('all.m')

r=Circ(routers,3,cr.idKey,cr.linkKey,cr.authKey,cr.idCert,cr.authCert,cr.linkCert)
r.make(0x80001234,"8.8.8.8",80)
ip=r.sendRELAY_RESOLVE(0x1234,"torproject.org")
print "resolve ip is",ip