import sys; sys.path.append("..")

from desc import Descriptors
from rend import rend_compute_v2_desc_id,Rend
import requests


d=Descriptors()

#"https://torstatus.blutmagie.de/"
print "downloading directory information all.z"
r=requests.get("http://faravahar.redteam.net/tor/server/all.z")
if r and r.status_code==200:
    open("all.z",'wb+').write(r.content)
    d.loadTextDesc('all.z')
    d.saveDesc('all.m')
    print "downloaded all.z"


routers=d.loadDesc('all.m')

r=Rend(routers)
r.connectToOnion('3g2upl4pq6kufc4m.onion') #duckduckgo
r.sendRELAY_BEGIN_IPv4(0x1234,"",80) #local service connect
r.sendRELAY_DATA(0x1234,'GET / HTTP/1.0\r\n\r\n')
print r.recvRELAY_DATA(0x1234)
r.sendRELAY_END(0x1234)
