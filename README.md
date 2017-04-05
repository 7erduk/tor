# Tor
This is a pure Python Tor protocol implementation. This is my research of tor, hidden servers and play with him. 

You can do:
- make circs from 2 to whant you want
- resolve domain
- connect to hidden servers


## Dependencies

- Python 2.7
- pyCrypto
- pyOpenSSL


## Examples
``` python
from tor.desc import Descriptors
from tor.rend import rend_compute_v2_desc_id,Rend
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
```

## Contacts

7erduk@gmail.com

