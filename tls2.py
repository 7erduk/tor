import socket
import ssl

class TLS:
    def __init__(self,ip,port):
        self.ip=ip
        self.port=port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #s.settimeout(10)
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False
        self.conn = ctx.wrap_socket(s)
        
    def connect(self):
        self.conn.connect((self.ip, self.port))
        
    def read(self,size):
        return self.conn.read(size)
    
    def write(self,data):
        self.conn.write(data)
        
    def close(self):
        self.conn.close()
