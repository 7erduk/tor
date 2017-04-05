import socket
from OpenSSL import SSL

class TLS:
    def __init__(self,ip,port):
        self.ip=ip
        self.port=port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
        self.conn = SSL.Connection(ctx, s)        
        
    def connect(self):
        self.conn.connect((self.ip, self.port))
        self.conn.do_handshake()
        
    def read(self,size):
        return self.conn.read(size)
    
    def write(self,data):
        self.conn.write(data)
        
    def close(self):
        self.conn.close()
