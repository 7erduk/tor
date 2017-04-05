import struct


class Block:
    def __init__(self,data=''):
        self.buffer=data

    
    def u8(self,v=None):
        if v!=None:
            self.buffer+=struct.pack(">B",v)
        else:
            v,=struct.unpack(">B",self.buffer[:1])
            self.buffer=self.buffer[1:]
            return v
    

    def u16(self,v=None):
        if v!=None:
            self.buffer+=struct.pack(">H",v)
        else:        
            v,=struct.unpack(">H",self.buffer[:2])
            self.buffer=self.buffer[2:]
            return v

    def u32(self,v=None):
        if v!=None:
            self.buffer+=struct.pack(">I",v)
        else:        
            v,=struct.unpack(">I",self.buffer[:4])
            self.buffer=self.buffer[4:]
            return v

    def u64(self,v=None):
        if v!=None:
            self.buffer+=struct.pack(">Q",v)
        else:        
            v,=struct.unpack(">Q",self.buffer[:8])
            self.buffer=self.buffer[8:]
            return v
        
    def get(self):
        return self.buffer
        
    
    def pop(self,size):
        
        v=self.buffer[:size]
        self.buffer=self.buffer[size:]
        return v
    
    def push(self,data):
        self.buffer+=data
        
    def isEmpty(self):
        if len(self.buffer)>0:
            return True
        else:
            return False
