#!/usr/bin/dev python
# -*- coding: utf-8 -*-

'''
Created on 2014年8月5日

@author: huaiyu
'''

import time
import struct as st
import ctypes as ct
from ctypes import cdll

BUF_LEN = 30960
_Buf = ct.c_ubyte * BUF_LEN

_nde = cdll.LoadLibrary('NetDataEncrypt.dll')
EncryptData = _nde.EncryptData
EncryptData.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_uint32, ct.c_uint32]
EncryptData.restype = ct.c_int32

DecryptData = _nde.DecryptData
DecryptData.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_uint32]
DecryptData.restype = ct.c_int32

CreateCryptoInst = _nde.CreateCryptoInst
CreateCryptoInst.argtypes = []
CreateCryptoInst.restype = ct.c_void_p

FreeCryptoInst = _nde.FreeCryptoInst
FreeCryptoInst.argtypes = [ct.c_void_p]
FreeCryptoInst.restype = None

ResetStatus = _nde.ResetStatus
ResetStatus.argtypes = [ct.c_void_p]
ResetStatus.restype = None

class NetHead(ct.Structure):
    _fields_ = [('ver', ct.c_uint8),
                ('check', ct.c_uint8),
                ('size', ct.c_uint16),
                ('mid', ct.c_uint16),
                ('sid', ct.c_uint16)]
NetHeadPtr = ct.POINTER(NetHead)

# //数据描述头
# struct tagDataDescribe
# {
#     WORD                            wDataSize;                        //数据大小
#     WORD                            wDataDescribe;                    //数据描述
# };
class DataDescribe(ct.Structure):
    _fields_ = [('size', ct.c_uint16),
                ('desc', ct.c_uint16),]
DataDescribePtr = ct.POINTER(DataDescribe)

def _HeartbeatHandler(pkt, sock):
    svrt = pkt.read('I')
    print '[cliT:%r,svrT:%r] heartbeat!' % (time.asctime(), svrt)
    sock.sendPacket(pkt)

class Packet(object):
    def __init__(self, **kwargs):
        '''
        1. Packet(initSize=4096, mid=0, sid=0)
        2. Packet(buf, offset, length)
        '''
        if 'buf' in kwargs:
            buf = kwargs.pop('buf')
            offset = kwargs.pop('offset', 0)
            length = kwargs.pop('length', ct.sizeof(buf)-offset)
            
            self.buf = (ct.c_ubyte*length)()
            self.offset = length
            self.pos = 0
            self._capacity = length
            
            ct.memmove(self.buf, ct.byref(buf, offset), length)
        else:
            initSize = kwargs.pop('initSize', 4096)
            mid = kwargs.pop('mid', 0)
            sid = kwargs.pop('sid', 0)
            
            self.buf = (ct.c_ubyte*initSize)() #ct.create_string_buffer(initSize)
            self.offset = 0
            self.pos = 0
            self._capacity = initSize
                       
            pnh = ct.cast(self.buf, NetHeadPtr)
            pnh.contents.mid = mid
            pnh.contents.sid = sid
            self.offset += ct.sizeof(NetHead)
        
        self._sendbuf = _Buf() #ct.create_string_buffer(8192)

#     def __init__(self, mid, sid, initSize=4096):
#         self.buf = (ct.c_ubyte*initSize)() #ct.create_string_buffer(initSize)
#         self.offset = 0
#         self.pos = 0
#         self._capacity = initSize
#                   
#         pnh = ct.cast(self.buf, NetHeadPtr)
#         pnh.contents.mid = mid
#         pnh.contents.sid = sid
#         self.offset += ct.sizeof(NetHead)

#     def frombuf(self, buf, offset, length):
#         ct.memmove(self.buf, ct.byref(buf, offset), length)
#         self.offset = length
#         return self

    _dipatch = {(0,1):(_HeartbeatHandler,[],{})}
    @classmethod
    def regHandler(cls, mid, sid, handler, *args, **kws):
        '''
        proto handler(Packet, sock)
        '''
        cls._dipatch[(mid,sid)] = (handler, args, kws)
    
    @classmethod
    def unregHandler(cls, mid, sid):
        del cls._dipatch[(mid,sid)]
    
    @classmethod
    def FromData(cls, mid, sid, hcode=0, fmt='', *val):
        self = cls(mid=mid,sid=sid)
        self.write(fmt, *val)
        return self
    
    @classmethod
    def FromBuf(cls, buf, offset=0, length=-1):
        if length == -1:
            length = (ct.sizeof(buf)-offset)
        self = cls(buf=buf, offset=offset, length=length)
        return self
        
    def __getattr__(self, name):
        #print '__getattr__', name
        if name == 'mid':
            pnh = ct.cast(self.buf, NetHeadPtr)
            return pnh.contents.mid
        elif name == 'sid':
            pnh = ct.cast(self.buf, NetHeadPtr)
            return pnh.contents.sid
        else:
            return object.__getattribute__(self, name)
    
    def __setattr__(self, name, value):
        #print '__setattr__', name, value
        if name == 'mid':
            pnh = ct.cast(self.buf, NetHeadPtr)
            pnh.contents.mid = value
        elif name == 'sid':
            pnh = ct.cast(self.buf, NetHeadPtr)
            pnh.contents.sid = value
        else:
            object.__setattr__(self, name, value)
    
    def write(self, fmt, *val):
        l = st.calcsize(fmt)
        if self.offset+l > self._capacity:
            raise Exception('out of bound: %d' % (self.offset+l))
        st.pack_into(fmt, self.buf, self.offset, *val)
        self.offset += l
        return self
    
    def write_ctype(self, data, length=-1):
        if length == -1:
            length = ct.sizeof(data)
        if self.offset+length > self._capacity:
            raise Exception('out of bound')
        ct.memmove(ct.byref(self.buf, self.offset), ct.byref(data), length)
        self.offset += length
        return self
    
    def writeDescData(self, desc, fmt, *val):
        l = st.calcsize(fmt)
        self.write('H', l)
        self.write('H', desc)
        self.write(fmt, *val)
    
    def ref(self, ctype, offset=-1):
        if offset == -1:
            offset = self.offset
        assert offset + ct.sizeof(ctype) <= self._capacity
        p_type = ct.POINTER(ctype)
        return ct.cast(ct.byref(self.buf, offset), p_type)
    
    def refAdd(self, ctype, offset=-1):
        if offset == -1:
            offset = self.offset
        assert offset + ct.sizeof(ctype) <= self._capacity
        p_type = ct.POINTER(ctype)
        offset_old = self.offset
        self.offset += ct.sizeof(ctype)
        return ct.cast(ct.byref(self.buf, offset_old), p_type)
    
    def seek(self, pos=0):
        if pos == -1:
            self.pos = self.offset
        elif pos >= 0:
            self.pos = pos
        else:
            raise Exception('invalid arg [pos]') 
        return self
    
    def read(self, fmt):
        l = st.calcsize(fmt)
        if self.pos+l > self.offset:
            raise Exception('out of bound')
        pos = self.pos
        self.pos += l
        return st.unpack_from(fmt, self.buf, pos)
    
    def readHead(self):
        self.seek(0)
        pnh = ct.cast(self.buf, NetHeadPtr)
        self.pos += ct.sizeof(NetHead)
        return pnh.contents
    
    def readCtype(self, tp):
        l = ct.sizeof(tp)
        if self.pos+l > self.offset:
            raise Exception('out of bound')
        pos = self.pos
        self.pos += l
        return tp.from_buffer_copy(self.buf, pos)
    
    def readAvail(self):
        return len(self) - self.pos
    
    def clear(self):
        self.offset = ct.sizeof(NetHead)
        return self
    
    def __len__(self):
        return self.offset
    
    def send(self, sock):
        #dump(self.buf)
        ct.memmove(self._sendbuf, self.buf, self.offset)
        slen = EncryptData(sock.crypto, ct.byref(self._sendbuf), ct.c_uint32(self.offset), ct.c_uint32(BUF_LEN))
        sdata = (ct.c_ubyte * slen)()
        ct.memmove(sdata, self._sendbuf, slen)
        #dump(sdata)
        sock.sendall(sdata)
        return self
    
    def encrypt(self, crypto):
        ct.memmove(self._sendbuf, self.buf, self.offset)
        slen = EncryptData(crypto, ct.byref(self._sendbuf), ct.c_uint32(self.offset), ct.c_uint32(BUF_LEN))
        sdata = ct.create_string_buffer(slen)
        ct.memmove(sdata, self._sendbuf, slen)
        return sdata.raw
    
    def dispatch(self, sock):
        hd = self.readHead()
        d = Packet._dipatch
        k = (hd.mid, hd.sid)
        h = d.get(k, ((lambda p,s:None), [], {}))
        h[0](self, sock, *(h[1]), **(h[2]))
    
    def dump(self):
        print '(%d)[mid:%d,sid:%d]' % (self.offset, self.mid, self.sid),
        for i in xrange(self.offset):
            print '%02x' % self.buf[i],
        print
        return self
