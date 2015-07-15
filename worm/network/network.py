#!/usr/bin/dev python
# coding: utf-8

'''
Created on 2014年5月12日

@author: huaiyu
'''

import time
import socket as skt

import struct as st
import ctypes as ct
#from ctypes import windll as wd
from ctypes import cdll

from worm.network.packet import *

def dump(bf):
    leng = 0
    try: leng = ct.sizeof(bf)
    except: leng = len(bf)
    print '(%d)' % (leng),
    for i in bf:
        print '%02x' % ord(i),
    print
    #print repr(bf)
    #return
    #for i in bf:
    #    # printf('%02x ', i)
    #    #tmp = ct.c_ubyte(i)
    #    print "%x" % (i),
    
class Socket(skt.socket):
    def __init__(self, *args, **kwargs):
        skt.socket.__init__(self, skt.AF_INET, skt.SOCK_STREAM)
        self.crypto = CreateCryptoInst()
        
    def __del__(self):
        FreeCryptoInst(self.crypto)
        
    def resetStatus(self):
        ResetStatus(self.crypto)

    def sendPacket(self, pkt):
        data = pkt.encrypt(self.crypto)
        #dump(data)
        self.sendall(data)

_Buf = ct.c_ubyte * BUF_LEN

def SendData(sock, mainID, subID, data=None):
    _sendbuf = _Buf() #ct.create_string_buffer(8192) 
    ct.memset(_sendbuf, 0, BUF_LEN)
    length = 0
    pnh = ct.cast(_sendbuf, NetHeadPtr)
    pnh.contents.mid = mainID
    pnh.contents.sid = subID
    length += ct.sizeof(NetHead)
    if isinstance(data, str):
        sb = ct.create_string_buffer(data, len(data))
        data = sb
    if data:
        ct.memmove(ct.byref(_sendbuf,length), ct.byref(data), ct.sizeof(data))
        length += ct.sizeof(data)
    #print length
    dump(_sendbuf)
    slen = EncryptData(sock.crypto, ct.byref(_sendbuf), ct.c_uint32(length))
    #print  #repr(buf.raw)
    #dump(buf)
    sdata = (ct.c_ubyte * slen)()
    ct.memmove(sdata, _sendbuf, slen)
    sock.sendall(sdata)
    
def recvPacketG(sock, ctx):
    """
    Convert int prefixed strings into calls to stringReceived.
    """
    # Try to minimize string copying (via slices) by keeping one buffer
    # containing all the data we have so far and a separate offset into that
    # buffer.
    data = sock.recv(4096)
    if not data:
        raise Exception('remote was closed!')
    alldata = ctx._unprocessed + data
    
    currentOffset = 0
    fmt = 'x x H 2x 2x'
    prefixLength = st.calcsize(fmt)
    ctx._unprocessed = alldata

    while len(alldata) >= (currentOffset + prefixLength):
        messageStart = currentOffset + prefixLength
        length, = st.unpack(fmt, alldata[currentOffset:messageStart])

        messageEnd = currentOffset + length
        if len(alldata) < messageEnd:
            break

        # Here we have to slice the working buffer so we can send just the
        # netstring into the stringReceived callback.
        packet = alldata[currentOffset:messageEnd]
        currentOffset = messageEnd
        
        # decrypt
        buf = ct.create_string_buffer(packet, 8192)
        dlen = DecryptData(sock.crypto, buf, len(packet))
        pkt = Packet.FromBuf(buf=buf, length=dlen)
        yield pkt

    # Slice off all the data that has been processed, avoiding holding onto
    # memory to store it, and update the compatibility attributes to reflect
    # that change.
    ctx._unprocessed = alldata[currentOffset:]

class _Dummy(object): pass

def RecvPacket(sock):
    ctx = _Dummy()
    ctx._recvbuf = _Buf()
    ctx._recvoffset = 0
    ctx._parsebuf = _Buf()
    
    pkts = []
    while True:
        _RecvRawData(sock, ctx)
        
        offset = 0
        while ctx._recvoffset-offset >= ct.sizeof(NetHead):
            cur = ct.byref(ctx._recvbuf, offset)
            pnh = ct.cast(cur, NetHeadPtr)
            size = pnh.contents.size
            #dumpl(cur, size)
            
            if ctx._recvoffset-offset < size:
                break

            ct.memmove(ctx._parsebuf, cur, size)
            dlen = 0
            print size
            assert size >= ct.sizeof(NetHead)
            try:
                dlen = DecryptData(sock.crypto, ctx._parsebuf, size)
            except:
                a=0
            pkt = Packet.FromBuf(buf=ctx._parsebuf, length=dlen)
            pkts.append(pkt)
            
            offset += size
        
        ct.memmove(ctx._recvbuf, ct.byref(ctx._recvbuf, offset), ctx._recvoffset-offset)
        ctx._recvoffset -= offset
        
        if 0 == ctx._recvoffset:
            break;
    return pkts

def _RecvRawData(sock, ctx):
    raw = sock.recv(BUF_LEN-ctx._recvoffset)
    if not raw:
        raise Exception('remote was closed!')
    sb = ct.create_string_buffer(raw, len(raw))
    ct.memmove(ctx._recvbuf, sb, ct.sizeof(sb))
    ctx._recvoffset += ct.sizeof(sb)

def RecvTimeOut(sock, timeout=-1):
    st = time.clock()
    while True:
        #pkts = RecvPacket(sock)
        ctx = _Dummy()
        ctx._unprocessed = ''
        for p in recvPacketG(sock, ctx):
            #p.dump()
            p.dispatch(sock)
        
        if timeout>0:
            ct = time.clock()
            if ct-st >= timeout:
                break;
    

def SocketAvilableBytes(sock):
    FIONREAD = 0x4004667f
    nrd = ct.c_ulong()
    sock.ioctl(skt, FIONREAD, ct.byref(nrd))
    return nrd

def addMacro(pkt):
    '''  
    struct MACROS_VERINFO
    {
        DWORD                       dwMacrosVer;//宏定义版本信息                
    };
    '''
    pkt.write('I', 0x0111)
    
class Dispatcher(object):
    def __init__(self):
        self.__dipatch = {(0,10):(self._heartbeatHandler,[],{})}

    def regHandler(self, mid, sid, handler, *args, **kws):
        '''
        proto handler(Packet, sock)
        '''
        self.__dipatch[(mid,sid)] = (handler, args, kws)
    
    def unregHandler(self, mid, sid):
        del self.__dipatch[(mid,sid)]
    
    def _heartbeatHandler(self, pkt, sock):
        svrt = pkt.read('I')
        #print '[cliT:%r,svrT:%r] heartbeat!' % (time.asctime(), svrt)
        sock.sendPacket(pkt)
        
    def dispatch(self, sock, pkt):
        hd = pkt.readHead()
        d = self.__dipatch
        k = (hd.mid, hd.sid)
        h = d.get(k, ((lambda p,s:None), [], {}))
        return h[0](pkt, sock, *(h[1]), **(h[2]))
    
    @staticmethod
    def _recipient(sock):
        ctx = _Dummy()
        ctx._unprocessed = ''
        def recv():
            return recvPacketG(sock, ctx)
        return recv

    def run(self, sock, timeout=-1):
        st = time.clock()
        ctx = _Dummy()
        ctx._unprocessed = ''
        while True:
            for p in recvPacketG(sock, ctx):
                p.dump()
                self.dispatch(sock, p)
            
            if timeout>0:
                ct = time.clock()
                if ct-st >= timeout:
                    break;
    
    def run_until(self, sock, timeout=-1):
        st = time.clock()
        r = self._recipient(sock)
        while True:
            for p in r():
                #p.dump()
                self.dispatch(sock, p)
            
            if timeout>0:
                ct = time.clock()
                if ct-st >= timeout:
                    break;

    def runner(self, sock):
        ctx = _Dummy()
        ctx._unprocessed = ''
        def run(filter, *args, **kws):
            return recvPacketG(sock, ctx)
        return run
