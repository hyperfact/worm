#!/usr/bin/env python
# encoding: utf-8
'''
Created on 2015年6月30日

@author: hy
'''

import os
from greenlet import GreenletExit
try:
    if os.name == 'nt':
        from twisted.internet import iocpreactor
        iocpreactor.install()
except:
    pass
from twisted.internet import reactor
print "reactor used:", type(reactor)

from twisted.internet.protocol import ClientFactory
import twisted.protocols.basic as pb

from worm.network.packet import *
import greenlet as grn

class LoopExit(Exception):
    pass

class SocketError(Exception):
    pass

class PacketError(SocketError):
    pass


class _GoOn(Exception): pass

import functools as ft
def catchGreenletExit(fun):
    @ft.wraps(fun)
    def f(*args, **kws):
        try:
            fun(*args, **kws)
        except GreenletExit:
            print 'GreenletExit'
    return f

class Socket(object):
    '''
    classdocs
    '''

    def __init__(self, hub, factory, work_routine):
        '''
        Constructor
        '''
        self.hub = hub
        self.factory = factory
        self.connector = None
        self.work_routine = work_routine
        self.protocol = None
    
    def connect(self, addr):
        con = self.hub.loop.connectTCP(addr[0], addr[1], self.factory)
        assert not hasattr(con, 'work_routine')
        con.work_routine = self.work_routine
        self.connector = con
        error, protocol = self.hub.request('CONNECTING')
        if not error:
            self.protocol = protocol
        return error
    
    def send(self, mid, sid, fmt=None, *val):
        self.protocol.sendData(mid, sid, fmt, *val)
        #error = self.hub.request('SEND')
    
    def sendPacket(self, pkt):
        self.protocol.sendPacket(pkt)
        #error = self.hub.request('SEND')
        
    def recvPacket(self, timeout=None):
        loop = self.hub.loop
        
        if timeout:
            def timer(r):
                r.hub.onresult(r, 'PACKET', 'TIMEOUT', None)
            loop.callLater(timeout, timer, self.work_routine)
        
        #f = lambda action,event,error,*args: (action=='RECEIVING' and event=='PACKET')
        while True:
            err, pkt = self.hub.request('RECEIVING', None)
            
            if err and err=='TIMEOUT':
                # 超时
                return None
            else:
                # heartbeat
                if pkt.mid==0 and pkt.sid==10:
                    self.sendPacket(pkt)
                else:
                    return pkt
    
    def close(self):
        self.protocol.disconnect()
        error = self.hub.request('DISCONNECTING')
        return error

class BaseProtocol(pb.IntNStringReceiver):
    structFormat = 'x x H 2x 2x'
    prefixLength = st.calcsize(structFormat)
    
    def __init__(self):
        self.crypto = CreateCryptoInst()
        self.routine = None
        self.sendCount = 0
        
    def __del__(self):
        FreeCryptoInst(self.crypto)
    
    def resetStatus(self):
        ResetStatus(self.crypto)

    def connectionMade(self):
        #print 'connectionMade'
        #print dir(self.transport.connector)
        self.resetStatus()
        self.routine = self.transport.connector.work_routine
        delattr(self.transport.connector, 'work_routine')
        
        rsp = self.factory.onresult(self.routine, 'CONNECTED', None, self)
        
    def connectionLost(self, reason):
        self.resetStatus()
        #print 'Connection lost. Reason', reason
        rsp = self.factory.onresult(self.routine, 'DISCONNECTED', reason)

    def dataReceived(self, data):
        assert (self.sendCount>0), 'no data send before recv'
        """
        Convert int prefixed strings into calls to stringReceived.
        """
        # Try to minimize string copying (via slices) by keeping one buffer
        # containing all the data we have so far and a separate offset into that
        # buffer.
        alldata = self._unprocessed + data
        currentOffset = 0
        prefixLength = self.prefixLength
        fmt = self.structFormat
        self._unprocessed = alldata

        while len(alldata) >= (currentOffset + prefixLength) and not self.paused:
            messageStart = currentOffset + prefixLength
            length, = st.unpack(fmt, alldata[currentOffset:messageStart])
            if length > self.MAX_LENGTH:
                self._unprocessed = alldata
                self.lengthLimitExceeded(length)
                return
            messageEnd = currentOffset + length
            if len(alldata) < messageEnd:
                break

            # Here we have to slice the working buffer so we can send just the
            # netstring into the stringReceived callback.
            packet = alldata[currentOffset:messageEnd]
            currentOffset = messageEnd
            
            # decrypt
            buf = ct.create_string_buffer(packet, 8192)
            dlen = DecryptData(self.crypto, buf, len(packet))
            if dlen == 0xFFFFFFFF:
                #self.routine.throw(PacketError('Packet parse error'))
                rsp = self.factory.onresult(self.routine, 'PACKET_ERROR', PacketError('Packet parse error'))
                self.disconnect()
                return
            pkt = Packet.FromBuf(buf=buf, length=dlen)
            self.lastRecvTime = time.clock()
            #if not self.factory.OnRecvNetPacket(self, pkt) :
            self.packetReceived(pkt)

        # Slice off all the data that has been processed, avoiding holding onto
        # memory to store it, and update the compatibility attributes to reflect
        # that change.
        self._unprocessed = alldata[currentOffset:]

    def sendPacket(self, pkt):
        data = pkt.encrypt(self.crypto)
        self.transport.write(data)
        self.sendCount += 1
        
    def sendData(self, mid, sid, fmt, *val):
        pkt = Packet(mid=mid, sid=sid)
        if fmt:
            pkt.write(fmt, *val)
        self.sendPacket(pkt)
        
    def packetReceived(self, pkt):
        """
        Override this for notification when each complete packet is received.

        @param pkt: The complete Packet which was received
        @type pkt: C{Packet}
        """
        #pkt.dump()
        rsp = self.factory.onresult(self.routine, 'PACKET', None, pkt)
    
    def loseConnection(self):
        self.transport.loseConnection()
        
    def disconnect(self):
        self.loseConnection()

class BaseFactory(ClientFactory):
    '''
    classdocs
    '''
    protocol = BaseProtocol
    def __init__(self, hub, nproc=1, ncc=1):
        '''
        Constructor
        '''
        self.hub = hub
    
    def startedConnecting(self, connector):
        #print 'Started to connect.'
        pass

    def buildProtocol(self, addr):
        #print 'Connected.'
        return ClientFactory.buildProtocol(self, addr)

    def clientConnectionLost(self, connector, reason):
        #print 'Lost connection.  Reason:', reason
        pass
    
    def clientConnectionFailed(self, connector, reason):
        #print 'Connection failed. Reason:', reason
        r = connector.work_routine
        assert r, 'work_routine not set'
        self.onresult(r, 'CONNECTION_FAILED', reason, None)
        #r.throw(SocketError('Connection failed, reason:' + repr(reason)))
    
    def onresult(self, routine, event, error, *args, **kws):
        self.hub.onresult(routine, event, error, *args, **kws)
    
class Hub(grn.greenlet):
    def __init__(self, *args, **kwargs):
        grn.greenlet.__init__(self, *args, **kwargs)
        self.loop = reactor
        
    def start(self):
        self.switch()
    
    def run(self):
        assert self is grn.getcurrent(), 'Do not call Hub.run() directly'
        while True:
            loop = self.loop
            #loop.error_handler = self
            try:
                loop.run()
            finally:
                #loop.error_handler = None  # break the refcount cycle
                pass
            self.parent.throw(LoopExit('This operation would block forever'))
        
    def _onresult(self, action, *args, **kws):
        #print 'H [req] action:', action
        return args

    def onresult(self, routine, event, error, *args, **kws):
        #print 'H [result] event: ', event, ' error: ', error
        try:
            r = routine.switch(event, error, *args, **kws)
            if not r:
                print 'greenlet exited!'
            else:
                return self._onresult(*r)
        except:
            import traceback,sys
            print>>sys.stderr, traceback.format_exc()

    def _request(self, action, filter, event, error, *args):
        #print 'C [result] action: ', action, ' event: ', event, ' error: ', error
        if 'CONNECTION_FAILED' == event:
            raise SocketError('Connection failed, reason:' + repr(error))
        if 'DISCONNECTED' == event:
            raise SocketError('Connection disconnected, reason:' + repr(error))
        if 'PACKET_ERROR' == event:
            raise SocketError('Packet parse failed, reason:' + repr(error))
        
        if not filter:
            return (error,) + args
        else:
            if filter(action, event, error, *args):
                return (error,) + args
            else:
                raise _GoOn
                # no tail recursion optimization
                #return self.request(action, filter)
    
    def request(self, action, filter=None, *args, **kws):
        #print 'C [req] action:', action
        while True:
            try:
                return self._request(action, filter, *self.switch(action, *args, **kws))
            except _GoOn:
                pass
    
    def wait(self, routine, timeout, *args, **kws):
        loop = self.loop
        def timer(r):
            r.hub.onresult(r, 'TIME_EXPIRED', None)
        loop.callLater(timeout, timer, routine)
        f = lambda a, ev, er, *args: (a=='DELAY' and ev=='TIME_EXPIRED')
        return self.request('DELAY', f)

class WorkRoutine(grn.greenlet):
    def __init__(self, hub, factory, *args, **kwargs):
        grn.greenlet.__init__(self, parent=hub, *args, **kwargs)
        self.hub = hub
        self.factory = factory
        
    def start(self):
        self.hub.loop.callWhenRunning(self.switch)
        
    def wait(self, timeout, *args, **kws):
        return self.hub.wait(self, timeout, *args, **kws)
    
    def run(self):
        pass
