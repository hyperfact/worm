#!/usr/bin/env python
#coding: utf-8
'''
Created on 2014年8月27日

@author: Administrator
'''

import struct as st
import os, sys

import greenlet
from worm.loadtest.ConcurrencyTest import CCTestProbe

if os.name == 'nt':
    from twisted.internet import iocpreactor
    iocpreactor.install()
from twisted.internet import reactor

from twisted.internet.protocol import Protocol, ClientFactory
import twisted.protocols.basic as pb

from worm.network.packet import *

from worm.loadtest.ConcurrencyTest import CCTestMPAnalyzer

def sample(ncc, hub):
    analyzer = CCTestMPAnalyzer(ncc, hub.switch)
    analyzer.start()
    analyzer.sample()
    for stat in analyzer.stat():
        print stat
    pass

class SocketError(Exception): pass

class AsyncSocket(CCTestProbe):
    def __init__(self, factory, hub, workroutine):
        self.factory = factory
        self.hub = hub
        self.work_coroutine = workroutine
        self.protocol = None

        CCTestProbe.__init__(self, sender=self.__probe_send)

    def connect(self, addr):
        con = reactor.connectTCP(addr[0], addr[1], self.factory)
        assert not hasattr(con, 'work_coroutine')
        self.connector = con
        con.work_coroutine = self.work_coroutine

        self.protocol, = self.__filter_switch('CONNECTING', addr)
        return

    def sendPacket(self, pkt):
        self.protocol.sendPacket(pkt)
        #self.hub.switch('SENDING')
        return

    def recvPacket(self):
        pkt, = self.__filter_switch('RECIEVING')
        return pkt
    
    def disconnect(self):
        self.protocol.disconnect()
        return self.__filter_switch('DISCONNECTING')
        
    def __filter_switch(self, msg, *args, **kws):
        ret = self.hub.switch(msg, *args, **kws)
        #print 'C recv:', ret
        notify = None
        ret_args = ()
        if isinstance(ret, tuple):
            notify = ret[0]
            ret_args = ret[1:]
        else:
            notify = ret[0]
        
        if notify == 'ERROR':
            raise SocketError(ret_args)
        elif notify == 'DISCONNECTED':
            raise SocketError(ret_args)
        else:
            return ret_args
    
    def __probe_send(self, *args, **kws):
        return self.__filter_switch('PROBE', *args, **kws)

class WorkCoroutine(greenlet.greenlet):
    def __init__(self, factory, *args, **kwargs):
        self.factory = factory
        self.connector = None
        greenlet.greenlet.__init__(self, *args, **kwargs)
        
    def yield2(self, notify, *args, **kws):
        while True:
            ret = self.switch(notify, *args, **kws)
            #print 'M recv:', ret
            cmd = None
            args = ()
            if isinstance(ret, tuple):
                cmd = ret[0]
                args = ret[1:]
            else:
                cmd = ret
            
            if cmd == 'PROBE':
                #print args
                self.factory.onProbe(*args)
                notify = 'PROBE'
                args = ()
                kws = {}
            else:
                return ret
    
    def start(self, *args, **kws):
        self.yield2(*args, **kws)

class BaseProtocol(pb.IntNStringReceiver):
    structFormat = 'x x H 2x 2x'
    prefixLength = st.calcsize(structFormat)
    
    def __init__(self):
        self.crypto = CreateCryptoInst()
        self.routine = None
        
    def __del__(self):
        FreeCryptoInst(self.crypto)
    
    def resetStatus(self):
        ResetStatus(self.crypto)

    def connectionMade(self):
        #print 'connectionMade'
        #print dir(self.transport.connector)
        self.routine = self.transport.connector.work_coroutine
        delattr(self.transport.connector, 'work_coroutine')
        #print self.routine
        rsp = self.routine.yield2('CONNECTED', self)
        #print 'M recv:', rsp
        
    def connectionLost(self, reason):
        ResetStatus(self.crypto)
        #print 'Connection lost. Reason', reason
        rsp = self.routine.yield2('DISCONNECTED', reason)
        #print 'M recv:', rsp

    def dataReceived(self, data):
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
        
    def sendData(self, mid, sid, hcode, fmt, *val):
        pkt = Packet(mid=mid, sid=sid)
        pkt.hcode = hcode
        pkt.write(fmt, *val)
        self.sendPacket(pkt)
        
    def packetReceived(self, pkt):
        """
        Override this for notification when each complete packet is received.

        @param pkt: The complete Packet which was received
        @type pkt: C{Packet}
        """
        #pkt.dump()
        rsp = self.routine.yield2('PACKET',pkt)
        #print 'M recv:', rsp
#         try:
#             self.disp.dispatch(self, pkt)
#         except:pass
        #raise NotImplementedError
    
    def loseConnection(self):
        self.transport.loseConnection()
        
    def disconnect(self):
        self.loseConnection()
    
class CCTestAsync(ClientFactory):
    '''
    classdocs
    '''
    protocol = BaseProtocol
    def __init__(self, nproc=1, ncc=1):
        '''
        Constructor
        '''
        self.stat_route = greenlet.greenlet(sample)
        self.stat_route.switch(ncc, greenlet.getcurrent())
        pass
    
    def submit(self, routine, gen, *args, **kws):
        for ctx in gen:            
            g = WorkCoroutine(self, routine)

            hub = greenlet.getcurrent()
            ctx.hub = hub
            ctx.socket = AsyncSocket(self, hub, g)
    
            #print dir(g)
            msg = g.start(ctx)
            #print msg
    
    def start(self):
        reactor.run()
    
    def join(self):
        #ret = t.get()
        return None
    
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
        r = connector.work_coroutine
        if r:
            r.yield2('ERROR', reason)
            
    def onProbe(self, *args):
        return self.stat_route.switch(*args)

if '__main__' == __name__:
    pass
    #print dir(reactor)
#     from Work.LogonLogin import testLogonC
#     
#     f = CCTestAsync()
#     ctx = Context(acc='202270',
#                     uid='102271',
#                     pwd='e10adc3949ba59abbe56e057f20f883e')
#     ctx.svr_addr = ('192.168.18.87', 9001)
#     f.submit(testLogonC, (ctx,))
#     f.start()

    #for _ in xrange(1):
        #c = reactor.connectTCP('192.168.18.15', 6013, f)
        #print '\n'.join([str(k)+': '+str(v) for k,v in vars(c).iteritems()])
    
