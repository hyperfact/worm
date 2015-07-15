#!/usr/bin/env python
#coding: utf-8
'''
Created on 2014年8月11日

@author: Administrator
'''
from __future__ import print_function

import threading as thrd
import multiprocessing as mp
import time, sys
import StringIO as sio

_now = time.clock

class _Dummy(object): pass

class CCTest(object):
    '''
    classdocs
    '''

    def __init__(self):
        '''
        Constructor
        '''
        self.tasks = []
    
    def submit(self, fun, args):
        t = thrd.Thread(target=fun, args=args)
        self.tasks.append(t)
        
    def start(self):
        for t in self.tasks:
            t.start()
    
    def join(self):
        for t in self.tasks:
            t.join()
    
try:
    import pp
    class CCTestPP(object):
        '''
        classdocs
        '''
    
        def __init__(self):
            '''
            Constructor
            '''
            self.pps = pp.Server(ncpus=100)
            self.tasks = []
        
        def submit(self, func, args=(), depfuncs=(), modules=(),
                    callback=None, callbackargs=(), group='default', globals=None):
            t = self.pps.submit(func, args, depfuncs,
                    modules, callback, callbackargs, group, globals)
            self.tasks.append(t)
            
        def start(self):
            pass
        
        def join(self):
            return [t() for t in self.tasks]
except: pass

def _subprocInit(ctx):
    p = mp.current_process()
    assert not hasattr(p, 'ctx')
    p.ctx = ctx

class CCTestMP(object):
    '''
    classdocs
    '''
    
    @staticmethod
    def getProcessContext():
        return mp.current_process().ctx

    def __init__(self, nproc):
        '''
        Constructor
        '''
        self.queue = mp.Queue()
        ctx = _Dummy()
        ctx.queue = self.queue
        self.pool = mp.Pool(processes=nproc, initializer=_subprocInit,
                    initargs=(ctx,), maxtasksperchild=None)
        self.result = None
    
    def submit(self, *args, **kws):
        self.result = self.pool.map_async(*args, **kws)
    
    def start(self):
        pass
    
    def join(self):
        #ret = t.get()
        self.pool.close()
        self.pool.join()
        return None

class CCTestProbe(object):
    BEGIN = '!BEGIN!'
    END = '~END~'
    def __init__(self, sender):
        self.send = sender or (lambda x:None)
        self.start_time = time.clock()
        self.last_time = self.start_time
        self.stage = 0
        
    def begin(self, *args, **kws):
        self.stage = 0
        self._step(self.BEGIN)
    
    def step(self, stage, *args, **kws):
        self.stage += 1
        self._step(stage, *args, **kws)
    
    def _step(self, stage, *args, **kws):
        ct = time.clock()
        self.send((self.stage, stage, ct, ct-self.start_time, ct-self.last_time, args, kws))
        self.last_time = ct
    
    def end(self, *args, **kws):
        self.stage = sys.maxint
        self._step(self.END)

class CCTestMPProbe(CCTestProbe):
    def __init__(self):
        CCTestProbe.__init__(self,
                sender=CCTestMP.getProcessContext().queue.put)
    
def _avg(iterable):
    leng = len(iterable)
    return sum(iterable)/ float(leng) if leng!=0 else 0
    
class CCTestMPAnalyzer(object):
    
    def __init__(self, total, receptor, sampleinterval=1.0):
        self.total = total
        self.receptor = receptor
        self.sampleinterval = float(sampleinterval)
        self.results = {}
    
    class Stage(object):
        def __init__(self, sta):
            self.sta = sta
            self.starttime = _now()
            self.elapses = []
            self.spans = []
            self.aps_lt = _now()
            self.aps_smpls = []
            self.aps_ctr = 0
            self.aps_spans = []
        
    def start(self):
        self.start_time = _now()
    
    def sample(self, *args, **kws):
        while True:
            sta, s, abst, relt, spnt, args, kws = self.receptor()
            #print s, abst, relt, spnt, args, kws
            
            if s not in self.results:
                self.results[s] = CCTestMPAnalyzer.Stage(sta)
            res = self.results[s]
            
            elps = abst-self.start_time if s==CCTestMPProbe.BEGIN else relt
            res.elapses.append(elps)
            res.spans.append(spnt)
            ct = _now()
            dt = ct-res.aps_lt
            if dt < self.sampleinterval:
                res.aps_ctr += 1
            else:
                res.aps_smpls.append(res.aps_ctr)
                res.aps_spans.append(dt)
                res.aps_lt = ct
                res.aps_ctr = 0
            
            if len(res.elapses) >= self.total:
                if res.aps_ctr > 0:
                    res.aps_smpls.append(res.aps_ctr)
                    res.aps_spans.append(dt)
                if s == CCTestMPProbe.END:
                    break;
    
    def stat(self):
        sb = sio.StringIO()
        def ps(*args, **kws):
            print(sep=' ', end='\n', file=sb, *args, **kws)

        for s, res in sorted(self.results.iteritems(), key=lambda x: x[1].sta):
            sb.truncate(0)
            
            ps('[stage: %s]' % s)
            ps('elapses_avg: %f' % _avg(res.elapses))
            ps('span_avg: %f' % _avg(res.spans))
            ps('action per second: avg-%f' % (sum(res.aps_smpls)/sum(res.aps_spans)))
            ps('distrib: {')
            z = zip(res.aps_smpls, res.aps_spans)
            ps('\n'.join('%r: %r' % (i,j) for (i,j) in z))
            ps('}')
            sb.flush()
            yield sb.getvalue()
            continue
#            yield ''' 
#     [stage: %s]
#     elapses_avg: %f
#     span_avg: %f
#     action per second: avg-%f
#     distrib-%r:
#     %s
#     ''' % (s, _avg(res.elapses), _avg(res.spans),
#             sum(res.aps_smpls)/sum(res.aps_spans),
#             res.aps_smpls, res.aps_spans)
