#!/usr/bin/env python
# encoding: utf-8
'''
Created on 2015年6月29日

@author: hy
'''

import greenlet as grn

SENDING = 'SENDING'
RECEIVING = 'RECEIVING'

class Hub(grn.greenlet):
    def __init__(self, *args, **kwargs):
        self.reactor = None
        grn.greenlet.__init__(self, *args, **kwargs)
        
    def yield2(self, event, *args, **kws): pass
    
    
