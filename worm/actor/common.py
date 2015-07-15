#!/usr/bin/env python
# encoding: utf-8
'''
Created on 2015年6月29日

@author: hy
'''

from worm.base.basics import Action

class ConnectAction(Action):
    def __init__(self, sock):
        self.sock = sock
    
    def start(self):
        pass