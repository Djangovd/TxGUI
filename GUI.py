#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Wed Oct  4 14:41:09 2017

@author: snackamoto
"""

# entry_widget.py

#import json
#import os
#import subprocess
#import random
#import unittest

#import bitcoin.ripemd as ripemd
#from bitcoin import *

#from ecdsa import SigningKey

#from GenericTx import *
#from TxTools import *

#import pybitcointools
#import re
#import sh
#import sys
# 
from Tkinter import *#Tk, Entry, Button, Label, INSERT, Canvas
root = Tk()

Fields = ['Version', '# inputs', 'Previous TXout hash', 'Previous TXout idx', 'scriptSig', 'Sequence', '# outputs', 'value', 'scriptPubKey', 'locktime']
PreSetVals = ['01000000', '01', '', '', '', '', '01', '', '', '00000000']
#Sizes(bytes): 4,       1-9,           32,                    4,                 - ,           4 ,          1 - 9,    8 , 4
FieldSize = [8, 18, 64, 8, 128, 8, 18, 16, 128, 8]
Ents = []
Labs = []
Frams = []

for field in Fields:
#    Frams.append(Frame(root))
 #.grid(row=Fields.index(field),column=1))
    Labs.append(Label(root, text=field, relief=RIDGE, width=25).grid(row=Fields.index(field),column=0))
    Ents.append(Entry(root, relief=SUNKEN, width=FieldSize[Fields.index(field)]))
#    Ents.append(Entry(Frams[Fields.index(field)], relief=SUNKEN, width=FieldSize[Fields.index(field)]))#.grid(row=Fields.index(field),column=1))
#    Labs.append(Label(Frams[Fields.index(field)], text=field, relief=RIDGE, width=25))#.grid(row=Fields.index(field),column=0))
#
#for item in Frams:
#    item.pack(fill=X, expand=True)
#
for item in Ents:
    item.grid(column=1, row=Ents.index(item), sticky=W)
#        
#for item in Labs:
#    item.grid(column=0, row=Labs.index(item), sticky=W)
#    
#for item in Ents:
#    item.pack(side=RIGHT, expand=True)
#    
#for item in Labs:
#    item.pack(side=LEFT, expand=True)
#Label(root, text="First Name").grid(row=0)
#Label(root, text="Last Name").grid(row=1)

#e1 = Entry(root)
#e2 = Entry(root)

### Fill form with pre-set values
for ent in Ents:
    ent.insert(0, PreSetVals[Ents.index(ent)])

# Print the contents of entry widget to console
def print_content():
    #print(entry.get())
    #print(e1.get())
    strng = ''
    for item in Ents:
        strng += item.get()
    print strng


# Create a button that will print the contents of the entry
button = Button(root, text='Print content', command=print_content)
#button = Button(root, text='Print content', command=print_content)
#button.pack()
button.grid(column=0, row=len(Ents)+2, sticky=W)
#entry2 = Entry(root)
#e2.pack()
#e2.insert(10,'yo, sup?!')

root.mainloop()