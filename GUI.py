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
Ents = []
Labs = []
Frams = []

for field in Fields:
    Frams.append(Frame(root))
    Ents.append(Entry(Frams[Fields.index(field)], relief=SUNKEN, width=120))#.grid(row=Fields.index(field),column=1))
    Labs.append(Label(Frams[Fields.index(field)], text=field, relief=RIDGE, width=25))#.grid(row=Fields.index(field),column=0))

for item in Frams:
    item.pack(fill=X, expand=True)

for item in Ents:
    item.grid(row=Ents.index(item),column=1)
        
for item in Labs:
    item.grid(row=Labs.index(item),column=0)
    
for item in Ents:
    item.pack(side=RIGHT, expand=True)
    
for item in Labs:
    item.pack(side=LEFT, expand=True)

    ###
e1 = Entry(root)
e2 = Entry(root)

e1.grid(row=0, column=1)
e2.grid(row=1, column=1)
# Create single line text entry box
e1.pack()

# Specifying character position in entry
# - END: After last character of entry widget
# - ANCHOR: The beginning of the current selection
# - INSERT: Current text cursor position
# - "@x": Mouse coordinates

# Insert some default text
#entry.insert(INSERT, 'Hello, world!')
e1.insert(INSERT, 'Testing!')

l1 = Label(root, text="First")#.grid(row=3, column=0)
l1.grid(row=0, column=4)
l1.pack()

# Print the contents of entry widget to console
def print_content():
    #print(entry.get())
    print(e1.get())

# Create a button that will print the contents of the entry
button = Button(root, text='Print content', command=print_content)
button.pack()

#entry2 = Entry(root)
e2.pack()
e2.insert(INSERT,'yo, sup?!')

root.mainloop()