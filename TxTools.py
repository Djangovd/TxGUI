import collections
import hashlib
import binascii
import base58
import unittest
import ecdsa
import copy
import os
from GenericTx import *
from ecdsa import SigningKey
###############


def H160(string):
### HASH160 function.
    uhex=binascii.unhexlify(string)
    sha256_uhex=hashlib.sha256(uhex).digest()
    md = hashlib.new('ripemd160')
    md.update(sha256_uhex)
    mdout = md.hexdigest()
    return mdout
################

def B58(string):
### Needs verification !!!
    unencoded = str(bytearray.fromhex( string ))
    encoded= base58.b58encode(unencoded)
    return encoded
##################

def decodeB58(string):
### Needs verification !!!
#    unencoded = str(bytearray.tohex( string ))
    unencoded = string
    encoded= base58.b58decode(unencoded)
    return encoded.encode('hex')
##################

def WIF2HEX(priv):
### convert WIF priv. key to HEX
    hextmp = decodeB58(priv)
    hextmp = hextmp[-8:]
    hextmp = hextmp[2:]
    return hextmp

################


def script_to_hex(script_string):
### Encode string in hex
    return script_string.encode("hex")
######################################

def str_to_endian(hex_string):
    new_endian_hex=''
    for i in range(len(hex_string),0,-2):
        new_endian_hex += hex_string[i-2:i]
    return new_endian_hex
#########################

def script_length(string, sig=False):
    config = collections.OrderedDict()
    if sig:
        config['']=-1
        config['fd']=253
        config['fe']=65535
        config['ff']=4294967296        
    else:
        config['']=-1
        config['4c']=75
        config['4d']=255
        config['4e']=65535
    prefix = ''
    l = len(string)/2
    lhx = hex(l)[2:] if l != 0 else '00'
    if len(str(lhx)) % 2 != 0: lhx='0'+lhx
    for key, value in config.items():
        if int(l) > value: prefix = key
    return prefix + str_to_endian(str(lhx))

##################


def script_to_address(script, ver=0):
    ### Input: hex string    
    ##  dec prefix  Description
    ##  00 	1 	Bitcoin pubkey hash
    ##  05 	3 	Bitcoin script hash
    ##  21 	4 	Bitcoin (compact) public key (proposed)
    ##  52 	M or N 	Namecoin pubkey hash
    ##  128     5 	Private key
    ##  111     m or n 	Bitcoin testnet pubkey hash
    ##  196     2 	Bitcoin testnet script hash 
    ###
    s_ver = ver
    s_ver_hex = hex(s_ver)[2:]
    if len(str(s_ver_hex)) % 2 != 0: s_ver_hex='0'+s_ver_hex 
    scriptHASH160 = H160(script)
    scriptHASH160ver = s_ver_hex + scriptHASH160
    scriptHASH160verSHA256SHA256 = hashlib.sha256(hashlib.sha256(scriptHASH160ver.decode('hex')).digest()).digest()
    checksum = scriptHASH160verSHA256SHA256.encode('hex')[0:8]
    scriptHASH160checksum = scriptHASH160ver + checksum
    return base58.b58encode(scriptHASH160checksum.decode('hex'))
################################################################
   
def locktime_conv(locktime):
### Value in BTCs
    ref          = '00000000'
    locktime_hex    = hex(locktime)
    locktime_hex_tmp = str(locktime_hex)[2:]
### if length of non-0 entries is uneven
    if len( str(locktime_hex)[2:] ) % 2 !=0: 
        locktime_hex_tmp = '0'+ locktime_hex_tmp
    locktime_hex_le = str_to_endian(locktime_hex_tmp)
    empty        = '0'
    locktime_len = len(str(locktime_hex_le))
    while( len(locktime_hex_le) < len(ref) ):
        locktime_hex_le = locktime_hex_le + empty 
    return locktime_hex_le
##########################

def value_calc(value):
### Value in BTCs
    ref          = '0000000000000000'
    value = int(value * 10**8)
    value_hex    = hex(value)
    value_hex_tmp = str(value_hex)[2:]
### if length of non-0 entries is uneven
    if len( str(value_hex)[2:] ) % 2 !=0: 
        value_hex_tmp = '0'+ value_hex_tmp
    value_hex_le = str_to_endian(value_hex_tmp)
    empty        = '0'
    value_len = len(str(value_hex_le))
    while( len(value_hex_le) < len(ref) ):
        value_hex_le = value_hex_le + empty 
    return value_hex_le
#######################


def modify(scrpt,newScriptPubKey,typ=None,sign=False):
#
# ver. no.             : 4 bytes
# in-counter           : 1-9 bytes
# list of inputs        
#    prev. output hash : 32 bytes
#    prev. output idx  : 4 bytes
#    script length     : 1 byte
#    scriptSig         : 
#    sequence          : 4 bytes
# ---
# out-counter          : 1-? bytes
# list of outputs
#    value             : 8 bytes
#    script length     : 1 byte
#    scriptPubKey      : 
# block lock time      : 4 bytes
#
###################################

    scriptPubKeySize = 25 # std. length of createrawtransaction
    

### Check if the Tx has been signed
    if not sign:
        scriptSigLen = 0 # for now
    else:
        entry_len = 4+1+32+4+1+4+1+8+1+scriptPubKeySize+4
        scriptSigLen = len(scrpt) - entry_len
        print "scriptSigLen         = " + str(scriptSigLen)
        print "scriptSigLen (Bytes) = " + str(scriptSigLen)/2
    
### Use ordered dictionary
    decomp = collections.OrderedDict()
    decomp['version'] = 4 
    decomp['input: count'] = 1 
    decomp['input: prev. output hash'] = 32 
    decomp['input: prev. output idx'] = 4 
    decomp['input: script length'] = 1 
    decomp['input: ScriptSig'] = scriptSigLen 
    decomp['input: sequence'] = 4 
    decomp['output: count'] = 1
    decomp['output: value'] = 8 
    decomp['output: script length'] = 1
    decomp['output: scriptPubKey'] = scriptPubKeySize 
    decomp['block lock time'] = 4


    script_decomp = []
    idx1 = 0
    for item in decomp.items():
        idx2 = idx1 + item[1]*2
        script_decomp.append(scrpt[idx1:idx2])
        idx1 = idx2
        
### Replace scriptPubKey with another (custom?) script
    scriptPubKeySize = len(newScriptPubKey)*2
    script_decomp[9]  = newScriptPubKey[0:2]
    script_decomp[10] = newScriptPubKey[2:]

#### Print out values.
    scrpt2 = ''
    for itm in script_decomp:
        scrpt2 += itm
    print scrpt2

##############################     

def op_script_encode(op_string,len_prefix=False, sig=False):
# We need 
#
# OP_2-OP_16 	82-96 	0x52-0x60 
# OP_DUP
# OP_HASH160
# OP_EQUAL
# OP_EQUALVERIFY
# OP_CHECKSIG
# OP_CHECKLOCKTIMEVERIFY
# ... to be enhanced according to need. 
# Consult https://en.bitcoin.it/wiki/Script for details
# on values and conversion
#
###
# The script is assumed to be of the form
#    OP_<1> OP_<2> ... <HEX of user script> OP_<N-1> OP_<N>
#    where OP_<i> is the ith operator
# 

    op_dict = {'OP_PUSHDATA': hex(76), 'OP_PUSHDATA2': hex(77), 'OP_PUSHDATA4': hex(78), 'OP_DUP': hex(118), 'OP_HASH160': hex(169), 'OP_EQUAL': hex(135), 'OP_EQUALVERIFY': hex(136), 'OP_CHECKSIG': hex(172), 'OP_CHECKMULTISIG': hex(174), 'OP_CHECKLOCKTIMEVERIFY': hex(177), 'OP_RETURN': hex(106), 'OP_0': '0x00', 'OP_1': hex(81), 'OP_2': hex(82), 'OP_3': hex(83), 'OP_4': hex(84), 'OP_5': hex(85), 'OP_6': hex(86), 'OP_7': hex(87), 'OP_8': hex(88), 'OP_9': hex(89), 'OP_10': hex(90), 'OP_11': hex(91), 'OP_12': hex(92), 'OP_13': hex(93), 'OP_14': hex(94), 'OP_15': hex(95), 'OP_16': hex(96), 'OP_PICK': hex(121), 'OP_IF': hex(99), 'OP_NOTIF': hex(100), 'OP_ELSE': hex(103), 'OP_ENDIF': hex(104), 'OP_DROP': hex(117), 'OP_NOP': hex(97), 'OP_TRUE': hex(81), 'OP_FALSE': '0x00', 'OP_ADD': hex(147), 'OP_SUB': hex(148), 'OP_SWAP': hex(124) }
    
    string = op_string.split()
    string_hex = []
    for word in string:
        if word not in op_dict:
            non_op_seg     = word
            #non_op_seg_len = len(non_op_seg)/2
            #non_op_seg_len_hex = hex(non_op_seg_len)[2:]
            if not sig:
                non_op_seg_len_hex = script_length(word)
                string_hex.append(non_op_seg_len_hex)
            string_hex.append(non_op_seg)
        else:
            string_hex.append(op_dict[word][2:])

    string_hex_out = ""
    for trm in string_hex:
        string_hex_out += trm

    if len_prefix:
        prefix = len(string_hex_out)/2
        prefix = hex(prefix)[2:]
        return str(prefix)+string_hex_out
    else:
        return string_hex_out

    print string_hex_out
    

########################

def sign(txdict, prevUTXO, prevUTXO_VOUT, scriptPK, priv, HASHCODE='SIGHASH_ALL', inp=True, outp=True, idx=0, customsigscript=''):
    ### Follows the procedure described here: 
    ### http://bitcoin.stackexchange.com/questions/36440/signing-a-raw-transaction-with-python-ecdsa-or-openssl
    HASHdict = { 'SIGHASH_ALL': '01', 'SIGHASH_NONE': '02', 'SIGHASH_SINGLE': '03', 'SIGHASH_ANYONECANPAY': '80', 'ALLANYONECANPAY': '81', 'NONEANYONECANPAY': '82', 'SINGLEANYONECANPAY': '83' }
    ##########
    tmp_unlocking_other=[]
    tmp_unlockingLen_other=[]

    count1=0
    count2=0
    prevUTXO=str_to_endian(prevUTXO)

    tmptxdict=copy.deepcopy(txdict)
    storekey1=0

    if idx == 0:
        print "idx=0"
        for key1 in tmptxdict['inputs']:
            print "key1 = " +str(key1)
            ### Backup unlocking fields
#            tmp_unlocking_other.append(tmptxdict['inputs'][key1]['unlocking'])
#            tmp_unlockingLen_other.append(tmptxdict['inputs'][key1]['unlockingLen'])
            tmptxdict['inputs'][key1]['unlocking']=''
            tmptxdict['inputs'][key1]['unlockingLen']='00'
            print "tmptxdict['inputs'][key1]['UTXO']      = " + tmptxdict['inputs'][key1]['UTXO']
            print "prevUTXO      = " + prevUTXO
            print "tmptxdict['inputs'][key1]['UTXO_VOUT'] = " + tmptxdict['inputs'][key1]['UTXO_VOUT']
            print "prevUTXO_VOUT = " + prevUTXO_VOUT
            if (tmptxdict['inputs'][key1]['UTXO'] == prevUTXO) and (tmptxdict['inputs'][key1]['UTXO_VOUT'] == prevUTXO_VOUT):
                storekey1=key1
                print "STORED KEY 1: " + str(storekey1)
                tmptxdict['inputs'][key1]['unlocking'] = scriptPK
                tmptxdict['inputs'][key1]['unlockingLen'] = str(hex(len(scriptPK)/2)[2:])
            count1+=1        
        for key1 in tmptxdict['outputs']:
            count2+=1
        print "=-=-=-="
        print "tmptxdict 1 = " +str(tmptxdict)
        print "=-=-=-="
        print "=-=-=-="
        print "txdict    1 = " +str(txdict)
        print "=-=-=-="
    elif idx > 0:
        for key1 in tmptxdict['inputs']:
            tmp_unlocking_other.append(tmptxdict['inputs'][key1]['unlocking'])
            tmp_unlockingLen_other.append(tmptxdict['inputs'][key1]['unlockingLen'])
            tmptxdict['inputs'][key1]['unlocking']=''
            tmptxdict['inputs'][key1]['unlockingLen']='00'
        
#            if (txdict['inputs'][key1]['UTXO'] == prevUTXO) and (txdict['inputs'][key1]['UTXO_VOUT'] == prevUTXO_VOUT):
        tmptxdict['inputs'][idx]['unlocking'] = scriptPK
        tmptxdict['inputs'][idx]['unlockingLen'] = str(hex(len(scriptPK)/2)[2:])
#            count1+=1
        count1=1
        count2=1
#        for key1 in txdict['outputs']:
#            count2+=1

    tmptx=assemble_tx(count1,count2,tmptxdict, inp, outp, idx)
    ### Concatenate HASHCODE at the end of the TX
    HASHCODEend = HASHdict[HASHCODE]+'000000'
    tmptx = tmptx+HASHCODEend
    print "tmptx = " + str(tmptx)
    tst = hashlib.sha256(hashlib.sha256(tmptx.decode('hex')).digest()).digest()
    print "tst = " + tst.encode('hex')
    sigtmp, sigscript, pubk = create_sig(tmptx, priv, customsigscript)
    print "sigtmp = " + str(sigtmp)
    if idx == 0:
        txdict['inputs'][storekey1]['unlocking']=sigscript
        txdict['inputs'][storekey1]['unlockingLen']=str(hex(len(sigscript)/2)[2:])

    elif idx > 0:
        txdict['inputs'][idx]['unlocking']=sigscript
        txdict['inputs'][idx]['unlockingLen']=str(hex(len(sigscript)/2)[2:])
    
    print "WTF: " + str(txdict)
    
    print "=-=-=-="
    print "tmptxdict 2 = " +str(tmptxdict)
    print "=-=-=-="
    print "=-=-=-="
    print "txdict    2 = " +str(txdict)
    print "=-=-=-="

    return (sigtmp, sigscript, txdict, assemble_tx(count1, count2, txdict))


####
def create_sig(tx, priv, custompk=''):
    ### Double hash
    #prvtmp = decodeB58(priv)    
    #print str(prvtmp)
    hashtx = hashlib.sha256(hashlib.sha256(tx.decode('hex')).digest()).digest()

    ### Prepare priv. key for signing
    signingkey = ecdsa.SigningKey.from_string(binascii.unhexlify(priv), curve=ecdsa.SECP256k1)
    #signingkey = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    signpubkey = '04' + signingkey.verifying_key.to_string().encode('hex')

    ### Produce signature
    sigtmp = signingkey.sign_digest(hashtx, sigencode=ecdsa.util.sigencode_der_canonize) + '01'.decode('hex')

    ### Get PubKey for verification
    pubktmp = signingkey.get_verifying_key()
    pubk = str(pubktmp.to_string().encode('hex'))

    if custompk == '':
        custompk = pubk

    ### Concatenate SigScript
    sigscript= str(hex(len(str(sigtmp.encode('hex')))/2)[2:]) + str(sigtmp.encode('hex')) + str(hex(len(str(custompk))/2)[2:]) + str(custompk)

    return (sigtmp.encode('hex'), sigscript, custompk)

####
def sign_type(txdict, UTXO, UTXO_VOUT, SPK, priv, HASHCODE, idx=0, customsigscript=''):
    ### idx=0 as default, user must specify idx when using SIGHASH SINGLE
    HASHdict = { 'SIGHASH_ALL': '01', 'SIGHASH_NONE': '02', 'SIGHASH_SINGLE': '03', 'SIGHASH_ANYONECANPAY': '80', 'ALLANYONECANPAY': '81', 'NONEANYONECANPAY': '82', 'SINGLEANYONECANPAY': '83' }

    sigl = []
    sigscriptl = []

    if HASHCODE == 'SIGHASH_ALL':
        inp = True
        outp= True
        idx0=0
    elif HASHCODE == 'SIGHASH_NONE':
        inp = True
        outp= False
        idx0=0
    elif HASHCODE == 'SIGHASH_SINGLE':
        inp = True
        outp= True
        idx0= idx

    i=0

    if (isinstance(UTXO, list) and isinstance(UTXO_VOUT, list) and isinstance(SPK, list) and isinstance(customsigscript, list)):
        if idx0==0:
            print "--- case 3 ---"
            for i in range(len(UTXO)):
                (sig, sigscript, txdict, txtmp) = sign(txdict, UTXO[i], UTXO_VOUT[i], SPK[i], priv[i], HASHCODE, inp, outp, idx0, customsigscript[i])
                sigl.append(sig)
                sigscriptl.append(sigscript)
#                print "i = " + str(i)
#                print "txdict = " + str(txdict)
        elif idx0 > 0:
            print "--- case 2 ---"
            (sig, sigscript, txdict, txtmp) = sign(txdict, UTXO[idx0], UTXO_VOUT[idx0], SPK[idx0], priv[idx0], HASHCODE, inp, outp, idx0, customsigscript[i])
            sigl.append(sig)
            sigscriptl.append(sigscript)
        elif idx0 < 0:
            print "negative index."
            exit()
    elif (isinstance(UTXO, str) and isinstance(UTXO_VOUT, str) and isinstance(SPK, str) ):
        print "--- case 1 ---"
        (sig, sigscript, txdict, txtmp) = sign(txdict, UTXO, UTXO_VOUT, SPK, priv, HASHCODE, inp, outp, idx0, customsigscript)
        sigl.append(sig)
        sigscriptl.append(sigscript)        

    return (sigl, sigscriptl, txdict, txtmp)



####
#def assemble_tx(ins, outs, txdict): # assemble tx from dictionary 
def assemble_tx(ins, outs, txdict, inp=True, outp=True, idx=0): 
# assemble tx hex string from dictionary 
    ### Concatenate inputs
    insh=hex(int(ins))[2:]
    outsh=hex(int(outs))[2:]
    inputs=''
    outputs=''
    for i in range(1,int(ins)+1):
        if len(insh) < 2:  txdict['inputs'][i]['input'] = '0'+insh
        inputs +=  txdict['inputs'][i]['UTXO'] + txdict['inputs'][i]['UTXO_VOUT']  + txdict['inputs'][i]['unlockingLen'] + txdict['inputs'][i]['unlocking'] + txdict['inputs'][i]['seq']
    ### Concatenate outputs
    for i in range(1,int(outs)+1):
        if len(outsh) < 2:  txdict['inputs'][i]['output'] = '0'+outsh
        outputs += txdict['outputs'][i]['value'] + txdict['outputs'][i]['locking']

    ### SIGHASH ALL
    if (inp) and (outp) and (idx == 0):
        return txdict['version'] + txdict['input'] + inputs + txdict['output'] + outputs + txdict['locktime']
    ### SIGHASH NONE
    elif (inp) and (not outp):
        return txdict['version'] + txdict['input'] + inputs + txdict['locktime']
    ### SIGHASH SINGLE
    elif ((inp) and (outp) and (idx != 0)):
        return txdict['version'] + txdict['input'] + txdict['inputs'][idx]['UTXO'] + txdict['inputs'][idx]['UTXO_VOUT']  + txdict['inputs'][idx]['unlockingLen'] + txdict['inputs'][idx]['unlocking'] + txdict['inputs'][idx]['seq'] + txdict['outputs'][idx]['value'] + txdict['outputs'][idx]['locking'] + txdict['locktime']


####
def compress(pkey):
    if len(pkey)/2 == 33: 
        return pkey
    elif len(pkey)/2 == 64:
        if int(int(pkey[len(pkey)-1:len(pkey)],16)) % 2 == 0:
            prefix = '02'
        else:
            prefix = '03'
        return prefix + pkey[0:64]
    else:
        print "unknown key"
        exit()
####
