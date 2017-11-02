### Written by P. Motylinski, nCrypt Ltd.

from TxTools import *

#def scriptlen(string):
#    new_in_script_sig = string
#    new_in_script_sig_len = len(str(len(new_in_script_sig)/2))
#    if new_in_script_sig_len < 2: in_script_len = '0'+in_script_len
#    if new_in_script_sig_len > 2 and new_in_script_sig_len < 4:
#        in_script_len = 'FD0'+in_script_len
#    if new_in_script_sig_len > 4 and new_in_script_sig_len < 8:
#def script_length(string):
#    l = len(string)/2
#    lhx = hex(l)[2:] if l != 0 else '00'
#    if len(str(lhx)) % 2 != 0: lhx='0'+lhx
#    #print "l: " + str(hex(lhx))
#    #print "string = " + string
#    #print "l = " + str(lhx)
#    if int(l) > 255:
#        #print"l_hex = " + str(hex(l))
##        print"compare " + str(0x00ff)
#        return "4d"+str(lhx)
#    elif int(l) > 65535:
#        return "4e"+str(lhx)
#        #print"l_hex = " + str(hex(l))    
#    else:
#        return str(lhx)
#        #print"l_hex = " + str(hex(l))
        
#####        
class GenericTx:
#    def __init__(self, i_in, i_out, ver=00000001, locktime=0):
    def __init__(self, i_in='00', i_out='00', ver='01000000', locktime='00000000'):
        self.version           = ver
        self.i_input           = i_in
        self.i_output          = i_out
        self.inputcount        = int(self.i_input)
        print "i_input = " + str(self.i_input)
        self.outputcount       = int(self.i_output)
        self.in_prev_out_hash  = []
        self.in_prev_out_idx   = []
        self.in_script_length  = []
        self.in_script_sig     = []
        self.in_sequence       = []
        self.out_value         = []
        self.out_script_length = []
        self.out_scriptPubKey  = []
        self.block_lock_time   = locktime

    def add_input(self, new_in_prev_out_hash, new_in_prev_out_idx, new_in_script_length, new_in_script_sig, new_in_sequence): # add another input block, new_in_script_length obsolete for now
        #in_script_len=str(hex(len(new_in_script_sig)/2)[2:])
        in_script_len=script_length(new_in_script_sig)
        self.inputcount += 1
        if len(hex(self.inputcount)[2:]) < 2: self.i_input = '0'+str(self.inputcount)
        self.in_prev_out_hash.append(new_in_prev_out_hash)
        self.in_prev_out_idx.append(new_in_prev_out_idx) 
        #if len(str(len(new_in_script_sig)/2)) < 2: in_script_len = '0'+in_script_len
        self.in_script_length.append(in_script_len)
        self.in_script_sig.append(new_in_script_sig)   
        self.in_sequence.append(new_in_sequence)     

    def add_signature(self, i_in, new_script_sig, PubKey, tmp): # add signature(s) to input with sequence id
        newPubKeyLen = ''
        if not tmp:
            #newSigLen    = hex( ( (len(str(new_script_sig)) )/2) )[2:]
            newSigLen    = script_length(new_script_sig)
            #newPubKeyLen = hex(len(str(PubKey))/2)[2:]
            newPubKeyLen = script_length(PubKey)
            newScriptSig = str(newSigLen)+new_script_sig+str(newPubKeyLen)+PubKey
            #newScriptSig = str(hex((len(newScriptSig)/2))[2:])+newScriptSig
            newScriptSig = script_length(newScriptSig)+newScriptSig
            self.in_script_length[int(i_in)] = script_length(newScriptSig)#str(hex(len(newScriptSig)/2-1)[2:]) # subtracting the PubKey length byte ???
            self.in_script_sig[int(i_in)] = str(newSigLen) + new_script_sig + str(newPubKeyLen) + PubKey
        else:
            newSigLen    = new_script_sig[:2]
            newScriptSig = new_script_sig[2:]
            self.in_script_length[int(i_in)] = newSigLen
            self.in_script_sig[int(i_in)] = newScriptSig
#str(hex(len(new_script_sig))[2:])+str(new_script_sig)+str(hex(len(PubKey))[2:])+str(PubKey)

    def delete_input(self,idx): # remove input with given index, not verified
        self.inputcount -= 1        
        self.i_input = '0'+str(self.inputcount)
        self.in_prev_out_hash.remove(self.in_prev_out_hash[idx]) 
        self.in_prev_out_idx.remove(self.in_prev_out_idx[idx])
        self.in_script_length.remove(self.in_script_length[idx])
        self.in_script_sig.remove(self.in_script_sig[idx])
        self.in_sequence.remove(self.in_sequence[idx])
        
    def add_output(self, new_out_value, new_out_scriptPubKey):
# add another output block
        self.outputcount += 1
        #out_script_len=str(hex(len(new_out_scriptPubKey)/2)[2:])
        out_script_len=script_length(new_out_scriptPubKey)
        if len(hex(self.outputcount)[2:]) < 2: self.i_output = '0'+str(self.outputcount)
        self.out_value.append(new_out_value)        
        #if len(str(len(new_out_scriptPubKey)/2)) < 2: out_script_len = '0'+out_script_len
        self.out_script_length.append(out_script_len)
        self.out_scriptPubKey.append(new_out_scriptPubKey)

    def delete_output(self,idx): # remove output, not verified
        self.outputcount -= 1
        self.i_output = '0'+str(self.outputcount)
        self.out_value.remove(self.out_value[idx])
        self.out_script_length.remove(self.out_script_length[idx])
        self.out_scriptPubKey.remove(self.out_scriptPubKey[idx])

    def print_input_only(self):
        i = 0
        if self.inputcount > 0: return str(self.version) + str(self.i_input) + str(self.in_prev_out_hash[i]) + str(self.in_prev_out_idx[i]) + str(self.in_script_length[i]) + str(self.in_script_sig[i]) + str(self.in_sequence[i]) 

    def print_output_only(self):
        i = 0
        if self.outputcount > 0: return str(self.i_output) + str(self.out_value[i]) + str(self.out_script_length[i]) + str(self.out_scriptPubKey[i])

    def create_output(self):
        i = 0
        inputs  = ''
        outputs = ''
        incnt=str(hex(self.inputcount)[2:])
        outcnt=str(hex(self.outputcount)[2:])
        in_scrpt_len=str(self.in_script_length[i])
        out_scrpt_len=str(self.out_script_length[i])
        if len(hex(self.inputcount)[2:]) < 2: incnt = '0'+incnt
        for i in range(self.inputcount):
            if len(incnt) < 2: incnt = '0'+incnt
#            print "incnt... = " + str(incnt)
            inputs  += str(self.in_prev_out_hash[i]) + str(self.in_prev_out_idx[i]) + in_scrpt_len + str(self.in_script_sig[i]) + str(self.in_sequence[i])
        if len(hex(self.outputcount)[2:]) < 2: outcnt = '0'+outcnt
        for i in range(self.outputcount):
            if len(outcnt) < 2: outcnt = '0'+outcnt
            outputs += str(self.out_value[i]) + out_scrpt_len + str(self.out_scriptPubKey[i])
        if self.inputcount * self.outputcount > 0: return str(self.version) + incnt + inputs + outcnt + outputs + str(self.block_lock_time)


    def dump(self): # print tx 
        incnt=str(hex(self.inputcount)[2:])
        outcnt=str(hex(self.outputcount)[2:])
        in_script=''
        out_script=''
        inputdict={}
        outputdict={}
        if len(hex(self.inputcount)[2:]) < 2: incnt = '0'+incnt
        if len(hex(self.outputcount)[2:]) < 2: outcnt = '0'+outcnt
        print "version                  : " + str(self.version)
        print "-----------"
        print "input count              : " + incnt
        for i in range(int(self.inputcount)):
            print "      | prev out hash    : " + str(self.in_prev_out_hash[i])
            print "      | prev out idx     : " + str(self.in_prev_out_idx[i])
            print "      | script length    : " + str(self.in_script_length[i])
            if str(self.in_script_length[i]) != '00': in_script = str(self.in_script_length[i]) + str(self.in_script_sig[i])
            print "      | script signature : " + in_script
#            print "      | script signature : " + str(self.in_script_length[i]) + str(self.in_script_sig[i])
            print "      | sequence         : " + str(self.in_sequence[i])
            inputdict[i+1] = {'UTXO': str(self.in_prev_out_hash[i]), 'UTXO_VOUT': str(self.in_prev_out_idx[i]), 'unlockingLen': str(self.in_script_length[i]), 'unlocking':  in_script, 'seq': str(self.in_sequence[i]) }
            print "-----------"
        print "-----------"
        print "output count             : " + outcnt
        for i in range(int(self.outputcount)):
            print "      | value            : " + str(self.out_value[i])
            print "      | script length    : " + str(self.out_script_length[i])
            if str(self.out_script_length[i]) != '00': out_script = str(self.out_script_length[i]) + str(self.out_scriptPubKey[i])
            print "      | script PubKey    : " + out_script
            outputdict[i+1] = {'value': str(self.out_value[i]), 'lockingLen': str(self.out_script_length[i]), 'locking': out_script }
#            print "      | script PubKey    : " + str(self.out_script_length[i]) + str(self.out_scriptPubKey[i])
        print "-----------"
        print "block lock time          : " + str(self.block_lock_time)
        print "-----------"
        txdict = {'version': str(self.version), 'input': incnt,  'inputs': inputdict, 'output': outcnt, 'outputs': outputdict, 'locktime':  str(self.block_lock_time)}
        return (inputdict, outputdict, txdict)

        def len_calc(script):
            length_bytes_int=len(script)/2
            length_bytes_hex=length_bytes_int.encode('hex')
            
            str(hex((len(script)/2))[2:])

#    def assemble_tx(self,txdict): # assemble tx from dictionary 
#        ### Concatenate inputs
#        inputs=''
#        outputs=''
#        for i in range(1,int(self.inputcount)+1):
#            inputs += txdict['inputs'][i]['input'] + txdict['inputs'][i]['UTXO'] + txdict['inputs'][i]['UTXO_VOUT'] + txdict['inputs'][i]['unlockingLen'] + txdict['inputs'][i]['unlocking'] + txdict['inputs'][i]['seq']
#        for i in range(1,int(self.outputcount)+1):
#            outputs += txdict['outputs'][i]['output'] + txdict['outputs'][i]['value'] + txdict['outputs'][i]['lockingLen'] + txdict['outputs'][i]['locking']
#        return txdict['version'] + inputs + outputs + txdict['locktime']
#########
### Standard TX template - work in progress, currently not to be used

class StandardRawTx(GenericTx):

    def __init__(self, prev_out_hash, scriptSig, out_value, out_script_length, outScriptPubKey, locktime='00000000'):
        self.version           = '00000001'
        i_in  = 0
        i_out = 0
        self.i_input           = i_in
        self.i_output          = i_out
        self.inputcount        = '01' # int(self.i_input)
        self.outputcount       = '01' # int(self.i_output)
        self.in_prev_out_hash  = [prev_out_hash]
        self.in_prev_out_idx   = ['01000000']
        self.in_script_length  = ['00']
        self.in_script_sig     = [scriptSig]
        self.in_sequence       = ['ffffffff']
        self.out_value         = [out_value]
        self.out_script_length = ['00']
        self.out_scriptPubKey  = [outScriptPubKey]
        self.block_lock_time   = locktime

