from pyasn1.codec.ber import decoder
from impacket.krb5.asn1 import *
import sys
import base64

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <ticket.kirbi / ticket.b64>\n" % (sys.argv[0]))
        sys.exit(-1)

    with open(sys.argv[1], 'rb') as fd:
        fd = fd.read()
        
        #if base64 blob, decode. 
        if((fd[-1] == 0x3d) or (fd[0] == 0x59)): # 0x3d == '=', 0x59 == 'Y'
            fd = base64.b64decode(fd)
        
        #find AP_REQ offset
        i = 0 
        while(fd[i] != 0x6e):
            i += 1
        
        #parse data
        ap_req = decoder.decode(fd[i:], asn1Spec=AP_REQ())[0]
        service = ap_req['ticket']['sname']['name-string'][0]._value
        host = ap_req['ticket']['sname']['name-string'][1]._value
        domain = ap_req['ticket']['realm']._value
        encType = ap_req['ticket']['enc-part']['etype']._value
        hash = ap_req['ticket']['enc-part']['cipher']._value[:16].hex().upper() + "$" + ap_req['ticket']['enc-part']['cipher']._value[16:].hex().upper() 
        print("$krb5tgs${0}$*{1}${2}${1}/{3}@{2}*${4}".format(encType, service, domain, host, hash))