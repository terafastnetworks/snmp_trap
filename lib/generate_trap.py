""" Contains class and functions that generates trap using 'Engineer Interface
Command' through port 9999.
"""

import pexpect
import os
import time

from gui.port_status import PortStatus
from gui.node import Node

class GenerateTrap:

    login_cmd = 'logon engineer P0lat1s'

    def __init__(self, box_ip, port='9999'):
        self.box_ip = box_ip
        self.pxpct = pexpect.spawn('telnet %s %s' % (box_ip, port))
        self.pxpct.expect("Escape character.*")

        self.pxpct.sendline('%s\r' % self.login_cmd)
        self.pxpct.expect('eng\$')
        #pxpct.sendline('event x y')
        #pxpct.expect('Invalid.*')
        #print "After Pexpect:", pxpct.after
        #print "B4 Pexpect:", pxpct.before
        
    def generate_trap(self, event_name, tag=1, msg=None):
	    #print "Sending Trap..."
        #self.pxpct.sendline('%s\r' % self.login_cmd)
        #self.pxpct.expect('eng\$')
        if not msg:
            msg = '%s Event Triggered' % event_name
        #if event_name == 'portdisable':
        #    prt_status = PortStatus()
        #    box = Node(self.box_ip)
        #    #prt_status.enable_port(box, 1)
        #    #time.lseep(5)
        #    prt_status.disable_port(box, 1)

        if event_name == 'coldstart':
            os.system('snmpset -v 2c -m ALL -c private %s polatisSysCtrlRestartAgent.0 i restart' % self.box_ip)

        elif event_name == 'authfail':
            val_rec = os.system('snmpget -v3 -u abcd123 10.99.99.120 .1.3.6.1.4.1.26592.2.6.2.1.1.1.2.5')
            print 'Val Rec', val_rec
        else:
            self.pxpct.sendline('event %s %s' % (event_name, msg))
            print "Msg:", msg
            #self.pxpct.sendline('event %s %s %s' % (event_name, tag, msg))
            #self.pxpct.sendline('event fanwarn 1 "FanWarning"')
            self.pxpct.expect('eng\$')
