import time
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram import udp
from pyasn1.codec.ber import decoder
from pysnmp.proto import api

from generate_trap import GenerateTrap


TRAP_RCVR='10.99.99.77'

class TrapReceiver:

    def __init__(self, rcv_ip, box_ip, event_name, port=162, inform=None):
	    
        
        
        self.rcvr_ip = rcv_ip
	   
        self.port = port
        self.box_ip = box_ip
        self.event_name = event_name
        self.gen_trap = GenerateTrap(self.box_ip)
        self.inform = inform


    def cbFun(self, transportDispatcher, transportDomain,
            cbCtx, wholeMsg, ):

        print "cbCtx :", cbCtx

        msgVer = int(api.decodeMessageVersion(wholeMsg))
	    #print "Inisde CB FUN..."
           
        
        print 'Inside CB FUN....'

        if msgVer in api.protoModules:
            pMod = api.protoModules[msgVer]
    	else:
            print('Unsupported SNMP version %s' % msgVer)
            #return
    	
        reqMsg, wholeMsg = decoder.decode(
            wholeMsg, asn1Spec=pMod.Message(),
    	)

        self.req = reqMsg

        print 'Type :', type(self.req)

        print 'Inform :', self.inform

        if self.inform:
            print 'Inside Inform IF........'
            if not 'InformRequestPDU()' in str(self.req):
                print 'Inform Message is not sent....failed...'



        print 'reqMsg : %s' % self.req
        #print 'wholeMsg : %s' % wholeMsg

    	#print('Notification message from %s:%s: ' % (
        #    transportDomain, transportAddress
        #    )
    	#)
    	reqPDU = pMod.apiMessage.getPDU(reqMsg)

        print ',,,,reqPDU : %s' % reqPDU
    	varBinds = pMod.apiPDU.getVarBindList(reqPDU)
    	#transportDispatcher.jobFinished(1)
	    
        self.terminationRequestedFlag = True
        if msgVer == api.protoVersion1:
	        self.varBinds = pMod.apiTrapPDU.getVarBindList(reqPDU)
	        self.specificTrap = pMod.apiTrapPDU.getSpecificTrap(reqPDU).prettyPrint()
	        self.version = 1 
	    
        if msgVer == api.protoVersion2c:
	        self.varBinds = pMod.apiPDU.getVarBindList(reqPDU)
	        self.specificTrap = None	
	        self.version = 2


    def timerCb(self, timeNow=10):
	    print "Inside Timer CB..."
	    if self.terminationRequestedFlag: 
	        print "Finishing the Job..."
	        self.transportDispatcher.jobFinished(1)
	    else:
	        self.terminationRequestedFlag = True


    def trap_listener(self):
	    #print "RECEIVER IP:", self.rcvr_ip 
    	self.transportDispatcher = AsynsockDispatcher()
        self.terminationRequestedFlag = False
	    #print "TER FLAG:", self.terminationRequestedFlag

    	self.transportDispatcher.registerRecvCbFun(self.cbFun)
        self.transportDispatcher.registerTimerCbFun(self.timerCb)
    	self.transportDispatcher.registerTransport(udp.domainName,
            udp.UdpSocketTransport().openServerMode(("%s" % self.rcvr_ip, 162))
    	)
        #time.sleep(1)


        # Generate the trap for the given Event.
        self.gen_trap.generate_trap(self.event_name)


    	self.transportDispatcher.jobStarted(1)
        print "Run Dispatcher...."
        self.transportDispatcher.runDispatcher()
        print "Close Dispatcher...."
        self.transportDispatcher.closeDispatcher()
        print "\n"

        #print "varBinds : ", self.varBinds
        #print "Version : ", self.version
        #print "specificTrap : ", self.specificTrap 


        return self.varBinds, self.specificTrap, self.version 


if __name__ == '__main__':

    TrapReceiver(TRAP_RCVR).trap_listener()

