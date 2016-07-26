from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c

from pysnmp.proto import api
import time



TRAP_RCVR='10.99.99.32'


class V3TrapReceiver:

    def __init__(self, rcv_ip, box_ip, event_name, port=162):
        self.rcvr_ip = rcv_ip
        self.port = port
        
        self.box_ip = box_ip
        self.event_name = event_name
        # Create SNMP engine with autogenernated engineID and pre-bound
        # to socket transport dispatcher
        #self.snmpEngine = engine.SnmpEngine()
         

    # Callback function for receiving notifications
    def cbFun(self, snmpEngine, contextEngineId, contextName,
            varBinds, cbCtx):
        print 'Inside cbFun......'
        
        #print('Notification received, ContextEngineId "%s", ContextName "%s"' \
        #   % (contextEngineId.prettyPrint(), contextName.prettyPrint())
        #)
        #print '\n ContextEngineId : ', contextEngineId.prettyPrint()
        #print '\n contextName : ', contextEngineId.prettyPrint()
        #from pyasn1.codec.ber import decoder
        #print ' cbCtx :', cbCtx.prettyPrint().encode("hex")


        #v2c.InformRequestPDU.tagSet(varBinds)

        cnt = 1
        for name, val in varBinds:
            if cnt ==2:
                print('Name : %s = Val :%s' % (name.prettyPrint(), val.prettyPrint())) 
                trap_val = val.prettyPrint()
                sepcTrap = trap_val.split('.')[-1]
                print " Trap Spec :  ",sepcTrap
            cnt+=1
      
        self.varBinds = varBinds
        self.oid = trap_val
        self.specTrap = sepcTrap
        self.version = 3

        self.terminationRequestedFlag = True 


    def __timerCbFun(self, timeNow=10):
        print "Inside Timer CB..."


        if self.terminationRequestedFlag:
            self.snmpEngine.transportDispatcher.jobFinished(1)
            print "Finishing the Job..."
        else:
            self.terminationRequestedFlag = True

    def v3_trap_listener(self):
        
        # Transport setup
        self.snmpEngine = engine.SnmpEngine()

        self.terminationRequestedFlag = False
        # UDP over IPv4

        print "Attempts to connect........"
        config.addSocketTransport(self.snmpEngine, udp.domainName,
            udp.UdpSocketTransport().openServerMode(('%s' % self.rcvr_ip, 162))
        )
        print "connected........"

        # SNMPv3/USM setup
    
        # user: usr-md5-des, auth: MD5, priv DES
        # user: root, auth: MD5, priv DES

        config.addV3User(self.snmpEngine, 'root',
            config.usmHMACMD5AuthProtocol, 'authkey1',
            config.usmDESPrivProtocol, 'privkey1'
        )
        print 'V3 user added'

        
        # Register SNMP Application at the SNMP engine
        ntfrcv.NotificationReceiver(self.snmpEngine, self.cbFun)


        # To finish the Job
        self.snmpEngine.transportDispatcher.unregisterTimerCbFun() 
        self.snmpEngine.transportDispatcher.registerTimerCbFun(self.__timerCbFun)




        print 'Start Job.....'
        self.snmpEngine.transportDispatcher.jobStarted(1)

        # Generate event via Engg Interface once after Job started...
        from generate_trap import GenerateTrap
        gen_trap = GenerateTrap(self.box_ip)  
        gen_trap.generate_trap(self.event_name)   


        print "Run Dispatcher...."
        self.snmpEngine.transportDispatcher.runDispatcher()
        
        print "Close Dispatcher...."
        self.snmpEngine.transportDispatcher.closeDispatcher()
        

        return self.varBinds,  self.specTrap, self.version

if __name__ == '__main__':

    #from generate_trap import GenerateTrap
    #gen_trap = GenerateTrap('10.99.99.120') 
    #gen_trap.generate_trap('fanwarn')

    V3TrapReceiver(TRAP_RCVR).v3_trap_listener()







