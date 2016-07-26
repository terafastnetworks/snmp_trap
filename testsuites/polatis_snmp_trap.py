
from snmp_get_set_tables import EventTable, EventLogTable
from gui.snmp import config_snmp
from base import BaseSNMPTrap

import logging
import nose
import re
import time

dict = eval(open("config.txt").read())

AGENT_IP = dict['switch_ip']
TRAP_RCVR = dict['trap_rcvr_ip']


class estBasicSetGetFunctionality(BaseSNMPTrap):


    @classmethod
    def setUpClass(cls):
        config_snmp(AGENT_IP, TRAP_RCVR)



    def testSetGetForEventTypeLog(self):
        """
        Test case that checks for 'set' and 'get' in the EventType - 'log'
        """

        self.log.info(' \n\n\n  *****  Test case : testSetGetForEventTypeLog  *****')

        event_table = EventTable(AGENT_IP, community='private', version=1)
        try:
            event_table.set_event('polatisEventType', '1', 2, 'INTEGER')
        except Exception as err:
            self.log.info("Error:", err)

            
        output = event_table.get_event('polatisEventType', snmp_action='get',
            oid_index='1')
        self.log.info('Output : OID - %s , EventType - %s ' %(output.keys(),
            str(output.values())))
        
        nose.tools.assert_in('2', str(output.values()), 'EventType '
            'log  can not be configured.')


    def testSetGetForEventTypeLogAndTrap(self):
        """
        Test case that checks for 'set' and 'get' in the EventType -
        'log-and-trap'
        """

        self.log.info('\n\n\n  *****  Test case : testSetGetForEventTypeLogAndTrap  *****')

        event_table = EventTable(AGENT_IP, community='private', version=1)
        try:
            event_table.set_event('polatisEventType', '1', 4, 'INTEGER')
        except Exception as err:
            self.log.info("Error:", err)

        output = event_table.get_event('polatisEventType', snmp_action='get',
            oid_index='1')
        self.log.info('Output : OID - %s , EventType - %s ' %(output.keys(), 
            str(output.values())))

        nose.tools.assert_in('4', str(output.values()), 'EventType '
            'log-and-trap can not be configured.')


    def testSetGetForEventTypeNone(self):
        """
        Test case that checks for 'set' and 'get' in the EventType - 'none'
        """

        self.log.info(' \n\n\n  *****  Test case : testSetGetForEventTypeNone  *****')

        event_table = EventTable(AGENT_IP, community='private', version=1)
        try:
            event_table.set_event('polatisEventType', '5', 1, 'INTEGER')

        except Exception as err:
            self.log.info("Error:", err)

        output = event_table.get_event('polatisEventType', snmp_action='get',
            oid_index='5')
        self.log.info('Output : OID - %s , EventType - %s ' %(output.keys(),
            str(output.values())))

        nose.tools.assert_in('1', str(output.values()), 'EventType '
            'none can not be configured.')


    def testSetGetForEventTypeSNMPTRAPUsingV1(self):
        """
        Test case that checks for 'set' and 'get' in the EventType - 'snmp-trap'
        using version V1.
        """

        self.log.info('\n\n\n  *****  Test case : testSetGetForEventTypeSNMPTRAPUsingV1  *****')

        event_table = EventTable(AGENT_IP, community='private', version=1)
        try:
            event_table.set_event('polatisEventType', '5', 3, 'INTEGER')
        
        except Exception as err:
            self.log.info("Error:", err)


        output = event_table.get_event('polatisEventType', snmp_action='get',
            oid_index='5')
        self.log.info('Output : OID - %s , EventType - %s ' %(output.keys(),
            str(output.values())))

        nose.tools.assert_in('3', str(output.values()), 'EventType '
            'snmp-trap using v1 can not be configured.')


    def testSetGetForEventTypeSNMPTRAPUsingV2(self):
        """
        Test case that checks for 'set' and 'get' in the EventType - 'snmp-trap'
        using version V2.
        """

        self.log.info('\n\n\n  *****  Test case : testSetGetForEventTypeSNMPTRAPUsingV2  *****')


        event_table = EventTable(AGENT_IP, community='private', version=2)
        try:
            event_table.set_event('polatisEventType', '7', 3, 'INTEGER')
        except Exception as err:
            self.log.info("Error:", err)


        output = event_table.get_event('polatisEventType', snmp_action='get',
            oid_index='7')
        self.log.info('Output : OID - %s , EventType - %s ' %(output.keys(),
            str(output.values())))

        nose.tools.assert_in('3', str(output.values()), 'EventType '
            'snmp-trap using v2 can not be configured.')

    def testSetGetEventCommunityUsingV1(self):	
        """
        Test case that checks for 'set' and 'get' in the EventCommunity for
        version v1.
        """

        self.log.info('\n\n\n  *****  Test case : testSetGetForEventCommunityUsingV1  *****')

        event_table = EventTable(AGENT_IP, community='private', version=1)
        try:
            event_table.set_event('polatisEventCommunity', '1', 'polatis',
                                'OCTET STRING')

        except Exception as err:
            self.log.info("Error:", err)


        output = event_table.get_event('polatisEventCommunity', snmp_action='get',
            oid_index='1')
        self.log.info('Output : OID - %s , Community String - %s ' %(output.keys(),
            str(output.values())))

        nose.tools.assert_in('polatis', str(output.values()), 'EventTypeCommunity'
            ' can not be configured using V1.')	

        
    def testSetGetEventCommunityUsingV2(self):
        """
        Test case that checks for 'set' and 'get' in the EventCommunity for
        version V2.
        """

        self.log.info('\n\n\n  *****  Test case : testSetGetForEventCommunityUsingV2  *****')

        event_table = EventTable(AGENT_IP, community='private', version=2)
        try:
            event_table.set_event('polatisEventCommunity', '5', 'tera', 'OCTET STRING')
        except Exception as err:
            self.log.info("Error:", err)


        output = event_table.get_event('polatisEventCommunity', snmp_action='get',
            oid_index='5')
        self.log.info('Output : OID - %s , Community String - %s ' %(output.keys(),
            str(output.values())))

        nose.tools.assert_in('tera', str(output.values()), 'EventTypeCommunity'
            ' can not be configured using V2.') 



# ******    EventType 'set_get'  finished   ***** 

class estEventTypeLog(BaseSNMPTrap):
    

    @classmethod
    def setUpClass(cls):

        
        cls.log.info('Configure snmp trap receiver IP : %s , community '
            'and snmp version in switch GUI.' % TRAP_RCVR)
        config_snmp(AGENT_IP, TRAP_RCVR)
        
        # Set EventType using SNMP SET command in polatisEventTable
        cls.event_table = EventTable(AGENT_IP, community='private', version=1)


    def testColdStartEventWithLog(self):
        """
        Aim:
            Check coldStart event for eventType "log"
        Steps:
            1. Configure snmp trap receiver IP and community in polatis switch
                GUI.                         
            2. Perform SNMPSET on polatisEventType MIB Object and set the 
                value as ""log"" . 
            3. Generate ""coldStrat"" event using engineering interface.
            4. Trap Receiver should not receive the coldStrat Events.
            5. Perform SNMPGET on polatisLogEntry Table and make
                sure data is returned.
        Expected Result:
            1. PolatisLogTable should return the accurate values against the
        triggered ColdStartEvent.
                -  polatisLogDescription:  Description of the event triggered. 
                -  polatisLogTime: sysUpTime Value when this event was created. 
                -  polatisLogIndex: Unique entry for each triggered event. 
                -  polatisLogEventIndex: Event entry that triggered this log entry.
            2. Make sure the traps are not sent for ColdStartEvent
        """


        self.log.info('\n\n\n  *****  Test case : testColdStartEventWithLog  *****')

        self.log.info('Set the EventType value as log using snmpset')
        self.event_table.set_event('polatisEventType', '1', 2, 'INTEGER')

        self.verify_trap_and_log('coldstart', '1', 'log')


    def testAuthenticationFailureEventWithLog(self):
        """
        Aim:
            Check Authetication Failure event for eventType "log"
        Steps:
            1. Configure snmp trap receiver IP and community in polatis switch
                GUI.  
            2. Perform SNMPSET on polatisEventType MIB Object and set the value
                as "log" .
            3. Generate "Authetication Failure" event using engineering
                interface.
            4. Trap Receiver should not receive the Authetication Failure
                Events.
            5. Perform SNMPGET on polatisLogEntry Table and make sure data is
                returned.
        Expected Result:
            1. Authetication Failure event should be returned on the
                PolatisLogTable
            2. And no trap should be received against Authetication Failure event
            
        """


        self.log.info(' \n\n\n  *****  Test case : testAuthenticationFailureEventWithLog  *****')
        
        self.log.info('Set the EventType value as log using snmpset')
        self.event_table.set_event('polatisEventType', '5', 2, 'INTEGER')
        
        self.verify_trap_and_log('authfail', '5', 'log')


    def testSwitchCompleteEventWithLog(self):
        """
        Aim:
            Check Switch Complete event for eventType "log"
        Steps:
            1. Configure snmp trap receiver IP and community in polatis switch
                GUI.                         
            2. Perform SNMPSET on polatisEventType MIB
                Object and set the value as ""log"" . 
            3. Generate ""Switch Complete"" event using engineering interface.
            4. Trap Receiver should not receive the Switch Complete Events.
            5. Perform SNMPGET on polatisLogEntry Table and make sure data is returned.
        Expected Result:
            1. SwitchCompleteEvent should be returned on the PolatisLogTable
            2. And no trap should be received against  SwitchCompleteEvent
        """

        self.log.info('\n\n\n  *****  Test case : testSwitchCompleteEventWithLog  *****')

        self.log.info('Set the EventType value as log using snmpset')
        self.event_table.set_event('polatisEventType', '7', 2, 'INTEGER')

        self.verify_trap_and_log('switch', '7', 'log')


    def testPortEnableEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'PortEnable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortEnableEventWithLog  *****'    )

        self.log.info('Set the EventType value as log using snmpset for PortEnableEvent')
        self.event_table.set_event('polatisEventType', '8', 2, 'INTEGER')

        self.verify_trap_and_log('portenable', '8', 'log')
    
    def estPortDisableEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'PortDisable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortDisableEventWithLog  *****')

        self.log.info('Set the EventType value as log using snmpset for PortDisableEvent')
        self.event_table.set_event('polatisEventType', '8', 2, 'INTEGER')

        self.verify_trap_and_log('portdisable', '8', 'log') 

    def testAttenuationCompleteEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'AttenuationComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testAttenuationCompleteEventWithLog *****')

        self.log.info('Set the EventType value as log using snmpset for AttenuationCompleteEvent')
        self.event_table.set_event('polatisEventType', '9', 2, 'INTEGER')

        self.verify_trap_and_log('voa', '9', 'log')


    def testEventMissingEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'EventMissing'
        """

        self.log.info('\n\n\n  *****  Test case : testEventMissingEventWithLog *****')
        
        self.log.info('Set the EventType value as log using snmpset for EventMissingEvent')
        self.event_table.set_event('polatisEventType', '10', 2, 'INTEGER')

        self.verify_trap_and_log('missing', '10', 'log')


    def testFanWarningEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'FanWarning'
        """

        self.log.info('\n\n\n  *****  Test case : testFanWarningEventWithLog *****')

        self.log.info('Set the EventType value as log using snmpset for FanWarningEvent')
        self.event_table.set_event('polatisEventType', '12', 2, 'INTEGER')

        self.verify_trap_and_log('fanwarn', '12', 'log')


    def testFanFailEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'FanFail'
        """

        self.log.info('\n\n\n  *****  Test case : testFanFailEventWithLog *****')

        self.log.info('Set the EventType value as log using snmpset for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 2, 'INTEGER')

        self.verify_trap_and_log('fanfail', '13', 'log')


    def testFPGAEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'FPGA Ptogramming Failure'
        """


        self.log.info('\n\n\n  *****  Test case : testFPGAEventWithLog *****')
 
        self.log.info('Set the EventType value as log using snmpset for FPGAEvent')
        self.event_table.set_event('polatisEventType', '14', 2, 'INTEGER')

        self.verify_trap_and_log('fpga', '14', 'log')


    def testConfigFileErrorEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event
        -   ConfigFileErrorEvent.
        """
 

        self.log.info('\n\n\n  *****  Test case : testConfigFileErrorEventWithLog *****')

        self.log.info('Set the EventType value as log using snmpset for ConfigFileErrorEvent')
        self.event_table.set_event('polatisEventType', '15', 2, 'INTEGER')

        self.verify_trap_and_log('config', '15', 'log')
    

    def testTemperatureRangeErrorEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'TemperatureRangeError'
        """

        self.log.info('\n\n\n  *****  Test case : testTemperatureRangeErrorEventWithLog *****')

        self.log.info('Set the EventType value as log using snmpset for TemperatureRangeErrorEvent')
        self.event_table.set_event('polatisEventType', '16', 2, 'INTEGER')

        self.verify_trap_and_log('temprange', '16', 'log')

    
    def testPowerMonitorLOSAlarmEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'PowerMonitorLOSAlarm'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerMonitorLOSAlarmEventWithLog *****')

        self.log.info('Set the EventType value as log using snmpset for PowerMonitorLOSAlarmEvent')
        self.event_table.set_event('polatisEventType', '17', 2, 'INTEGER')

        self.verify_trap_and_log('pmonlosalarm', '17', 'log')


    def testProtectionSwitchEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'ProtectionSwitch'
        """

        self.log.info('\n\n\n  *****  Test case : testProtectionSwitchEventWithLog *****')

        self.log.info('Set the EventType value as log using snmpset for '
            'ProtectionSwitchEvent ')
        self.event_table.set_event('polatisEventType', '18', 2, 'INTEGER')

        self.verify_trap_and_log('protswitch', '18', 'log')    


    def testPowerSupplyEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'PowerSupply'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerSupplyEventWithLog ')
        '*****'


        self.log.info('Set the EventType value as log using snmpset for '
            'PowerSupplyEvent')
        self.event_table.set_event('polatisEventType', '20', 2, 'INTEGER')
        
        self.verify_trap_and_log('psu', '20', 'log')


    def testPowerMonitorDegradedSignalAlarmEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'PowerMonitorDegradedSignalAlarm'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testPowerMonitorDegradedSignalAlarmEventWithLog *****')

        self.log.info('Set the EventType value as log using snmpset '
            'for PowerMonitorDegradedSignalAlarmEvent')
        self.event_table.set_event('polatisEventType', '21', 2, 'INTEGER')

        self.verify_trap_and_log('pmondegralarm', '21', 'log')            


    def testOXCErrorEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'OXCError'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testOXCErrorEventWithLog  *****')

        self.log.info('Set the EventType value as log using snmpset '
            'for OXCErrorEvent')
        self.event_table.set_event('polatisEventType', '23', 2, 'INTEGER')

        self.verify_trap_and_log('oxcerr', '23', 'log')    


    def testOXCPortErrorEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'OXCPortError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCPortErrorEventWithLog  *****')

        self.log.info('Set the EventType value as log using snmpset '
            'for OXCPortErrorEvent')
        self.event_table.set_event('polatisEventType', '24', 2, 'INTEGER')

        self.verify_trap_and_log('oxcporterr', '24', 'log')    


    def testOXCCompensationResumedEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'OXCCompensationResumed'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCCompensationResumedEventWithLog  *****')

        self.log.info('Set the EventType value as log using snmpset '
            'for OXCCompensationResumedEvent')
        self.event_table.set_event('polatisEventType', '25', 2, 'INTEGER')

        self.verify_trap_and_log('oxccompcomplete', '25', 'log')


    def testSNMPWarningEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'SNMPWarning'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithLog  *****')

        self.log.info('Set the EventType value as log using snmpset '
            'for SNMPWarningEvent')
        self.event_table.set_event('polatisEventType', '27', 2, 'INTEGER')

        self.verify_trap_and_log('snmpwarn', '27', 'log')
        
    
    def testSNMPErrorEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'SNMPError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithLog  *****')

        self.log.info('Set the EventType value as log using snmpset '
            'for SNMPErrorEvent')
        self.event_table.set_event('polatisEventType', '28', 2, 'INTEGER')

        self.verify_trap_and_log('snmperr', '28', 'log')


    def testSystemErrorEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'SystemError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSystemErrorEventWithLog  *****')
        
        self.log.info('Set the EventType value as log using snmpset '
            'for SystemErrorEvent')
        self.event_table.set_event('polatisEventType', '38', 2, 'INTEGER')        

        self.verify_trap_and_log('syserror', '38', 'log')

    
    def testProtectionSwitchFailureEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'ProtectionSwitchFailure'
        """


        self.log.info('\n\n\n  ***** Test case :   '
            'testProtectionSwitchFailureEventWithLog  *****')

        self.log.info('Set the EventType value as log using snmpset '
            'for ProtectionSwitchFailureEvent')
        self.event_table.set_event('polatisEventType', '4', 2, 'INTEGER')

        self.verify_trap_and_log('protavail', '4', 'log')


    def testOPMErrorEventWithLog(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'OPMError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOPMErrorEventWithLog  *****')

        self.log.info('Set the EventType value as log using snmpset '
            'for OPMErrorEvent')
        
        self.event_table.set_event('polatisEventType', '12', 2, 'INTEGER')

        self.verify_trap_and_log('opmerr', '12', 'log')

# ******    EventType 'log'   finished   ***** 




class estEventTypeLogAndTrap(BaseSNMPTrap):
    
    


    @classmethod
    def setUpClass(cls):

        cls.log.info('Configure snmp trap receiver IP : %s , community and '
            'snmp version in switch GUI with trap notification type.' % TRAP_RCVR)
        config_snmp(AGENT_IP, TRAP_RCVR)

        # Set EventType using SNMP SET command in polatisEventTable
        cls.event_table = EventTable(AGENT_IP, community='private', version=1)



    def testColdStartEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and trap
        is received in the configured trap receiver against the event - 'cold
        start'
        """

        self.log.info('\n\n\n  *****  Test case : testColdStartEventWithLogAndTrap  *****')
        
        self.log.info('Set the EventType value as log-and-trap using snmpset')
        self.event_table.set_event('polatisEventType', '1', 4, 'INTEGER')

        self.verify_trap_and_log('coldstart', '1', 'log-and-trap')


    def testAuthenticationFailureEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'AuthenticationFailure'
        """

        self.log.info(' \n\n\n  *****  Test case : testAuthenticationFailureEventWithLogAndTrap  *****')
        
        self.log.info('Set the EventType value as log-and-trap using snmpset')
        self.event_table.set_event('polatisEventType', '5', 4, 'INTEGER')
        
        self.verify_trap_and_log('authfail', '5', 'log-and-trap')


    def testSwitchCompleteEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'SwitchComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testSwitchCompleteEventWithLogAndTrap  *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset')
        self.event_table.set_event('polatisEventType', '7', 4, 'INTEGER')

        self.verify_trap_and_log('switch', '7', 'log-and-trap')


    def testPortEnableEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'PortEnable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortEnableEventWithLogAndTrap  *****'    )

        self.log.info('Set the EventType value as log-and-trap using snmpset for PortEnableEvent')
        self.event_table.set_event('polatisEventType', '8', 4, 'INTEGER')

        self.verify_trap_and_log('portenable', '8', 'log-and-trap')
    
    def estPortDisableEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'PortDisable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortDisableEventWithLogAndTrap  *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset for PortDisableEvent')
        self.event_table.set_event('polatisEventType', '8', 4, 'INTEGER')

        self.verify_trap_and_log('portdisable', '8', 'log-and-trap')

 
    def testAttenuationCompleteEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'AttenuationComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testAttenuationCompleteEventWithLogAndTrap *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset for AttenuationCompleteEvent')
        self.event_table.set_event('polatisEventType', '9', 4, 'INTEGER')

        self.verify_trap_and_log('voa', '9', 'log-and-trap')


    def testEventMissingEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'EventMissing'
        """

        self.log.info('\n\n\n  *****  Test case : testEventMissingEventWithLogAndTrap *****')
        
        self.log.info('Set the EventType value as log-and-trap using snmpset for EventMissingEvent')
        self.event_table.set_event('polatisEventType', '10', 4, 'INTEGER')

        self.verify_trap_and_log('missing', '10', 'log-and-trap')


    def testFanWarningEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'FanWarning'
        """

        self.log.info('\n\n\n  *****  Test case : testFanWarningEventWithLogAndTrap *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset for FanWarningEvent')
        self.event_table.set_event('polatisEventType', '12', 4, 'INTEGER')

        self.verify_trap_and_log('fanwarn', '12', 'log-and-trap')


    def testFanFailEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'FanFail'
        """

        self.log.info('\n\n\n  *****  Test case : testFanFailEventWithLogAndTrap *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 4, 'INTEGER')

        self.verify_trap_and_log('fanfail', '13', 'log-and-trap')


    def testFPGAEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'FPGA Ptogramming Failure'
        """


        self.log.info('\n\n\n  *****  Test case : testFPGAEventWithLogAndTrap *****')
 
        self.log.info('Set the EventType value as log-and-trap using snmpset for FPGAEvent')
        self.event_table.set_event('polatisEventType', '14', 4, 'INTEGER')

        self.verify_trap_and_log('fpga', '14', 'log-and-trap')


    def testConfigFileErrorEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'ConfigFileError'
        """

        self.log.info('\n\n\n  *****  Test case : testConfigFileErrorEventWithLogAndTrap *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset for ConfigFileErrorEvent')
        self.event_table.set_event('polatisEventType', '15', 4, 'INTEGER')

        self.verify_trap_and_log('config', '15', 'log-and-trap')
    

    def testTemperatureRangeErrorEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'TemperatureRangeError'
        """

        self.log.info('\n\n\n  *****  Test case : testTemperatureRangeErrorEventWithLogAndTrap *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset for TemperatureRangeErrorEvent')
        self.event_table.set_event('polatisEventType', '16', 4, 'INTEGER')

        self.verify_trap_and_log('temprange', '16', 'log-and-trap')

    
    def testPowerMonitorLOSAlarmEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'PowerMonitorLOSAlarm'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerMonitorLOSAlarmEventWithLogAndTrap *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset for PowerMonitorLOSAlarmEvent')
        self.event_table.set_event('polatisEventType', '17', 4, 'INTEGER')

        self.verify_trap_and_log('pmonlosalarm', '17', 'log-and-trap')


    def testProtectionSwitchEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'ProtectionSwitch'
        """

        self.log.info('\n\n\n  *****  Test case : testProtectionSwitchEventWithLogAndTrap *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset for '
            'ProtectionSwitchEvent ')
        self.event_table.set_event('polatisEventType', '18', 4, 'INTEGER')

        self.verify_trap_and_log('protswitch', '18', 'log-and-trap')    


    def testPowerSupplyEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'PowerSupply'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerSupplyEventWithLogAndTrap ')
        '*****'


        self.log.info('Set the EventType value as log-and-trap using snmpset for '
            'PowerSupplyEvent')
        self.event_table.set_event('polatisEventType', '20', 4, 'INTEGER')
        
        self.verify_trap_and_log('psu', '20', 'log-and-trap')


    def testPowerMonitorDegradedSignalAlarmEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'PowerMonitorDegradedSignalAlarm'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testPowerMonitorDegradedSignalAlarmEventWithLogAndTrap *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset '
            'for PowerMonitorDegradedSignalAlarmEvent')
        self.event_table.set_event('polatisEventType', '21', 4, 'INTEGER')

        self.verify_trap_and_log('pmondegralarm', '21', 'log-and-trap')            


    def testOXCErrorEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'OXCError'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testOXCErrorEventWithLogAndTrap  *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset '
            'for OXCErrorEvent')
        self.event_table.set_event('polatisEventType', '23', 4, 'INTEGER')

        self.verify_trap_and_log('oxcerr', '23', 'log-and-trap')    


    def testOXCPortErrorEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'OXCPortError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCPortErrorEventWithLogAndTrap  *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset '
            'for OXCPortErrorEvent')
        self.event_table.set_event('polatisEventType', '24', 4, 'INTEGER')

        self.verify_trap_and_log('oxcporterr', '24', 'log-and-trap')    


    def testOXCCompensationResumedEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'OXCCompensationResumed'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCCompensationResumedEventWithLogAndTrap  *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset '
            'for OXCCompensationResumedEvent')
        self.event_table.set_event('polatisEventType', '25', 4, 'INTEGER')

        self.verify_trap_and_log('oxccompcomplete', '25', 'log-and-trap')


    def testSNMPWarningEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'SNMPWarning'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithLogAndTrap  *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset '
            'for SNMPWarningEvent')
        self.event_table.set_event('polatisEventType', '27', 4, 'INTEGER')

        self.verify_trap_and_log('snmpwarn', '27', 'log-and-trap')
        
    
    def testSNMPErrorEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'SNMPError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithLogAndTrap  *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset '
            'for SNMPErrorEvent')
        self.event_table.set_event('polatisEventType', '28', 4, 'INTEGER')

        self.verify_trap_and_log('snmperr', '28', 'log-and-trap')


    def testSystemErrorEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'SystemError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSystemErrorEventWithLogAndTrap  *****')
        
        self.log.info('Set the EventType value as log-and-trap using snmpset '
            'for SystemErrorEvent')
        self.event_table.set_event('polatisEventType', '38', 4, 'INTEGER')        

        self.verify_trap_and_log('syserror', '38', 'log-and-trap')

    
    def testProtectionSwitchFailureEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'ProtectionSwitchFailure'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testProtectionSwitchFailureEventWithLogAndTrap  *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset '
            'for ProtectionSwitchFailureEvent')
        self.event_table.set_event('polatisEventType', '38', 4, 'INTEGER')

        self.verify_trap_and_log('protavail', '38', 'log-and-trap')


    def testOPMErrorEventWithLogAndTrap(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        trap is received in the configured trap receiver against the event -
        'OPMError'
        """


        self.log.info('\n\n\n  ***** Test case :   '
            'testOPMErrorEventWithLogAndTrap  *****')

        self.log.info('Set the EventType value as log-and-trap using snmpset '
            'for OPMErrorEvent')
        self.event_table.set_event('polatisEventType', '38', 4, 'INTEGER')

        self.verify_trap_and_log('opmerror', '38', 'log-and-trap')



# ******    EventType 'log-and-trap'   finished   ***** 





class estEventTypeNone(BaseSNMPTrap):


    @classmethod
    def setUpClass(cls):

        cls.log.info('Configure snmp trap receiver IP : %s ,community string'
            'and snmp version in switch GUI.' % TRAP_RCVR)
        config_snmp(AGENT_IP, TRAP_RCVR)

        # Set EventType using SNMP SET command in polatisEventTable
        cls.event_table = EventTable(AGENT_IP, community='private', version=1)



    def testColdStartEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and trap
        is not received in the configured trap receiver against the event - 'cold
        start'
        """

        self.log.info('\n\n\n  *****  Test case : testColdStartEventWithNone  *****')

        self.log.info('Set the EventType value as none using snmpset')
        self.event_table.set_event('polatisEventType', '1', 1, 'INTEGER')

        self.verify_trap_and_log('coldstart', '1', 'none')


    def testAuthenticationFailureEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'AuthenticationFailure'
        """

        self.log.info(' \n\n\n  *****  Test case : testAuthenticationFailureEventWithNone  *****')
        
        self.log.info('Set the EventType value as none using snmpset')
        self.event_table.set_event('polatisEventType', '5', 1, 'INTEGER')
        
        self.verify_trap_and_log('authfail', '5', 'none')


    def testSwitchCompleteEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'SwitchComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testSwitchCompleteEventWithNone  *****')

        self.log.info('Set the EventType value as none using snmpset')
        self.event_table.set_event('polatisEventType', '7', 1, 'INTEGER')

        self.verify_trap_and_log('switch', '7', 'none')


    def testPortEnableEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'PortEnable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortEnableEventWithNone  *****'    )

        self.log.info('Set the EventType value as none using snmpset for PortEnableEvent')
        self.event_table.set_event('polatisEventType', '8', 1, 'INTEGER')

        self.verify_trap_and_log('portenable', '8', 'none')
   

    def estPortDisableEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'PortDisable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortDisableEventWithNone  *****')

        self.log.info('Set the EventType value as none using snmpset for PortDisableEvent')
        self.event_table.set_event('polatisEventType', '8', 1, 'INTEGER')

        self.verify_trap_and_log('portdisable', '8', 'none')
    

    def testAttenuationCompleteEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'AttenuationComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testAttenuationCompleteEventWithNone *****')

        self.log.info('Set the EventType value as none using snmpset for AttenuationCompleteEvent')
        self.event_table.set_event('polatisEventType', '9', 1, 'INTEGER')

        self.verify_trap_and_log('voa', '9', 'none')


    def testEventMissingEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'EventMissing'
        """

        self.log.info('\n\n\n  *****  Test case : testEventMissingEventWithNone *****')
        
        self.log.info('Set the EventType value as none using snmpset for EventMissingEvent')
        self.event_table.set_event('polatisEventType', '10', 1, 'INTEGER')

        self.verify_trap_and_log('missing', '10', 'none')


    def testFanWarningEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'FanWarning'
        """

        self.log.info('\n\n\n  *****  Test case : testFanWarningEventWithNone *****')

        self.log.info('Set the EventType value as none using snmpset for FanWarningEvent')
        self.event_table.set_event('polatisEventType', '12', 1, 'INTEGER')

        self.verify_trap_and_log('fanwarn', '12', 'none')


    def testFanFailEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'FanFail'
        """

        self.log.info('\n\n\n  *****  Test case : testFanFailEventWithNone *****')

        self.log.info('Set the EventType value as none using snmpset for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 1, 'INTEGER')

        self.verify_trap_and_log('fanfail', '13', 'none')


    def testFPGAEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'FPGA Ptogramming Failure'
        """


        self.log.info('\n\n\n  *****  Test case : testFPGAEventWithNone *****')
 
        self.log.info('Set the EventType value as none using snmpset for FPGAEvent')
        self.event_table.set_event('polatisEventType', '14', 1, 'INTEGER')

        self.verify_trap_and_log('fpga', '14', 'none')


    def testConfigFileErrorEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'ConfigFileError'
        """

        self.log.info('\n\n\n  *****  Test case : testConfigFileErrorEventWithNone *****')

        self.log.info('Set the EventType value as none using snmpset for ConfigFileErrorEvent')
        self.event_table.set_event('polatisEventType', '15', 1, 'INTEGER')

        self.verify_trap_and_log('config', '15', 'none')
    

    def testTemperatureRangeErrorEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'TemperatureRangeError'
        """

        self.log.info('\n\n\n  *****  Test case : testTemperatureRangeErrorEventWithNone *****')

        self.log.info('Set the EventType value as none using snmpset for TemperatureRangeErrorEvent')
        self.event_table.set_event('polatisEventType', '16', 1, 'INTEGER')

        self.verify_trap_and_log('temprange', '16', 'none')

    
    def testPowerMonitorLOSAlarmEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'PowerMonitorLOSAlarm'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerMonitorLOSAlarmEventWithNone *****')

        self.log.info('Set the EventType value as none using snmpset for PowerMonitorLOSAlarmEvent')
        self.event_table.set_event('polatisEventType', '17', 1, 'INTEGER')

        self.verify_trap_and_log('pmonlosalarm', '17', 'none')


    def testProtectionSwitchEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'ProtectionSwitch'
        """

        self.log.info('\n\n\n  *****  Test case : testProtectionSwitchEventWithNone *****')

        self.log.info('Set the EventType value as none using snmpset for '
            'ProtectionSwitchEvent ')
        self.event_table.set_event('polatisEventType', '18', 1, 'INTEGER')

        self.verify_trap_and_log('protswitch', '18', 'none')    


    def testPowerSupplyEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'PowerSupply'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerSupplyEventWithNone ')
        '*****'


        self.log.info('Set the EventType value as none using snmpset for '
            'PowerSupplyEvent')
        self.event_table.set_event('polatisEventType', '20', 1, 'INTEGER')
        
        self.verify_trap_and_log('psu', '20', 'none')


    def testPowerMonitorDegradedSignalAlarmEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'PowerMonitorDegradedSignalAlarm'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testPowerMonitorDegradedSignalAlarmEventWithNone *****')

        self.log.info('Set the EventType value as none using snmpset '
            'for PowerMonitorDegradedSignalAlarmEvent')
        self.event_table.set_event('polatisEventType', '21', 1, 'INTEGER')

        self.verify_trap_and_log('pmondegralarm', '21', 'none')            


    def testOXCErrorEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'OXCError'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testOXCErrorEventWithNone  *****')

        self.log.info('Set the EventType value as none using snmpset '
            'for OXCErrorEvent')
        self.event_table.set_event('polatisEventType', '23', 1, 'INTEGER')

        self.verify_trap_and_log('oxcerr', '23', 'none')    


    def testOXCPortErrorEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'OXCPortError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCPortErrorEventWithNone  *****')

        self.log.info('Set the EventType value as none using snmpset '
            'for OXCPortErrorEvent')
        self.event_table.set_event('polatisEventType', '24', 1, 'INTEGER')

        self.verify_trap_and_log('oxcporterr', '24', 'none')    


    def testOXCCompensationResumedEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'OXCCompensationResumed'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCCompensationResumedEventWithNone  *****')

        self.log.info('Set the EventType value as none using snmpset '
            'for OXCCompensationResumedEvent')
        self.event_table.set_event('polatisEventType', '25', 1, 'INTEGER')

        self.verify_trap_and_log('oxccompcomplete', '25', 'none')


    def testSNMPWarningEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'SNMPWarning'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithNone  *****')

        self.log.info('Set the EventType value as none using snmpset '
            'for SNMPWarningEvent')
        self.event_table.set_event('polatisEventType', '27', 1, 'INTEGER')

        self.verify_trap_and_log('snmpwarn', '27', 'none')
        
    
    def testSNMPErrorEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'SNMPError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithNone  *****')

        self.log.info('Set the EventType value as none using snmpset '
            'for SNMPErrorEvent')
        self.event_table.set_event('polatisEventType', '28', 1, 'INTEGER')

        self.verify_trap_and_log('snmperr', '28', 'none')

    def testSystemErrorEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'SystemError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSystemErrorEventWithNone  *****')
        
        self.log.info('Set the EventType value as none using snmpset '
            'for SystemErrorEvent')
        self.event_table.set_event('polatisEventType', '38', 1, 'INTEGER')        

        self.verify_trap_and_log('syserror', '38', 'none')

    
    def testProtectionSwitchFailureEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'ProtectionSwitchFailure'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testProtectionSwitchFailureEventWithNone  *****')

        self.log.info('Set the EventType value as none using snmpset '
            'for testProtectionSwitchFailureEvent')
        self.event_table.set_event('polatisEventType', '4', 1, 'INTEGER')

        self.verify_trap_and_log('protavail', '4', 'none')

    def testOPMErrorEventWithNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        trap is not received in the configured trap receiver against the event -
        'OPMError'
        """


        self.log.info('\n\n\n  ***** Test case :   '
            'testOPMErrorEventWithNone  *****')
       
        self.log.info('Set the EventType value as none using snmpset '
            'for testOPMErrorEvent')
        self.event_table.set_event('polatisEventType', '12', 1, 'INTEGER')
        
        self.verify_trap_and_log('opmerr', '12', 'none')



# ******    EventType 'none'   finished   ***** 





class testEventTypeSnmpTrapVersionV1(BaseSNMPTrap):
   

    @classmethod
    def setUpClass(cls):
        
        cls.log.info('Configure snmp trap receiver IP : %s , community string and'
            ' SNMP Version in switch GUI.' % TRAP_RCVR)
        config_snmp(AGENT_IP, TRAP_RCVR, community= 'public', snmp_version='v1')
        
        # Set EventType Using SNMP SET command in polatisEventTable
        cls.event_table = EventTable(AGENT_IP, community='private', version=1)


    def testColdStartEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and trap
        is received for Version V1 in the configured trap receiver against the event - 'cold
        start'
        """

        self.log.info('\n\n\n  *****  Test case : testColdStartEventWithSnmpTrapVersionV1  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '1', 3, 'INTEGER')
        
        self.log.info("Trigger ColdStart Event via SNMP Command..")
        self.verify_trap_and_log('coldstart', '1', 'snmp_trapv1')


    def testAuthenticationFailureEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'AuthenticationFailure'
        """

        self.log.info(' \n\n\n  *****  Test case : testAuthenticationFailureEventWithSnmpTrapVersionV1  *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '5', 3, 'INTEGER')
        
        self.verify_trap_and_log('authfail', '5', 'snmp_trapv1')


    def testSwitchCompleteEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'SwitchComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testSwitchCompleteEventWithSnmpTrapVersionV1  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '7', 3, 'INTEGER')

        self.verify_trap_and_log('switch', '7', 'snmp_trapv1')


    def testPortEnableEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'PortEnable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortEnableEventWithSnmpTrapVersionV1  *****'    )

        self.log.info('Set the EventType value as snmp-trap using snmpset for PortEnableEvent')
        self.event_table.set_event('polatisEventType', '8', 3, 'INTEGER')

        self.verify_trap_and_log('portenable', '8', 'snmp_trapv1')
    
    def estPortDisableEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'PortDisable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortDisableEventWithSnmpTrapVersionV1  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for PortDisableEvent')
        self.event_table.set_event('polatisEventType', '8', 3, 'INTEGER')

        self.verify_trap_and_log('portdisable', '8', 'snmp_trapv1')

    
    def testAttenuationCompleteEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'AttenuationComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testAttenuationCompleteEventWithSnmpTrapVersionV1 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for AttenuationCompleteEvent')
        self.event_table.set_event('polatisEventType', '9', 3, 'INTEGER')

        self.verify_trap_and_log('voa', '9', 'snmp_trapv1')


    def testEventMissingEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'EventMissing'
        """

        self.log.info('\n\n\n  *****  Test case : testEventMissingEventWithSnmpTrapVersionV1 *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset for EventMissingEvent')
        self.event_table.set_event('polatisEventType', '10', 3, 'INTEGER')

        self.verify_trap_and_log('missing', '10', 'snmp_trapv1')


    def testFanWarningEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'FanWarning'
        """

        self.log.info('\n\n\n  *****  Test case : testFanWarningEventWithSnmpTrapVersionV1 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for FanWarningEvent')
        self.event_table.set_event('polatisEventType', '12', 3, 'INTEGER')

        self.verify_trap_and_log('fanwarn', '12', 'snmp_trapv1')


    def testFanFailEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'FanFail'
        """

        self.log.info('\n\n\n  *****  Test case : testFanFailEventWithSnmpTrapVersionV1 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 3, 'INTEGER')

        self.verify_trap_and_log('fanfail', '13', 'snmp_trapv1')


    def testFPGAEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'FPGA Ptogramming Failure'
        """


        self.log.info('\n\n\n  *****  Test case : testFPGAEventWithSnmpTrapVersionV1 *****')
 
        self.log.info('Set the EventType value as snmp-trap using snmpset for FPGAEvent')
        self.event_table.set_event('polatisEventType', '14', 3, 'INTEGER')

        self.verify_trap_and_log('fpga', '14', 'snmp_trapv1')


    def testConfigFileErrorEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'ConfigFileError'
        """

        self.log.info('\n\n\n  *****  Test case : testConfigFileErrorEventWithSnmpTrapVersionV1 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for ConfigFileErrorEvent')
        self.event_table.set_event('polatisEventType', '15', 3, 'INTEGER')

        self.verify_trap_and_log('config', '15', 'snmp_trapv1')
    

    def testTemperatureRangeErrorEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'TemperatureRangeError'
        """

        self.log.info('\n\n\n  *****  Test case : testTemperatureRangeErrorEventWithSnmpTrapVersionV1 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for TemperatureRangeErrorEvent')
        self.event_table.set_event('polatisEventType', '16', 3, 'INTEGER')

        self.verify_trap_and_log('temprange', '16', 'snmp_trapv1')

    
    def testPowerMonitorLOSAlarmEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'PowerMonitorLOSAlarm'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerMonitorLOSAlarmEventWithSnmpTrapVersionV1 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for PowerMonitorLOSAlarmEvent')
        self.event_table.set_event('polatisEventType', '17', 3, 'INTEGER')

        self.verify_trap_and_log('pmonlosalarm', '17', 'snmp_trapv1')


    def testProtectionSwitchEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'ProtectionSwitch'
        """

        self.log.info('\n\n\n  *****  Test case : testProtectionSwitchEventWithSnmpTrapVersionV1 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for '
            'ProtectionSwitchEvent ')
        self.event_table.set_event('polatisEventType', '18', 3, 'INTEGER')

        self.verify_trap_and_log('protswitch', '18', 'snmp_trapv1')    


    def testPowerSupplyEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'PowerSupply'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerSupplyEventWithSnmpTrapVersionV1 ')
        '*****'


        self.log.info('Set the EventType value as snmp-trap using snmpset for '
            'PowerSupplyEvent')
        self.event_table.set_event('polatisEventType', '20', 3, 'INTEGER')
        
        self.verify_trap_and_log('psu', '20', 'snmp_trapv1')


    def testPowerMonitorDegradedSignalAlarmEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'PowerMonitorDegradedSignalAlarm'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testPowerMonitorDegradedSignalAlarmEventWithSnmpTrapVersionV1 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for PowerMonitorDegradedSignalAlarmEvent')
        self.event_table.set_event('polatisEventType', '21', 3, 'INTEGER')

        self.verify_trap_and_log('pmondegralarm', '21', 'snmp_trapv1')            


    def testOXCErrorEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'OXCError'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testOXCErrorEventWithSnmpTrapVersionV1  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCErrorEvent')
        self.event_table.set_event('polatisEventType', '23', 3, 'INTEGER')

        self.verify_trap_and_log('oxcerr', '23', 'snmp_trapv1')    


    def testOXCPortErrorEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'OXCPortError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCPortErrorEventWithSnmpTrapVersionV1  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCPortErrorEvent')
        self.event_table.set_event('polatisEventType', '24', 3, 'INTEGER')

        self.verify_trap_and_log('oxcporterr', '24', 'snmp_trapv1')    


    def testOXCCompensationResumedEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'OXCCompensationResumed'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCCompensationResumedEventWithSnmpTrapVersionV1  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCCompensationResumedEvent')
        self.event_table.set_event('polatisEventType', '25', 3, 'INTEGER')

        self.verify_trap_and_log('oxccompcomplete', '25', 'snmp_trapv1')


    def testSNMPWarningEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'SNMPWarning'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithSnmpTrapVersionV1  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SNMPWarningEvent')
        self.event_table.set_event('polatisEventType', '27', 3, 'INTEGER')

        self.verify_trap_and_log('snmpwarn', '27', 'snmp_trapv1')
        
    
    def testSNMPErrorEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'SNMPError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithSnmpTrapVersionV1  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SNMPErrorEvent')
        self.event_table.set_event('polatisEventType', '28', 3, 'INTEGER')

        self.verify_trap_and_log('snmperr', '28', 'snmp_trapv1')

    def testSystemErrorEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'SystemError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSystemErrorEventWithSnmpTrapVersionV1  *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SystemErrorEvent')
        self.event_table.set_event('polatisEventType', '38', 3, 'INTEGER')        

        self.verify_trap_and_log('syserror', '38', 'snmp_trapv1') 

    
    def testProtectionSwitchFailureEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'ProtectionSwitchFailure'
        """


        self.log.info('\n\n\n  ***** Test case :   '
            'testProtectionSwitchFailureEventWithSnmpTrapVersionV1  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for ProtectionSwitchFailureEvent')
        self.event_table.set_event('polatisEventType', '4', 3, 'INTEGER')

        self.verify_trap_and_log('protavail', '4', 'snmp_trapv1')


    def testOPMErrorEventWithSnmpTrapVersionV1(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V1 trap is received in the configured trap receiver against the event -
        'OPMError'
        """

        
        self.log.info('\n\n\n  ***** Test case :   '
            'testOPMErrorEventWithSnmpTrapVersionV1  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OPMErrorEvent')
        self.event_table.set_event('polatisEventType', '12', 3, 'INTEGER')

        self.verify_trap_and_log('opmerr', '12', 'snmp_trapv1')

# ******    EventType 'snmp_trapv1'   finished   ***** 



class testEventTypeSnmpTrapVersionV2(BaseSNMPTrap):
   


    @classmethod
    def setUpClass(cls):
        
        cls.log.info('Configure snmp trap receiver IP : %s , community string and'
            ' SNMP Version in switch GUI.' % TRAP_RCVR)
        config_snmp(AGENT_IP, TRAP_RCVR, community= 'public', snmp_version='v2c')
        
        # Set EventType Using SNMP SET command in polatisEventTable
        cls.event_table = EventTable(AGENT_IP, community='private', version=2)


    def testColdStartEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and trap
        is received for Version V2 in the configured trap receiver against the event - 'cold
        start'
        """

        self.log.info('\n\n\n  *****  Test case : testColdStartEventWithSnmpTrapVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '1', 3, 'INTEGER')
        
        self.log.info("Trigger ColdStart Event via SNMP Command..")
        self.verify_trap_and_log('coldstart', '1', 'snmp_trapv2')


    def testAuthenticationFailureEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'AuthenticationFailure'
        """

        self.log.info(' \n\n\n  *****  Test case : testAuthenticationFailureEventWithSnmpTrapVersionV2  *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '5', 3, 'INTEGER')
        
        self.verify_trap_and_log('authfail', '5', 'snmp_trapv2')


    def testSwitchCompleteEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'SwitchComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testSwitchCompleteEventWithSnmpTrapVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '7', 3, 'INTEGER')

        self.verify_trap_and_log('switch', '7', 'snmp_trapv2')


    def testPortEnableEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'PortEnable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortEnableEventWithSnmpTrapVersionV2  *****'    )

        self.log.info('Set the EventType value as snmp-trap using snmpset for PortEnableEvent')
        self.event_table.set_event('polatisEventType', '8', 3, 'INTEGER')

        self.verify_trap_and_log('portenable', '8', 'snmp_trapv2')
    
    def estPortDisableEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'PortDisable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortDisableEventWithSnmpTrapVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for PortDisableEvent')
        self.event_table.set_event('polatisEventType', '8', 3, 'INTEGER')

        self.verify_trap_and_log('portdisable', '8', 'snmp_trapv2')

    
    def testAttenuationCompleteEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'AttenuationComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testAttenuationCompleteEventWithSnmpTrapVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for AttenuationCompleteEvent')
        self.event_table.set_event('polatisEventType', '9', 3, 'INTEGER')

        self.verify_trap_and_log('voa', '9', 'snmp_trapv2')


    def testEventMissingEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'EventMissing'
        """

        self.log.info('\n\n\n  *****  Test case : testEventMissingEventWithSnmpTrapVersionV2 *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset for EventMissingEvent')
        self.event_table.set_event('polatisEventType', '10', 3, 'INTEGER')

        self.verify_trap_and_log('missing', '10', 'snmp_trapv2')


    def testFanWarningEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'FanWarning'
        """

        self.log.info('\n\n\n  *****  Test case : testFanWarningEventWithSnmpTrapVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for FanWarningEvent')
        self.event_table.set_event('polatisEventType', '12', 3, 'INTEGER')

        self.verify_trap_and_log('fanwarn', '12', 'snmp_trapv2')


    def testFanFailEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'FanFail'
        """

        self.log.info('\n\n\n  *****  Test case : testFanFailEventWithSnmpTrapVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 3, 'INTEGER')

        self.verify_trap_and_log('fanfail', '13', 'snmp_trapv2')


    def testFPGAEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'FPGA Ptogramming Failure'
        """


        self.log.info('\n\n\n  *****  Test case : testFPGAEventWithSnmpTrapVersionV2 *****')
 
        self.log.info('Set the EventType value as snmp-trap using snmpset for FPGAEvent')
        self.event_table.set_event('polatisEventType', '14', 3, 'INTEGER')

        self.verify_trap_and_log('fpga', '14', 'snmp_trapv2')


    def testConfigFileErrorEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'ConfigFileError'
        """

        self.log.info('\n\n\n  *****  Test case : testConfigFileErrorEventWithSnmpTrapVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for ConfigFileErrorEvent')
        self.event_table.set_event('polatisEventType', '15', 3, 'INTEGER')

        self.verify_trap_and_log('config', '15', 'snmp_trapv2')
    

    def testTemperatureRangeErrorEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'TemperatureRangeError'
        """

        self.log.info('\n\n\n  *****  Test case : testTemperatureRangeErrorEventWithSnmpTrapVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for TemperatureRangeErrorEvent')
        self.event_table.set_event('polatisEventType', '16', 3, 'INTEGER')

        self.verify_trap_and_log('temprange', '16', 'snmp_trapv2')

    
    def testPowerMonitorLOSAlarmEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'PowerMonitorLOSAlarm'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerMonitorLOSAlarmEventWithSnmpTrapVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for PowerMonitorLOSAlarmEvent')
        self.event_table.set_event('polatisEventType', '17', 3, 'INTEGER')

        self.verify_trap_and_log('pmonlosalarm', '17', 'snmp_trapv2')


    def testProtectionSwitchEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'ProtectionSwitch'
        """

        self.log.info('\n\n\n  *****  Test case : testProtectionSwitchEventWithSnmpTrapVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for '
            'ProtectionSwitchEvent ')
        self.event_table.set_event('polatisEventType', '18', 3, 'INTEGER')

        self.verify_trap_and_log('protswitch', '18', 'snmp_trapv2')    


    def testPowerSupplyEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'PowerSupply'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerSupplyEventWithSnmpTrapVersionV2 ')
        '*****'


        self.log.info('Set the EventType value as snmp-trap using snmpset for '
            'PowerSupplyEvent')
        self.event_table.set_event('polatisEventType', '20', 3, 'INTEGER')
        
        self.verify_trap_and_log('psu', '20', 'snmp_trapv2')


    def testPowerMonitorDegradedSignalAlarmEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'PowerMonitorDegradedSignalAlarm'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testPowerMonitorDegradedSignalAlarmEventWithSnmpTrapVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for PowerMonitorDegradedSignalAlarmEvent')
        self.event_table.set_event('polatisEventType', '21', 3, 'INTEGER')

        self.verify_trap_and_log('pmondegralarm', '21', 'snmp_trapv2')            


    def testOXCErrorEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'OXCError'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testOXCErrorEventWithSnmpTrapVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCErrorEvent')
        self.event_table.set_event('polatisEventType', '23', 3, 'INTEGER')

        self.verify_trap_and_log('oxcerr', '23', 'snmp_trapv2')    


    def testOXCPortErrorEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'OXCPortError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCPortErrorEventWithSnmpTrapVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCPortErrorEvent')
        self.event_table.set_event('polatisEventType', '24', 3, 'INTEGER')

        self.verify_trap_and_log('oxcporterr', '24', 'snmp_trapv2')    


    def testOXCCompensationResumedEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'OXCCompensationResumed'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCCompensationResumedEventWithSnmpTrapVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCCompensationResumedEvent')
        self.event_table.set_event('polatisEventType', '25', 3, 'INTEGER')

        self.verify_trap_and_log('oxccompcomplete', '25', 'snmp_trapv2')


    def testSNMPWarningEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'SNMPWarning'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithSnmpTrapVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SNMPWarningEvent')
        self.event_table.set_event('polatisEventType', '27', 3, 'INTEGER')

        self.verify_trap_and_log('snmpwarn', '27', 'snmp_trapv2')
        
    
    def testSNMPErrorEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'SNMPError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithSnmpTrapVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SNMPErrorEvent')
        self.event_table.set_event('polatisEventType', '28', 3, 'INTEGER')

        self.verify_trap_and_log('snmperr', '28', 'snmp_trapv2')


    def testSystemErrorEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'SystemError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSystemErrorEventWithSnmpTrapVersionV2  *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SystemErrorEvent')
        self.event_table.set_event('polatisEventType', '38', 3, 'INTEGER')        

        self.verify_trap_and_log('syserror', '38', 'snmp_trapv2') 

    
    def testProtectionSwitchFailureEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'ProtectionSwitchFailure'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testProtectionSwitchFailureEventWithSnmpTrapVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for ProtectionSwitchFailureEvent')
        self.event_table.set_event('polatisEventType', '4', 3, 'INTEGER')

        self.verify_trap_and_log('protavail', '4', 'snmp_trapv2')


    def testOPMErrorEventWithSnmpTrapVersionV2(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V2 trap is received in the configured trap receiver against the event -
        'OPMError'
        """

        
        self.log.info('\n\n\n  ***** Test case :   '
            'testOPMErrorEventWithSnmpTrapVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OPMErrorEvent')
        self.event_table.set_event('polatisEventType', '12', 3, 'INTEGER')

        self.verify_trap_and_log('opmerr', '12', 'snmp_trapv2')

# ******    EventType 'snmp_trapv2'   finished   ***** 



class testEventTypeSnmpTrapVersionV3(BaseSNMPTrap):
   

    @classmethod
    def setUpClass(cls):
        
        cls.log.info('Configure snmp trap receiver IP : %s , username as community and'
            ' SNMP Version as V3 in switch GUI.' % TRAP_RCVR)
        config_snmp(AGENT_IP, TRAP_RCVR, community ='root', snmp_version='v3')

        # Set EventType Using SNMP SET command in polatisEventTable
        cls.event_table = EventTable(AGENT_IP, community='private', version=1)


    def testColdStartEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and trap
        is received for Version V3 in the configured trap receiver against the event - 'cold
        start'
        """

        self.log.info('\n\n\n  *****  Test case : testColdStartEventWithSnmpTrapVersionV3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '1', 3, 'INTEGER')
        
        self.verify_trap_and_log('coldstart', '1', 'snmp_trapv3')


    def testAuthenticationFailureEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'AuthenticationFailure'
        """

        self.log.info(' \n\n\n  *****  Test case : testAuthenticationFailureEventWithSnmpTrapVersionV3  *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '5', 3, 'INTEGER')
        
        self.verify_trap_and_log('', '5', 'snmp_trapv3')


    def testSwitchCompleteEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'SwitchComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testSwitchCompleteEventWithSnmpTrapVersionV3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '7', 3, 'INTEGER')

        self.verify_trap_and_log('switch', '7', 'snmp_trapv3')


    def testPortEnableEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'PortEnable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortEnableEventWithSnmpTrapVersionV3  *****'    )

        self.log.info('Set the EventType value as snmp-trap using snmpset for PortEnableEvent')
        self.event_table.set_event('polatisEventType', '8', 3, 'INTEGER')

        self.verify_trap_and_log('portenable', '8', 'snmp_trapv3')
   

    def estPortDisableEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'PortDisable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortDisableEventWithSnmpTrapVersionV3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for PortDisableEvent')
        self.event_table.set_event('polatisEventType', '8', 3, 'INTEGER')

        self.verify_trap_and_log('portdisable', '8', 'snmp_trapv3')

    
    def testAttenuationCompleteEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'AttenuationComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testAttenuationCompleteEventWithSnmpTrapVersionV3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for AttenuationCompleteEvent')
        self.event_table.set_event('polatisEventType', '9', 3, 'INTEGER')

        self.verify_trap_and_log('voa', '9', 'snmp_trapv3')


    def testEventMissingEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'EventMissing'
        """

        self.log.info('\n\n\n  *****  Test case : testEventMissingEventWithSnmpTrapVersionV3 *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset for EventMissingEvent')
        self.event_table.set_event('polatisEventType', '10', 3, 'INTEGER')

        self.verify_trap_and_log('missing', '10', 'snmp_trapv3')


    def testFanWarningEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'FanWarning'
        """

        self.log.info('\n\n\n  *****  Test case : testFanWarningEventWithSnmpTrapVersionV3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for FanWarningEvent')
        self.event_table.set_event('polatisEventType', '12', 3, 'INTEGER')

        self.verify_trap_and_log('fanwarn', '12', 'snmp_trapv3')


    def testFanFailEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'FanFail'
        """

        self.log.info('\n\n\n  *****  Test case : testFanFailEventWithSnmpTrapVersionV3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 3, 'INTEGER')

        self.verify_trap_and_log('fanfail', '13', 'snmp_trapv3')


    def testFPGAEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'FPGA Ptogramming Failure'
        """


        self.log.info('\n\n\n  *****  Test case : testFPGAEventWithSnmpTrapVersionV3 *****')
 
        self.log.info('Set the EventType value as snmp-trap using snmpset for FPGAEvent')
        self.event_table.set_event('polatisEventType', '14', 3, 'INTEGER')

        self.verify_trap_and_log('fpga', '14', 'snmp_trapv3')


    def testConfigFileErrorEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'ConfigFileError'
        """

        self.log.info('\n\n\n  *****  Test case : testConfigFileErrorEventWithSnmpTrapVersionV3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for ConfigFileErrorEvent')
        self.event_table.set_event('polatisEventType', '15', 3, 'INTEGER')

        self.verify_trap_and_log('config', '15', 'snmp_trapv3')
    

    def testTemperatureRangeErrorEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'TemperatureRangeError'
        """

        self.log.info('\n\n\n  *****  Test case : testTemperatureRangeErrorEventWithSnmpTrapVersionV3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for TemperatureRangeErrorEvent')
        self.event_table.set_event('polatisEventType', '16', 3, 'INTEGER')

        self.verify_trap_and_log('temprange', '16', 'snmp_trapv3')

    
    def testPowerMonitorLOSAlarmEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'PowerMonitorLOSAlarm'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerMonitorLOSAlarmEventWithSnmpTrapVersionV3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for PowerMonitorLOSAlarmEvent')
        self.event_table.set_event('polatisEventType', '17', 3, 'INTEGER')

        self.verify_trap_and_log('pmonlosalarm', '17', 'snmp_trapv3')


    def testProtectionSwitchEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'ProtectionSwitch'
        """

        self.log.info('\n\n\n  *****  Test case : testProtectionSwitchEventWithSnmpTrapVersionV3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for '
            'ProtectionSwitchEvent ')
        self.event_table.set_event('polatisEventType', '18', 3, 'INTEGER')

        self.verify_trap_and_log('protswitch', '18', 'snmp_trapv3')    


    def testPowerSupplyEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'PowerSupply'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerSupplyEventWithSnmpTrapVersionV3 ')
        '*****'


        self.log.info('Set the EventType value as snmp-trap using snmpset for '
            'PowerSupplyEvent')
        self.event_table.set_event('polatisEventType', '20', 3, 'INTEGER')
        
        self.verify_trap_and_log('psu', '20', 'snmp_trapv3')


    def testPowerMonitorDegradedSignalAlarmEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'PowerMonitorDegradedSignalAlarm'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testPowerMonitorDegradedSignalAlarmEventWithSnmpTrapVersionV3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for PowerMonitorDegradedSignalAlarmEvent')
        self.event_table.set_event('polatisEventType', '21', 3, 'INTEGER')

        self.verify_trap_and_log('pmondegralarm', '21', 'snmp_trapv3')            


    def testOXCErrorEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'OXCError'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testOXCErrorEventWithSnmpTrapVersionV3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCErrorEvent')
        self.event_table.set_event('polatisEventType', '23', 3, 'INTEGER')

        self.verify_trap_and_log('oxcerr', '23', 'snmp_trapv3')    


    def testOXCPortErrorEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'OXCPortError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCPortErrorEventWithSnmpTrapVersionV3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCPortErrorEvent')
        self.event_table.set_event('polatisEventType', '24', 3, 'INTEGER')

        self.verify_trap_and_log('oxcporterr', '24', 'snmp_trapv3')    


    def testOXCCompensationResumedEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'OXCCompensationResumed'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCCompensationResumedEventWithSnmpTrapVersionV3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCCompensationResumedEvent')
        self.event_table.set_event('polatisEventType', '25', 3, 'INTEGER')

        self.verify_trap_and_log('oxccompcomplete', '25', 'snmp_trapv3')


    def testSNMPWarningEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'SNMPWarning'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithSnmpTrapVersionV3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SNMPWarningEvent')
        self.event_table.set_event('polatisEventType', '27', 3, 'INTEGER')

        self.verify_trap_and_log('snmpwarn', '27', 'snmp_trapv3')
        
    
    def testSNMPErrorEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'SNMPError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithSnmpTrapVersionV3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SNMPErrorEvent')
        self.event_table.set_event('polatisEventType', '28', 3, 'INTEGER')

        self.verify_trap_and_log('snmperr', '28', 'snmp_trapv3')

    def testSystemErrorEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'SystemError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSystemErrorEventWithSnmpTrapVersionV3  *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SystemErrorEvent')
        self.event_table.set_event('polatisEventType', '38', 3, 'INTEGER')        

        self.verify_trap_and_log('syserror', '38', 'snmp_trapv3') 

    
    def testProtectionSwitchFailureEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'ProtectionSwitchFailure'
        """


        self.log.info('\n\n\n  ***** Test case :   '
            'testProtectionSwitchFailureEventWithSnmpTrapVersionV3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for ProtectionSwitchFailureEvent')
        self.event_table.set_event('polatisEventType', '4', 3, 'INTEGER')

        self.verify_trap_and_log('protavail', '4', 'snmp_trapv3')


    def testOPMErrorEventWithSnmpTrapVersionV3(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable and
        V3 trap is received in the configured trap receiver against the event -
        'OPMError'
        """

        
        self.log.info('\n\n\n  ***** Test case :   '
            'testOPMErrorEventWithSnmpTrapVersionV3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OPMErrorEvent')
        self.event_table.set_event('polatisEventType', '12', 3, 'INTEGER')

        self.verify_trap_and_log('opmerr', '12', 'snmp_trapv3')

# ******    EventType 'snmp_trapv3'   finished   ***** 





class testEventTypeSnmpInformVersionV2(BaseSNMPTrap):
   

    @classmethod
    def setUpClass(cls):
        
        cls.log.info('Configure snmp trap receiver IP : %s , community string and'
            ' SNMP Version  along with inform notification type '
            ' in switch GUI.' % TRAP_RCVR)
        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v2c', notify_type = 'inform')

        # Set EventType Using SNMP SET command in polatisEventTable
        cls.event_table = EventTable(AGENT_IP, community='private', version=1)


    def setUp(self):
        # sleeping for 10 seconds here, since more than one response arrives
        # for single event.
        time.sleep(10)

    def testColdStartEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        inform message is received for Version V2 in the configured trap 
        receiver against the event - 'coldstart'
        """

        self.log.info('\n\n\n  *****  Test case : testColdStartEventWithSnmpInformVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '1', 3, 'INTEGER')
        
        self.verify_trap_and_log('coldstart', '1', 'snmp_informv2')


    def testAuthenticationFailureEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'AuthenticationFailure'
        """

        self.log.info(' \n\n\n  *****  Test case : testAuthenticationFailureEventWithSnmpInformVersionV2  *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '5', 3, 'INTEGER')
        
        self.verify_trap_and_log('authfail', '5', 'snmp_informv2')


    def testSwitchCompleteEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'SwitchComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testSwitchCompleteEventWithSnmpInformVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '7', 3, 'INTEGER')

        self.verify_trap_and_log('switch', '7', 'snmp_informv2')


    def testPortEnableEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'PortEnable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortEnableEventWithSnmpInformVersionV2  *****'    )

        self.log.info('Set the EventType value as snmp-trap using snmpset for PortEnableEvent')
        self.event_table.set_event('polatisEventType', '8', 3, 'INTEGER')

        self.verify_trap_and_log('portenable', '8', 'snmp_informv2')
   

    def estPortDisableEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'PortDisable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortDisableEventWithSnmpInformVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for PortDisableEvent')
        self.event_table.set_event('polatisEventType', '8', 3, 'INTEGER')

        self.verify_trap_and_log('portdisable', '8', 'snmp_informv2')

    
    def testAttenuationCompleteEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'AttenuationComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testAttenuationCompleteEventWithSnmpInformVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for AttenuationCompleteEvent')
        self.event_table.set_event('polatisEventType', '9', 3, 'INTEGER')

        self.verify_trap_and_log('voa', '9', 'snmp_informv2')


    def testEventMissingEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'EventMissing'
        """

        self.log.info('\n\n\n  *****  Test case : testEventMissingEventWithSnmpInformVersionV2 *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset for EventMissingEvent')
        self.event_table.set_event('polatisEventType', '10', 3, 'INTEGER')

        self.verify_trap_and_log('missing', '10', 'snmp_informv2')


    def testFanWarningEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'FanWarning'
        """

        self.log.info('\n\n\n  *****  Test case : testFanWarningEventWithSnmpInformVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for FanWarningEvent')
        self.event_table.set_event('polatisEventType', '12', 3, 'INTEGER')

        self.verify_trap_and_log('fanwarn', '12', 'snmp_informv2')


    def testFanFailEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'FanFail'
        """

        self.log.info('\n\n\n  *****  Test case : testFanFailEventWithSnmpInformVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 3, 'INTEGER')

        self.verify_trap_and_log('fanfail', '13', 'snmp_informv2')


    def testFPGAEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'FPGA Ptogramming Failure'
        """


        self.log.info('\n\n\n  *****  Test case : testFPGAEventWithSnmpInformVersionV2 *****')
 
        self.log.info('Set the EventType value as snmp-trap using snmpset for FPGAEvent')
        self.event_table.set_event('polatisEventType', '14', 3, 'INTEGER')

        self.verify_trap_and_log('fpga', '14', 'snmp_informv2')


    def testConfigFileErrorEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'ConfigFileError'
        """

        self.log.info('\n\n\n  *****  Test case : testConfigFileErrorEventWithSnmpInformVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for ConfigFileErrorEvent')
        self.event_table.set_event('polatisEventType', '15', 3, 'INTEGER')

        self.verify_trap_and_log('config', '15', 'snmp_informv2')
    

    def testTemperatureRangeErrorEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'TemperatureRangeError'
        """

        self.log.info('\n\n\n  *****  Test case : testTemperatureRangeErrorEventWithSnmpInformVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for TemperatureRangeErrorEvent')
        self.event_table.set_event('polatisEventType', '16', 3, 'INTEGER')

        self.verify_trap_and_log('temprange', '16', 'snmp_informv2')

    
    def testPowerMonitorLOSAlarmEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'PowerMonitorLOSAlarm'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerMonitorLOSAlarmEventWithSnmpInformVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for PowerMonitorLOSAlarmEvent')
        self.event_table.set_event('polatisEventType', '17', 3, 'INTEGER')

        self.verify_trap_and_log('pmonlosalarm', '17', 'snmp_informv2')


    def testProtectionSwitchEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'ProtectionSwitch'
        """

        self.log.info('\n\n\n  *****  Test case : testProtectionSwitchEventWithSnmpInformVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for '
            'ProtectionSwitchEvent ')
        self.event_table.set_event('polatisEventType', '18', 3, 'INTEGER')

        self.verify_trap_and_log('protswitch', '18', 'snmp_informv2')    


    def testPowerSupplyEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'PowerSupply'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerSupplyEventWithSnmpInformVersionV2 ')
        '*****'

        self.log.info('Set the EventType value as snmp-trap using snmpset for '
            'PowerSupplyEvent')
        self.event_table.set_event('polatisEventType', '20', 3, 'INTEGER')
        
        self.verify_trap_and_log('psu', '20', 'snmp_informv2')


    def testPowerMonitorDegradedSignalAlarmEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'PowerMonitorDegradedSignalAlarm'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testPowerMonitorDegradedSignalAlarmEventWithSnmpInformVersionV2 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for PowerMonitorDegradedSignalAlarmEvent')
        self.event_table.set_event('polatisEventType', '21', 3, 'INTEGER')

        self.verify_trap_and_log('pmondegralarm', '21', 'snmp_informv2')            


    def testOXCErrorEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'OXCError'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testOXCErrorEventWithSnmpInformVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCErrorEvent')
        self.event_table.set_event('polatisEventType', '23', 3, 'INTEGER')

        self.verify_trap_and_log('oxcerr', '23', 'snmp_informv2')    


    def testOXCPortErrorEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'OXCPortError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCPortErrorEventWithSnmpInformVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCPortErrorEvent')
        self.event_table.set_event('polatisEventType', '24', 3, 'INTEGER')

        self.verify_trap_and_log('oxcporterr', '24', 'snmp_informv2')    


    def testOXCCompensationResumedEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'OXCCompensationResumed'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCCompensationResumedEventWithSnmpInformVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCCompensationResumedEvent')
        self.event_table.set_event('polatisEventType', '25', 3, 'INTEGER')

        self.verify_trap_and_log('oxccompcomplete', '25', 'snmp_informv2')


    def testSNMPWarningEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'SNMPWarning'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithSnmpInformVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SNMPWarningEvent')
        self.event_table.set_event('polatisEventType', '27', 3, 'INTEGER')

        self.verify_trap_and_log('snmpwarn', '27', 'snmp_informv2')
        
    
    def testSNMPErrorEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'SNMPError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithSnmpInformVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SNMPErrorEvent')
        self.event_table.set_event('polatisEventType', '28', 3, 'INTEGER')

        self.verify_trap_and_log('snmperr', '28', 'snmp_informv2')

    def testSystemErrorEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'SystemError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSystemErrorEventWithSnmpInformVersionV2  *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SystemErrorEvent')
        self.event_table.set_event('polatisEventType', '38', 3, 'INTEGER')        

        self.verify_trap_and_log('syserror', '38', 'snmp_informv2') 

    
    def testProtectionSwitchFailureEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'ProtectionSwitchFailure'
        """


        self.log.info('\n\n\n  ***** Test case :   '
            'testProtectionSwitchFailureEventWithSnmpInformVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for ProtectionSwitchFailureEvent')
        self.event_table.set_event('polatisEventType', '4', 3, 'INTEGER')

        self.verify_trap_and_log('protavail', '4', 'snmp_informv2')


    def testOPMErrorEventWithSnmpInformVersionV2(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        V2 inform message is received in the configured trap receiver against the event -
        'OPMError'
        """

        
        self.log.info('\n\n\n  ***** Test case :   '
            'testOPMErrorEventWithSnmpInformVersionV2  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OPMErrorEvent')
        self.event_table.set_event('polatisEventType', '12', 3, 'INTEGER')

        self.verify_trap_and_log('opmerr', '12', 'snmp_informv2')

# ******    EventType 'snmp_informv2'   finished   ***** 



class testEventTypeSnmpInformVersionv3(BaseSNMPTrap):
  

    @classmethod
    def setUpClass(cls):
        
        cls.log.info('Configure snmp trap receiver IP : %s , username as '
            'community and SNMP Version along with inform notification type '
            'via switch GUI.' % TRAP_RCVR)
        config_snmp(AGENT_IP, TRAP_RCVR, community ='root',
            snmp_version='v3', notify_type = 'inform')

        # Set EventType Using SNMP SET command in polatisEventTable
        cls.event_table = EventTable(AGENT_IP, community='private', version=1)


    def setUp(self):
        # sleeping for 10 seconds to avoid checking the trap oids from more
        # than one response for single event.
        time.sleep(10)

    def testColdStartEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        inform message is received for Version v3 in the configured trap 
        receiver against the event - 'coldstart'
        """

        self.log.info('\n\n\n  *****  Test case : testColdStartEventWithSnmpInformVersionv3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '1', 3, 'INTEGER')
        
        self.log.info("Trigger ColdStart Event via SNMP Command..")
        self.verify_trap_and_log('coldstart', '1', 'snmp_informv3')


    def testAuthenticationFailureEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'AuthenticationFailure'
        """

        self.log.info(' \n\n\n  *****  Test case : testAuthenticationFailureEventWithSnmpInformVersionv3  *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '5', 3, 'INTEGER')
        
        self.verify_trap_and_log('authfail', '5', 'snmp_informv3')


    def testSwitchCompleteEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'SwitchComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testSwitchCompleteEventWithSnmpInformVersionv3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset')
        self.event_table.set_event('polatisEventType', '7', 3, 'INTEGER')

        self.verify_trap_and_log('switch', '7', 'snmp_informv3')


    def testPortEnableEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'PortEnable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortEnableEventWithSnmpInformVersionv3  *****'    )

        self.log.info('Set the EventType value as snmp-trap using snmpset for PortEnableEvent')
        self.event_table.set_event('polatisEventType', '8', 3, 'INTEGER')

        self.verify_trap_and_log('portenable', '8', 'snmp_informv3')
    
    def estPortDisableEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'PortDisable'
        """

        self.log.info('\n\n\n  *****  Test case : testPortDisableEventWithSnmpInformVersionv3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for PortDisableEvent')
        self.event_table.set_event('polatisEventType', '8', 3, 'INTEGER')

        self.verify_trap_and_log('portdisable', '8', 'snmp_informv3')

    
    def testAttenuationCompleteEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'AttenuationComplete'
        """

        self.log.info('\n\n\n  *****  Test case : testAttenuationCompleteEventWithSnmpInformVersionv3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for AttenuationCompleteEvent')
        self.event_table.set_event('polatisEventType', '9', 3, 'INTEGER')

        self.verify_trap_and_log('voa', '9', 'snmp_informv3')


    def testEventMissingEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'EventMissing'
        """

        self.log.info('\n\n\n  *****  Test case : testEventMissingEventWithSnmpInformVersionv3 *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset for EventMissingEvent')
        self.event_table.set_event('polatisEventType', '10', 3, 'INTEGER')

        self.verify_trap_and_log('missing', '10', 'snmp_informv3')


    def testFanWarningEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'FanWarning'
        """

        self.log.info('\n\n\n  *****  Test case : testFanWarningEventWithSnmpInformVersionv3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for FanWarningEvent')
        self.event_table.set_event('polatisEventType', '12', 3, 'INTEGER')

        self.verify_trap_and_log('fanwarn', '12', 'snmp_informv3')


    def testFanFailEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'FanFail'
        """

        self.log.info('\n\n\n  *****  Test case : testFanFailEventWithSnmpInformVersionv3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 3, 'INTEGER')

        self.verify_trap_and_log('fanfail', '13', 'snmp_informv3')


    def testFPGAEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'FPGA Ptogramming Failure'
        """


        self.log.info('\n\n\n  *****  Test case : testFPGAEventWithSnmpInformVersionv3 *****')
 
        self.log.info('Set the EventType value as snmp-trap using snmpset for FPGAEvent')
        self.event_table.set_event('polatisEventType', '14', 3, 'INTEGER')

        self.verify_trap_and_log('fpga', '14', 'snmp_informv3')


    def testConfigFileErrorEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'ConfigFileError'
        """

        self.log.info('\n\n\n  *****  Test case : testConfigFileErrorEventWithSnmpInformVersionv3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for ConfigFileErrorEvent')
        self.event_table.set_event('polatisEventType', '15', 3, 'INTEGER')

        self.verify_trap_and_log('config', '15', 'snmp_informv3')
    

    def testTemperatureRangeErrorEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'TemperatureRangeError'
        """

        self.log.info('\n\n\n  *****  Test case : testTemperatureRangeErrorEventWithSnmpInformVersionv3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for TemperatureRangeErrorEvent')
        self.event_table.set_event('polatisEventType', '16', 3, 'INTEGER')

        self.verify_trap_and_log('temprange', '16', 'snmp_informv3')

    
    def testPowerMonitorLOSAlarmEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'PowerMonitorLOSAlarm'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerMonitorLOSAlarmEventWithSnmpInformVersionv3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for PowerMonitorLOSAlarmEvent')
        self.event_table.set_event('polatisEventType', '17', 3, 'INTEGER')

        self.verify_trap_and_log('pmonlosalarm', '17', 'snmp_informv3')


    def testProtectionSwitchEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'ProtectionSwitch'
        """

        self.log.info('\n\n\n  *****  Test case : testProtectionSwitchEventWithSnmpInformVersionv3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset for '
            'ProtectionSwitchEvent ')
        self.event_table.set_event('polatisEventType', '18', 3, 'INTEGER')

        self.verify_trap_and_log('protswitch', '18', 'snmp_informv3')    


    def testPowerSupplyEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'PowerSupply'
        """

        self.log.info('\n\n\n  *****  Test case : testPowerSupplyEventWithSnmpInformVersionv3 ')
        '*****'


        self.log.info('Set the EventType value as snmp-trap using snmpset for '
            'PowerSupplyEvent')
        self.event_table.set_event('polatisEventType', '20', 3, 'INTEGER')
        
        self.verify_trap_and_log('psu', '20', 'snmp_informv3')


    def testPowerMonitorDegradedSignalAlarmEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'PowerMonitorDegradedSignalAlarm'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testPowerMonitorDegradedSignalAlarmEventWithSnmpInformVersionv3 *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for PowerMonitorDegradedSignalAlarmEvent')
        self.event_table.set_event('polatisEventType', '21', 3, 'INTEGER')

        self.verify_trap_and_log('pmondegralarm', '21', 'snmp_informv3')            


    def testOXCErrorEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'OXCError'
        """

        self.log.info('\n\n\n  ***** Test case : '
            'testOXCErrorEventWithSnmpInformVersionv3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCErrorEvent')
        self.event_table.set_event('polatisEventType', '23', 3, 'INTEGER')

        self.verify_trap_and_log('oxcerr', '23', 'snmp_informv3')    


    def testOXCPortErrorEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'OXCPortError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCPortErrorEventWithSnmpInformVersionv3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCPortErrorEvent')
        self.event_table.set_event('polatisEventType', '24', 3, 'INTEGER')

        self.verify_trap_and_log('oxcporterr', '24', 'snmp_informv3')    


    def testOXCCompensationResumedEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'OXCCompensationResumed'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testOXCCompensationResumedEventWithSnmpInformVersionv3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OXCCompensationResumedEvent')
        self.event_table.set_event('polatisEventType', '25', 3, 'INTEGER')

        self.verify_trap_and_log('oxccompcomplete', '25', 'snmp_informv3')


    def testSNMPWarningEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'SNMPWarning'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithSnmpInformVersionv3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SNMPWarningEvent')
        self.event_table.set_event('polatisEventType', '27', 3, 'INTEGER')

        self.verify_trap_and_log('snmpwarn', '27', 'snmp_informv3')
        
    
    def testSNMPErrorEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'SNMPError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSNMPWarningEventWithSnmpInformVersionv3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SNMPErrorEvent')
        self.event_table.set_event('polatisEventType', '28', 3, 'INTEGER')

        self.verify_trap_and_log('snmperr', '28', 'snmp_informv3')

    def testSystemErrorEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'SystemError'
        """

        self.log.info('\n\n\n  ***** Test case :   '
            'testSystemErrorEventWithSnmpInformVersionv3  *****')
        
        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for SystemErrorEvent')
        self.event_table.set_event('polatisEventType', '38', 3, 'INTEGER')        

        self.verify_trap_and_log('syserror', '38', 'snmp_informv3') 

    
    def testProtectionSwitchFailureEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'ProtectionSwitchFailure'
        """


        self.log.info('\n\n\n  ***** Test case :   '
            'testProtectionSwitchFailureEventWithSnmpInformVersionv3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for ProtectionSwitchFailureEvent')
        self.event_table.set_event('polatisEventType', '4', 3, 'INTEGER')

        self.verify_trap_and_log('protavail', '4', 'snmp_informv3')


    def testOPMErrorEventWithSnmpInformVersionv3(self):
        """
        Test case that verifies, logs are returned in the polatisLogTable and
        v3 inform message is received in the configured trap receiver against the event -
        'OPMError'
        """

        
        self.log.info('\n\n\n  ***** Test case :   '
            'testOPMErrorEventWithSnmpInformVersionv3  *****')

        self.log.info('Set the EventType value as snmp-trap using snmpset '
            'for OPMErrorEvent')
        self.event_table.set_event('polatisEventType', '12', 3, 'INTEGER')

        self.verify_trap_and_log('opmerr', '12', 'snmp_informv3')

# ******    EventType 'snmp_informv3'   finished   ***** 



class testNegativeCases(BaseSNMPTrap):
    
    @classmethod
    def setUpClass(cls):
        
        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v1')


    def testInvalidEventTypeValue(self):
        """
        Test case to ensure that setting Invalid EventType value throws an
        error. Try to set the  value as other than "none", "log", "trap" , and
        "log-and-trap"  .
        """

        event_table = EventTable(AGENT_IP, community='private', version=1)
        result = event_table.set_event('polatisEventType', '1', 10, 'INTEGER')

        nose.tools.assert_equal(result, 0, 'Able to set Invalid'
                'EventType value')


    def testInvalidCommunityStringLengthInV1(self):
        """
        Test case that ensures community string could not be set with greater
        than the allowed characters using SNMP Version V1.(>128)
        """

        event_table = EventTable(AGENT_IP, community='private', version=1)

        community_str='SNMPCommunitystringsareusedonlybydeviceswhichsupportSNMPv1andSNMPv2cprotocolSNMPv3usesusernamepasswordauthenticationalongwithanencryptionkey'

        result = event_table.set_event('polatisEventCommunity', '1',
            community_str, 'OCTET STRING')
        
        nose.tools.assert_equal(result, 0, 'Able to set community string with'
            'more than allowed characters via SNMP Version V1.')


    def testInvalidCommunityStringLengthInV2(self):
        """
        Test case that ensures community string could not be set with greater
        than the allowed characters using SNMP Version V2.(>128)
        """

        event_table = EventTable(AGENT_IP, community='private', version=2)
        community_str='SNMPCommunitystringsareusedonlybydeviceswhichsupportSNMPv1andSNMPv2cprotocolSNMPv3usesusernamepasswordauthenticationalongwithanencryptionkey'

        result = event_table.set_event('polatisEventCommunity', '8',
            community_str, 'OCTET STRING')

        nose.tools.assert_equal(result, 0, 'Able to set community string with'
            'more than allowed characters via SNMP Version V2.')


    def testInvalidEventIndexAs0(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the invalid event index as 0 for the given oid.
        """

        event_table = EventTable(AGENT_IP, community='public', version=1)
        result = event_table.get_event('polatisEventDescription', snmp_action='get',
            oid_index='0')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisEventDescription for the invalid EventIndex with 0')
        

    def testInvalidEventIndexAsNegativeValue(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the invalid event index as -1 for the given oid.
        """

        event_table = EventTable(AGENT_IP, community='public', version=1)
        result = event_table.get_event('polatisEventCommunity',
            snmp_action='get', oid_index='-1')



        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisEventCommunity for the invalid EventIndex with -1')


    def testInvalidEventIndexWithMoreThanMaxLimit(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the invalid event index as more than allowed limit
        for the given oid.(>65535)
        """


        event_table = EventTable(AGENT_IP, community='public', version=1)
        result = event_table.get_event('polatisEventType',
            snmp_action='get', oid_index='65536')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisEventType for the invalid EventIndex with 65536')

    def testInvalidEventIndexWithIllegalChar(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the invalid event index as illegal characters for the
        given oid.
        """

        event_table = EventTable(AGENT_IP, community='public', version=1)
        result = event_table.get_event('polatisEventIndex',
            snmp_action='get', oid_index='abcd')


        nose.tools.assert_equal('0', ''.join(result.values()), 'Able to fetch the '
            'polatisEventIndex for the invalid EventIndex with \'abcd\'')


    def testPortEnableEventWithInvalidLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the invalid log index as - '0' for port enable event.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        result = log_table.get_log('polatisLogIndex', snmp_action='get',
            oid_index='8.0')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisLogIndex with the invalid log index as \'0\' for port enable event')


    def testPortDisableEventWithInvalidLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the invalid log index as '-1' for port disable event.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        result = log_table.get_log('polatisLogIndex', snmp_action='get', 
            oid_index='8.-1')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisLogIndex with the invalid log index as \'-1\' for port '
            'disable event')


    def testOXCPortErrorEventWithInvalidLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the invalid log index as more than maximum allowed limit
        for fetching LogDescription of OXCPortErrorEvent. ( to be > 2147483647)
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        result = log_table.get_log('polatisLogDescription', snmp_action='get',
            oid_index='24.2147483649')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisLogDescription with invalid logindex for '
            'OXCPortErrorEvent.')



    def testProtectionSwitchEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
       operation with the non-existent log index for fetching polatisEventIndex
       of ProtectionSwitchEvent.
       """

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        result = log_table.get_log('polatisEventIndex', snmp_action='get',
            oid_index='18.101')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisEventIndex with non-existent logindex for '
            'ProtectionSwitchEvent')

    def testProtectionSwitchFailureEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the non-existent log index for fetching polatisLogIndex
        of ProtectionSwitchFailureEvent.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=2)
        result = log_table.get_log('polatisLogIndex', snmp_action='get',
            oid_index='18.101')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisLogIndex with non-existent logindex for '
            'ProtectionSwitchFailureEvent')


    def testPMONLOSAlarmEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the non-existent log index for fetching polatisLogTime
        of Power Monitor LOSAlarmEvent.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        result = log_table.get_log('polatisLogTime', snmp_action='get',
            oid_index='17.201')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisLogTime with non-existent logindex for '
            'Power Monitor LOSAlarmEvent')


    def testPMONDegradedSignalAlarmEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the non-existent log index for fetching
        polatisLogDescription of Power Monitor DegradedSignalAlarmEvent.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        result = log_table.get_log('polatisLogDescription', snmp_action='get',
            oid_index='21.301')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisLogDescription with non-existent logindex for '
            'Power Monitor DegradedSignalAlarmEvent')    


    def testFanWarningEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the non-existent log index for fetching
        polatisEventIndex of FanWarningEvent.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        result = log_table.get_log('polatisEventIndex', snmp_action='get',
            oid_index='12.401')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisEventIndex with non-existent logindex for '
            'FanWarningEvent')


    def testFanFailEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the non-existent log index for fetching polatisLogIndex
        of FanFailEvent.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=2)
        result = log_table.get_log('polatisLogIndex', snmp_action='get',
            oid_index='13.501')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisLogIndex with non-existent logindex for FanFailEvent')

    
    def testTemperatureErrorEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the non-existent log index for fetching polatisLogTime
        of TemperatureErrorEvent.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        result = log_table.get_log('polatisLogTime', snmp_action='get',
            oid_index='16.601')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisLogTime with non-existent logindex for '
            'TemperatureErrorEvent')


    def testPowerSupplyEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the non-existent log index for fetching
        polatisLogDescription of PowerSupplyEvent.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=2)
        result = log_table.get_log('polatisLogDescription', snmp_action='get',
            oid_index='20.701')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisLogDescription with non-existent logindex for '
            'PowerSupplyEvent')


    def testOXCErrorEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the non-existent log index for fetching
        polatisEventIndex of OXCErrorEvent.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=2)
        result = log_table.get_log('polatisEventIndex', snmp_action='get',
            oid_index='23.801')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisEventIndex with non-existent logindex for '
            ' OXCErrorEvent')

    def testOPMErrorEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the non-existent log index for fetching
        polatisLogIndex of OPMErrorEvent.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=2)
        result = log_table.get_log('polatisLogIndex', snmp_action='get',
            oid_index='4.901')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch the '
            'polatisLogIndex with non-existent logindex for OPMErrorEvent')

    
    def testSystemErrorEventWithNonExistentLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with the non-existent log index for fetching
        polatisLogDescription of SystemErrorEvent.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=2)
        result = log_table.get_log('polatisLogDescription', snmp_action='get',
            oid_index='38.901')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch '
            'the polatisLogDescription with non-existent logindex for'
            'SystemErrorEvent')
        


    def testWithInvalidLogIndexAndInvalidEventIndex(self):    
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with invalid LogIndex and invalid EventIndex for fetching
        polatisLogDescription.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=2)
        result = log_table.get_log('polatisLogDescription', snmp_action='get',
            oid_index='-1.0')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch '
            'the polatisLogDescription with invalid LogIndex and invalid '
            'EventIndex.')

    
    def testWithValidLogIndexAndInvalidEventIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with valid LogIndex and invalid EventIndex for fetching
        polatisLogIndex.
        """

        ## add code to trigger event and get the logindex
        log_table = EventLogTable(AGENT_IP, community='public', version=2)
        result = log_table.get_log('polatisLogIndex', snmp_action='get',
            oid_index='0.1')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch '
            'the polatisLogIndex with valid LogIndex and invalid EventIndex.')


    def testWithValidEventIndexAndInvalidLogIndex(self):
        """
        Test case to verify that error is thrown while performing SNMP GET
        operation with invalid LogIndex and valid EventIndex for fetching
        polatisLogIndex.
        """

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        result = log_table.get_log('polatisLogIndex', snmp_action='get',
            oid_index='1.0')

        nose.tools.assert_equal('', ''.join(result.values()), 'Able to fetch '
            'the polatisLogIndex with invalid LogIndex and valid EventIndex.')
        

    def testCommunityStringWithIllegalChar(self):
        """
        Test case that ensures , not able to set community string with illegal
        characters.
        """

        event_table = EventTable(AGENT_IP, community='private', version=1)
        community_str='$public'
        result = event_table.set_event('polatisEventCommunity', '8',
            community_str, 'OCTET STRING')

        nose.tools.assert_equal(result, '0', 'Able to set community string '
           'with special characters via SNMPSET command.') 


    def testWithMismatchCommunityStringInV1(self):
        """
        Test case to ensure that with the mismatch community string, no trap
        and log is returned using snmp Version v1.
        """

        # Set the community string as other than public and 
        # make sure no trap is received due to mismatch community
        # string
        self.log.info('configure invalid community string in SNMP version V1.')
        config_snmp(AGENT_IP, TRAP_RCVR, community ='abcd123',
            snmp_version='v1')
        
        # Set the EventType value as snmp-trap using snmpset for
        # PortEnableEvent
        try:
            #self.verify_trap_and_log('portenable', '8', 'snmp_trapv1')
            nose.tools.assert_raises(AttributeError,
                 self.verify_trap_and_log,'portenable', '8', 'snmp_trapv1')
        except Exception as err:
            self.log.info('Exception is : %s' % err)
            self.log.info('Trap is received for the mismatch community string'
                'in snmp Version V1')

        # now configure the apt community string and make sure trap is received
        config_snmp(AGENT_IP, TRAP_RCVR, community = 'public',
           snmp_version='v1')
        self.verify_trap_and_log('portenable', '8', 'snmp_trapv1')


    def testWithMismatchCommunityStringInV2(self):
        """
        Test case to ensure that with the mismatch community string, no trap
         and log is returned using snmp Version v2.
        """

        # Set the community string as other than public and and version as v2c
        # make sure no trap is received due to mismatch community string
        config_snmp(AGENT_IP, TRAP_RCVR, community ='abcd123',
            snmp_version='v2c')
        
        # Set the EventType value as snmp-trap using snmpset for
        # PortEnableEvent
        try:
            nose.tools.assert_raises(AttributeError,
                self.verify_trap_and_log, 'portenable', '8', 'snmp_trapv2')
        except Exception as err:
            self.log.info('Exception is : %s' % err)
            self.log.info('Trap is received for the mismatch community string'
                'in snmp Version V2c')

        # now configure the apt community string and make sure trap is received
        config_snmp(AGENT_IP, TRAP_RCVR, community = 'public',
            snmp_version='v2C')
        self.verify_trap_and_log('portenable', '8', 'snmp_trapv2')


class testLimitingCases:


    def testCommunityStringWithMaxLengthInV1(self):
        """
        Test case that verifies the community string can be set with the
        maximum allowed characters via Version V1. (=127)
        """

        event_table = EventTable(AGENT_IP, community='private', version=1)

        community_str='SNMPCommunitystringsareusedonlybydeviceswhichsupportSNMPv1andSNMPv2cprotocolSNMPv3usesusernamepasswordauthenticationalongwithan'

        result = event_table.set_event('polatisEventCommunity', '1',
                        community_str, 'OCTET STRING')

        nose.tools.assert_equal(result, 1, 'Not Able to to set '
            'community string with maximum allowed characters via snmpv1')

        # Perform SNMPGET and makesure community string value has been set.
        result = event_table.get_event('polatisEventCommunity', snmp_action='get',
                       oid_index='1') 
        nose.tools.assert_equal(community_str, ''.join(result.values()), 'Not '
            'able to get the community string value which is been set with '
            'max allowed characters via SNMP Version V1.')



    def testCommunityStringWithMaxLengthInV2(self):
        """
        Test case that verifies the community string can be set with the
        maximum allowed characters via Version V2. (=127)
        """

        event_table = EventTable(AGENT_IP, community='private', version=2)

        community_str='SNMPCommunitystringsareusedonlybydeviceswhichsupportSNMPv1andSNMPv2cprotocolSNMPv3usesusernamepasswordauthenticationalongwithan'

        result = event_table.set_event('polatisEventCommunity', '8',
            community_str, 'OCTET STRING')

        nose.tools.assert_equal(result, 1, 'Able to to set '
            'community string with maximum allowed characters via snmpv2')


        # Perform SNMPGET and makesure community string value has been set.
        result = event_table.get_event('polatisEventCommunity',
            snmp_action='get',oid_index='8')  
        nose.tools.assert_equal(community_str, ''.join(result.values()), 'Not '
            'able to get the community string value which is been set with '
            'max allowed characters via SNMP Version V2.')

    

    def testLogIndexWithMaxLength(self):
        """
        Test case that checks Log Entry is available for the given maximum
        allowed LogIndex Lengh.(=2147483647)
        """

        ### This case fails for now, due to no log entry available for this
        ### LogIndex

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        result = log_table.get_log('polatisLogIndex', snmp_action='get',
                oid_index='1.2147483647')

        nose.tools.assert_equal('2147483647', ''.join(result.values()), 'Not Able to fetch '
            'the polatisLogIndex with maximum allowed LogIndex Length')


    def testEventIndexWithMaxLength(self):
        """
        Test case that checks EventIndex is available for the given maximum
        allowed EventIndex Lengh.(=65535)
        """

        event_table = EventTable(AGENT_IP, community='private', version=1)
        result = event_table.get_event('polatisEventIndex',
                        snmp_action='get',oid_index='8')

        nose.tools.assert_equal('2147483647', ''.join(result.values()), 'Not Able to fetch ' 
            'the polatisEventIndex with maximum allowed EventIndex Length')


class testUpdateCases(BaseSNMPTrap):

    @classmethod
    def setUpClass(cls):
        cls.snmp_base = BaseSNMPTrap()
        cls.event_table = EventTable(AGENT_IP, community='private', version=1)    

    def testModifyTrapDestinations(self):
        """
        Test case that verifies updating existing trap receiver IP, is getting
        modified and working as expected.
        """

        # Configure some Invalid trap destination IP via GUI and make sure no
        # trap returned.
        self.log.info('Configure Invalid Trap Receiver IP....')
        config_snmp(AGENT_IP, '1.1.1.1', community ='public',
            snmp_version='v1', notify_type = 'trap')
       
        self.log.info('Make sure trap is not received....') 
        # Set the EventType value as snmp-trap using snmpset for FanFailEvent 
        self.event_table.set_event('polatisEventType', '13', 3, 'INTEGER')
        
        self.snmp_base.check_no_trap('fanfail', 'log-and-trap')

        # Update the trap destination with valid IP and make sure 
        # trap and log is returned.
        self.log.info('Configure back valid trap receiver IP....')
        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v1')
        # Make sure log and trap is received.
        self.log.info('Make sure trap is received in snmp version v1...')
        self.snmp_base.check_trap('fanfail', snmp_version=1)


    def testModifySNMPVersion(self):
        """
        Test case that verifies updating existing SNMP Version from V1 to V2c, is getting
        modified and working as expected.
        """

        # Configure snmp version as v1 and check for the V1 trap.
        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v1', notify_type = 'trap')    

        self.log.info('Set the EventType value as snmp-trap using snmpset for \
            FPGAEvent')
        self.event_table.set_event('polatisEventType', '14', 3, 'INTEGER')   
        self.snmp_base.check_trap('fanfail', snmp_version=1)

        # Update the version to V2c and check for the V2 trap.
        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v2c')
        self.snmp_base.check_trap('fanfail', snmp_version=2)

    def testModifyTrapDestinationAndSNMPVersion(self):
        """
        Test case that verifies updating existing trap receiver IP and SNMP
        Version, both are getting modified and working as expected.
        """

        # Configure SNMP Version as V2c and some Invalid trap receiver IP.
        # and check no trap is received.
        config_snmp(AGENT_IP, '1.1.1.1', community ='public',
           snmp_version='v2c', notify_type ='trap') 
        self.log.info('Set the EventType value as snmp-trap using snmpset \
            for FanFailEvent') 
        self.event_table.set_event('polatisEventType', '13', 3, 'INTEGER')
        self.snmp_base.check_no_trap('fanfail', 'snmp_trapv1')


        # Update the SNMP Version to V1 and valid trap receiver IP.
        # Ensure V2 trap is received in the configured trap receiver.
        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v1')
        self.snmp_base.check_trap('fanfail', snmp_version=1)


    def testModifyEventTypeWithNotifyTypeTrap(self):
        """
        Test case that verifies modifying EventType from log-and trap to log 
        is working as expected.
        """

        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v1', notify_type = 'trap')
        # Set EventType as 'log-and-trap' and verify both log and trap is
        # received.
        self.log.info('Set the eventType as log-and-trap and make sure both log and '
            'trap is received.')

        self.log.info('Set the EventType value as log-and-trap using snmpset \
             for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 4, 'INTEGER')
        self.verify_trap_and_log('fanfail', '13', 'log-and-trap')

        # Set the EventType as 'log' and verify that only log is received.
        self.log.info('Set the eventType as log and make sure only log is returned')
        
        self.log.info('Set the EventType value as log using snmpset '
            'for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 2, 'INTEGER')
        self.verify_trap_and_log('fanfail', '13', 'log')


    def testModifySNMPVersionAndEventType(self):
        """
        Test case that verifies the changing the existing trap destination ,
        SNMP VErsion and EventType is getting modified and working as expected.
        """

        # Configure trap receiver IP, SNMP version as V2c and eventType
        # as 'log-and-trap'.Ensure eventtype as snmp version is returned as
        # expected.
        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v2c', notify_type = 'trap') 
        self.event_table.set_event('polatisEventType', '13', 4, 'INTEGER')

        # Make sure data is returned as expected.
        self.log.info('Make sure eventType and snmp version is working as expected.')
        self.verify_trap_and_log('fanfail', '13', 'log-and-trap') 
        
        #  Configure trap receiver IP, SNMP version as V1 and
        #  eventType as 'log'.Ensure only log is returned.and trap is received
        #  in snmp version v1.
        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v1', notify_type = 'trap')
        self.event_table.set_event('polatisEventType', '13', 2, 'INTEGER')
        self.verify_trap_and_log('fanfail', '13', 'log')


    def testUpdatingTrapDestAndSNMPVersionWithInform(self):
        """
        Test case that verifies the changing the existing trap destination and
        SNMP version is getting modified and able to receive the inform.
        """
        # Configure SNMP Version as V2c and some Invalid inform receiver IP.
        # and check no inform is received.
        config_snmp(AGENT_IP, '1.1.1.1', community ='public',
            snmp_version='v2c', notify_type = 'inform')
        self.log.info('Set the EventType value as snmp-trap using snmpset \
            for FanFailEvent')
        self.event_table.set_event('polatisEventType', '13', 3, 'INTEGER')
        self.snmp_base.check_no_trap('fanfail', 'snmp_informv2')

        # Update the SNMP Version to V1 and valid trap receiver IP.
        # Ensure V2 inform is received in the configured trap receiver.
        config_snmp(AGENT_IP, TRAP_RCVR, community ='root',
            snmp_version='v3', notify_type = 'inform')
        self.verify_trap_and_log('fanfail', '13', 'snmp_informv3')


    def testModifyEventTypeWithNotifyTypeInform(self):
        """
        Test case that verifies modifying EventType from log-and trap to log 
        is working as expected and able to receive inform message.
        """

        # Set EventType as 'log-and-trap' and verify both log and inform is
        # received.
        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v2c', notify_type = 'inform')
        self.log.info('Set the EventType value as log-and-trap using snmpset \
             for PortEnableEvent')
        self.event_table.set_event('polatisEventType', '8', 4, 'INTEGER')
        self.verify_trap_and_log('portenable', '8', 'log-and-trap')

        # Set the EventType as 'log' and verify that only log is received.
        self.log.info('Set the EventType value as log using snmpset \
            for FanFailEvent')
        self.event_table.set_event('polatisEventType', '8', 2, 'INTEGER')
        self.verify_trap_and_log('portenable', '8', 'none')


    def testInformWithEventTypeLog(self):
        """
        Test case that verifies logs are returned in the polatisLogTable and
        inform is not received in the configured trap receiver against the
        event - 'portenable' 
        """

        config_snmp(AGENT_IP, TRAP_RCVR, community ='root',
            snmp_version='v2c', notify_type = 'trap')

        self.log.info('Set the EventType value as log using snmpset for \
            PowerSupplyEvent')
        self.event_table.set_event('polatisEventType', '20', 1, 'INTEGER')

        self.verify_trap_and_log('portenable', '20', 'log')


    def testInformWithEventTypeNone(self):
        """
        Test case that verifies, logs are not returned in the polatisLogTable
        and inform is not received in the configured trap receiver against the
        event - 'oxc port error'
        """

        config_snmp(AGENT_IP, TRAP_RCVR, community ='public',
            snmp_version='v2c', notify_type = 'inform')

        self.log.info('Set the EventType value as none using snmpset '
            'for OXCPortErrorEvent')
        self.event_table.set_event('polatisEventType', '24', 1, 'INTEGER')

        self.verify_trap_and_log('oxcporterr', '24', 'none')


    def testInformWithEventTypeLogAndTrap(self):
        """
        Test case that verifies, both log and inform message is returned
        against event - 'system error'
       """

        config_snmp(AGENT_IP, TRAP_RCVR, community ='root',
                        snmp_version='v2c', notify_type = 'inform')

        self.log.info('Set the EventType value as log-and-trap using snmpset '
            'for SystemErrorEvent')
        self.event_table.set_event('polatisEventType', '38', 1, 'INTEGER')

        self.verify_trap_and_log('syserror', '38', 'log-and -trap')










