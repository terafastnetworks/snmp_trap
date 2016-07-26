
from trap_receiver import TrapReceiver
from v3_trap_receiver import V3TrapReceiver
from snmp_get_set_tables import EventTable, EventLogTable
from gui.snmp import config_snmp
from gui.port_status import PortStatus
from gui.node import Node


import logging
import netsnmp
import nose
import re
import datetime
import time
import os
import unittest
import sys

PASS_CNT = 0
FAIL_CNT = 0
PASS_LST = []
FAIL_LST = []

dict = eval(open("config.txt").read())

AGENT_IP = dict['switch_ip']
TRAP_RCVR = dict['trap_rcvr_ip']


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

class BaseSNMPTrap(unittest.TestCase):


    log = logging.getLogger(__name__)
    log.setLevel(logging.INFO)
    handler = logging.FileHandler(dict['log_filename'], mode='w')
    handler.setLevel(logging.INFO)
    log.addHandler(handler)

    """
    #received oids
    trap_oids = {
        'switch'          :    '.1.3.6.1.4.1.26592.2.1.3.0.7',
        'portenable'      :    '.1.3.6.1.4.1.26592.2.1.3.0.8',
        'portdisable'     :    '.1.3.6.1.4.1.26592.2.1.3.0.8',
        'fanwarn'         :    '.1.3.6.1.4.1.26592.2.1.3.0.7',        
        'fanfail'         :    '.1.3.6.1.4.1.26592.2.1.3.0.9',
        'oxccompcomplete' :    '.1.3.6.1.4.1.26592.2.1.3.0.6',
        'oxcporterr'      :    '.1.3.6.1.4.1.26592.2.1.3.0.13',
        'oxcerr'          :    '.1.3.6.1.4.1.26592.2.1.3.0.11',
        'pmondegralarm'   :    '.1.3.6.1.4.1.26592.2.1.3.0.5',
        'psu'             :    '.1.3.6.1.4.1.26592.2.1.3.0.17',
        'protswitch'      :    '.1.3.6.1.4.1.26592.2.1.3.0.2',
        'pmonlosalarm'    :    '.1.3.6.1.4.1.26592.2.1.3.0.3',
        'temprange'       :    '.1.3.6.1.4.1.26592.2.1.3.0.9',
        'config'          :    '.1.3.6.1.4.1.26592.2.1.3.0.13',
        'fpga'            :    '.1.3.6.1.4.1.26592.2.1.3.0.11',
        'missing'         :    '.1.3.6.1.4.1.26592.2.1.3.0.19',
        'syserror'        :    '.1.3.6.1.4.1.26592.2.1.3.0.15',
        'voa'             :    '.1.3.6.1.4.1.26592.2.1.3.0.2',
        'snmpwarn'        :    '',
        'snmperr'         :    '',
        'protavail'       :    '',
        'opmerr'          :    '',
        #'coldstart'       :    '.1.3.6.1.4.1.26592.2.1.3.0.0'
        'coldstart'       :    '1.3.6.1.6.3.1.1.5.1'
    }    

    """



    #actual oids
    trap_oids = {
        'switch'          :    '.1.3.6.1.4.1.26592.2.1.3.0.7',
        'portenable'      :    '.1.3.6.1.4.1.26592.2.1.3.0.8',
        'portdisable'     :    '.1.3.6.1.4.1.26592.2.1.3.0.8',
        'fanwarn'         :    '.1.3.6.1.4.1.26592.2.1.3.0.12',
        'fanfail'         :    '.1.3.6.1.4.1.26592.2.1.3.0.13',
        'oxccompcomplete' :    '.1.3.6.1.4.1.26592.2.1.3.0.25',
        'oxcporterr'      :    '.1.3.6.1.4.1.26592.2.1.3.0.24',
        'oxcerr'          :    '.1.3.6.1.4.1.26592.2.1.3.0.23',
        'pmondegralarm'   :    '.1.3.6.1.4.1.26592.2.1.3.0.21',
        'psu'             :    '.1.3.6.1.4.1.26592.2.1.3.0.20',
        'protswitch'      :    '.1.3.6.1.4.1.26592.2.1.3.0.18',
        'pmonlosalarm'    :    '.1.3.6.1.4.1.26592.2.1.3.0.17',
        'temprange'       :    '.1.3.6.1.4.1.26592.2.1.3.0.16',
        'config'          :    '.1.3.6.1.4.1.26592.2.1.3.0.15',
        'fpga'            :    '.1.3.6.1.4.1.26592.2.1.3.0.14',
        'missing'         :    '.1.3.6.1.4.1.26592.2.1.3.0.10',
        'syserror'        :    '.1.3.6.1.4.1.26592.2.1.3.0.9',
        'voa'             :    '.1.3.6.1.4.1.26592.2.1.3.0.2',
        'snmpwarn'        :    '.1.3.6.1.4.1.26592.2.1.3.0.27',
        'snmperr'         :    '.1.3.6.1.4.1.26592.2.1.3.0.28',
        'protavail'       :    '.1.3.6.1.4.1.26592.2.1.3.0.',
        'opmerr'          :    '.1.3.6.1.4.1.26592.2.1.3.0.',
        'coldstart'       :    '1.3.6.1.6.3.1.1.5.1'

    }


    start_time = time.time()



    @classmethod
    def setUpClass(cls):
        cls.trap_rcvr = TrapReceiver(TRAP_RCVR)
        cls.gen_trap = GenerateTrap(AGENT_IP)
        cls.start_time = time.time()

    @classmethod
    def tearDownClass(cls):
        cls.end_time = time.time()
        cls.endTime = datetime.datetime.utcfromtimestamp(cls.end_time)
        cls.stTime = datetime.datetime.utcfromtimestamp(cls.start_time)

        cls.log.info('\n\n Time Took to execute :  %s seconds ......' % \
            (cls.endTime-cls.stTime))
        result_summary()


    def setUp(self):
        msg = '*** Starting %s test case. ***' % self._testMethodName
        self.log.info('*' * len(msg))
        self.log.info(msg)
        self.log.info('*' * len(msg))


    def tearDown(self):
        
        
        result = sys.exc_info()
        
        
        if result[0] == result[1] == result[2] == None:
            self.log.info('\nTest Case %s resulted in pass.' % self._testMethodName)
            case_result(True, '%s' % self._testMethodName)
        else:
            self.log.info('Following Exception occured: %s' %result[1])
            self.log.info('\nTest Case %s resulted in fail.' % self._testMethodName)
            case_result(False, '%s' % self._testMethodName)



    def check_trap_value(self, trap_value):
        for oid, value in trap_value:
            #self.log.info("OID:%s --- Value:%s" % (oid.prettyPrint(), \)
            #    value.prettyPrint())
            match = re.search(r'.*objectID-value=([0-9.]+)', \
                value.prettyPrint())
            if match:
                rcvd_trap_oid = match.group(1)
                return rcvd_trap_oid


    def verify_trap_and_log(self, trap_name, event_index, event_type):
        """
        Procedure that generates trap using engineering interface against the
        given trapname and verifies the trap is received on the configured
        receiver based on the EventType.
        And  walks through the polatisLogTable then gets the log details based
        on the latest log index for the given corresponding event index and
        verifies them according to EventType.
        """   
        #self.log.info('Check for Trap & Log') 

        
        #self.log.info('Get the very last log index for the given event before '
        #    'Triggering the Event, so that we could make sure it is incremented by '
        #    'one, once the same event is triggered.')
        self.log.info('Fetching the log index of %s event ......' % trap_name)
        self.init_log_index = self.get_log_index(event_index)
        self.log.info('Log Index before event is triggered : %s'  % self.init_log_index)
        
        ### Triggeres event using engineering interface

        #if trap_name:
        #    self.log.info("Generating Trap for the event : %s " % trap_name)
        #    self.gen_trap.generate_trap(trap_name)
        
        ### Checks whether trap is received in the trap listener 
        
        if event_type == 'log-and-trap':
            self.check_trap(trap_name)
            self.check_log(event_index, event_type)

        elif event_type == 'log':
            self.check_no_trap(trap_name, event_type)
            self.check_log(event_index, event_type)

        elif event_type == 'none':
            self.check_no_trap(trap_name, event_type)
            self.check_no_log(event_index, event_type)
            

        elif event_type == 'snmp_trapv1':
            self.check_trap(trap_name, snmp_version=1)
            self.check_no_log(event_index, event_type)

        elif event_type == 'snmp_trapv2':
            self.check_trap(trap_name, snmp_version=2)
            self.check_no_log(event_index, event_type)

        elif event_type == 'snmp_trapv3':
            self.check_trap(trap_name, snmp_version=3)
            self.check_no_log(event_index, event_type)

        elif event_type == 'snmp_informv2':
            self.check_trap(trap_name, snmp_version=2, inform = True)

        elif event_type == 'snmp_informv3':
            self.check_trap(trap_name, snmp_version=3)
        
        else:
            raise Exception("EventType should be either of the following. "
                "'log', 'log-and-trap', 'snmp-trapv1', 'snmp-trapv2', "
                " 'snmp-trapv3' , 'snmp_informv2', 'snmp_informv3' and 'none'.")

            
            
    def check_trap(self, trap_name, snmp_version = None, inform = None):


        #self.log.info("Make sure trap is received for Event: %s with EventType : %s " % (trap_name, event_type))
       


        self.log.info('Make sure Trap is received...')
       
        """ 
        try:
            (trap_val, version, spec_trap) = self.trap_rcvr.trap_listener()
        except Exception as err:
            self.log.info('Failed to receive Trap , Exception : %s' % err)
        """

        if snmp_version == 3:

            try:
                trap_rcvr = V3TrapReceiver(TRAP_RCVR, AGENT_IP, trap_name)
                (trap_val, spec_trap, version) =  trap_rcvr.v3_trap_listener()
            except Exception as err:
                self.log.info('Failed to receive V3 Trap , Exception : %s' % err)
                raise Exception('Failed to receive Trap , Exception : %s' % err)
        else:

            try:
                trap_rcvr = TrapReceiver(TRAP_RCVR, AGENT_IP, trap_name, inform = inform)
                (trap_val, spec_trap, version) =  trap_rcvr.trap_listener()
        
            except Exception as err:
                self.log.info('Failed to receive Trap , Exception : %s' % err)
                raise Exception('Failed to receive Trap , Exception : %s' % err)

        if trap_val:
            #self.log.info("Version %s:" % version)
            #self.log.info("Trap_val %s:" % trap_val)
            #self.log.info("Received Trap OID : %s" % spec_trap)
            self.log.info("Expected Trap OID : %s" % self.trap_oids[trap_name].split('.')[-1] )


        
        if snmp_version:
            if snmp_version == version:
                self.log.info('Trap received in SNMP Version : V%d' % snmp_version)
            else:
                raise Exception('Mismatch SNMP Version : V%d for V%d' % (version, snmp_version))
        

        if version == 2:
            obt_oid=self.check_trap_value(trap_val)
            nose.tools.assert_equal(obt_oid.split('.')[-1], 
                self.trap_oids[trap_name].split('.')[-1], 
                'EvenIndex Mismatched for the event %s in SNMP Version V2' % trap_name)

        else:
            nose.tools.assert_equal(spec_trap, 
                self.trap_oids[trap_name].split('.')[-1],
                'EvenIndex Mismatched for the event \'%s\' in SNMP Version V%s' % \
                (trap_name, version))


    def check_no_trap(self, trap_name, event_type):

        self.log.info('Make sure Trap is not received...')
        #self.log.info("Make sure trap is not received for Event: %s with EventType : %s " % (trap_name, event_type))
        trap_rcvr = TrapReceiver(TRAP_RCVR, AGENT_IP, trap_name)

        try:
            nose.tools.assert_raises(AttributeError,
                trap_rcvr.trap_listener)
        except Exception as err:
            self.log.info('Exception is : %s' % err)
            raise Exception("Trap is received for Event - '%s' with EventType \
                - '%s'" % (trap_name, event_type))
        


    def check_log(self, event_index, event_type):
        ### Checks whether log is returned in the PolatisLogTable 

        self.log.info('Fetches and verifies the polatisLogTable output')
        log_index = self.get_log_index(event_index)
        self.log.info('Log Index after event triggered : %s'  % log_index)


        self.log.info('Make sure log is returned .......')
        if not self.init_log_index+1  == log_index:
            raise Exception('Log is not received in the polatisLogTable '
                'for the EventType : %s' % event_type) 

        oid_index = event_index+'.'+str(log_index)
        #self.log.info('OID Index : %s' % oid_index)

        log_table = EventLogTable(AGENT_IP, community='public', version=1)
        table_colums = ['polatisEventIndex', 'polatisLogIndex',
            'polatisLogTime', 'polatisLogDescription']
       
        log_output = {}


        for no in range(len(table_colums)):
            output = log_table.get_log(table_colums[no],
                snmp_action='get', oid_index=oid_index)
            log_output[table_colums[no]] = output

        self.log.info('Make sure log is returned .......')
        self.log.info('Log Table Output :  %s' % log_output)
        
        if event_index == str(1):
            nose.tools.assert_equal(log_output['polatisLogDescription'].values(),
                ['Cold start'], 'Description mismatches in the log table.')
        
        #elif event_index == str(8):
        #    pass    
        
        else:
            nose.tools.assert_equal(log_output['polatisLogDescription'].values(),
                ['(ENG) Event Triggered'], 'Description mismatches in the log table.')
        
        nose.tools.assert_in(str(log_index), log_output['polatisLogIndex'].values(),
            'Log index mismatches in the polatisLogTable')
        nose.tools.assert_in(event_index, log_output['polatisEventIndex'].values(),
            'Event index mismatches in the polatisLogTable')


    def check_no_log(self, event_index, event_type):

        #self.log.info('Make sure log is not returned for EventIndex - %s with ')
        #'EventType - %s' % (event_index, event_type)
        

        self.log.info('Fetches and verifies the polatisLogTable output')
        log_index = self.get_log_index(event_index)
        self.log.info('Log Index after event triggered : %s'  % log_index)

        self.log.info('Make sure log is not returned .......') 
        if not self.init_log_index == log_index:
            raise Exception('Log is received in the polatisLogTable '
                'for the EventType : %s' % event_type)


    def get_log_index(self, event_index):
        """
        Procedure that gets the latest log index for the given
        event index.
        """

        oid = '.1.3.6.1.4.1.26592.2.6.2.2.1.1.1'
        try:
            result = netsnmp.snmpwalk(oid, Version=1, DestHost=AGENT_IP,
                Community='public')
        except Exception as err:
            raise Exception('Exception : %s thrown while doing snmpwalk on '
                'polatisLogTable' % err)


        #self.log.info('Result : %s' % result)
        

        cnt = 0
        for index in result:
            if index == event_index:
                cnt += 1

        else:
            pass
            #self.log.info('No more matched index found on polatisLogTable')
        
        #self.log.info('Count : %d' % cnt )
        return cnt
        





#####


def case_result(pass_flag, testCaseName):
    """ Procedures that handles, test case result details. """
        
        
    global PASS_CNT
    global FAIL_CNT
    global PASS_LST
    global FAIL_LST


    if pass_flag:
        #log.info('\n\n Test case Result : =====   Passed   ====')
        PASS_CNT += 1
        PASS_LST.append(testCaseName)

    else:
        #log.info('\n\n Test case Result : =====   Failed   ====')
        FAIL_CNT +=1
        FAIL_LST.append(testCaseName)


def result_summary():
    
    global PASS_CNT
    global FAIL_CNT
    global PASS_LST
    global FAIL_LST


    log.info('\n\n\n  *********  Result Summary  *********')
    log.info('\n Total number of cases Executed : %s' % (PASS_CNT + FAIL_CNT))
    
    
    #self.log.info('\n Number of cases Passed : %s' % PASS_CNT)
    #self.log.info('\n Number of cases Failed : %s' % FAIL_CNT)
    #self.log.info('\n Total Cases List : %s' % PASS_LST.extend(FAIL_LST))
    #self.log.info('\n Passed Cases List: %s' % PASS_LST)
    #self.log.info('\n Failed Cases List: %s' % FAIL_LST)

    log.info('\n Number of cases Passed : %s' % PASS_CNT)
    log.info('\n Passed Cases List: ')
    n=0
    for case in PASS_LST:
        log.info('    %d . %s' % (n+1, case))
        n+=1

    log.info('\n Number of cases Failed : %s' % FAIL_CNT)
    log.info('\n Failed Cases List: ')
    n=0
    for case in FAIL_LST:
        log.info('    %d . %s' % (n+1, case))
        n+=1
            
    #self.log.info('\n\n%d Number of cases are passed and %d number of cases are failed' % (PASS_CNT, FAIL_CNT))
