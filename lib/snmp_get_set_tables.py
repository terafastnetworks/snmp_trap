""" Python File that handles the SNMP (SET, GET, GETNEXT, WALK and GETBULK) 
Operations on:

- polatisOxcPortTable
- polatisVoaConfigTable
- polatisOpmConfigTable
- polatisOpmAlarmConfigTable
- polatisOpmPowerTable
- polatisApsPortTable
- polatisApsProtGroupTable
- polatisApsTriggerTable

"""

from snmp import Snmp

class SnmpBaseClass:

    def __init__(self, devIpAddr, version=2, community='public'):
        self.snmp_sess = Snmp(devIpAddr, version=version, community=community)
    
    def get_oxc_size(self):
        """ Performs SNMP Get on 'polatisOxcSize' MIB Object and returns the
            Size Value.
        """
        oid = '.1.3.6.1.4.1.26592.2.2.2.1.1.0'
        return self.snmp_sess.snmp_get(oid)

    def get_snmp_value(self, oid, snmp_action, oid_index):
        size = self.get_oxc_size()
        size = size['enterprises.26592.2.2.2.1.1.0.'].split('x')[0]
        myList = []
        #print "OID:%s --- Action:%s --- Index:%s" % (oid, snmp_action, oid_index)

        if snmp_action is None:
            # Perform SNMP Get on the Specified Object.
            if oid_index is None:
                for i in range(1, int(size)*2+1):
                    new_oid = oid+"."+str(i)
                    myList.append(self.snmp_sess.snmp_get(new_oid))
                return myList
            else:
                oid = oid+"."+oid_index
                return self.snmp_sess.snmp_get(oid) 
        elif snmp_action == 'walk':
            return self.snmp_sess.snmp_walk(oid)
        elif snmp_action == 'getbulk':
            return self.snmp_get_bulk(oid)
        else:
            if oid_index is None:
                for i in range(1, int(size)*2+1):
                    new_oid = oid+"."+str(i)
                    myList.append(self.snmp_sess.do_snmp_operations(new_oid,
                            snmp_action))
                return myList
            else:
                 oid = oid+"."+oid_index
                 return self.snmp_sess.do_snmp_operations(oid, snmp_action)


class OxcPortTable(SnmpBaseClass):

    oxcPortTable = {
        'polatisOxcPortPatch': '.1.3.6.1.4.1.26592.2.2.2.1.2.1.2', #UNSIGNED32
        'polatisOxcPortCurrentState': '.1.3.6.1.4.1.26592.2.2.2.1.2.1.3', #INTEGER - enabled(1), disabled(2), failed(3)
        'polatisOxcPortDesiredState': '.1.3.6.1.4.1.26592.2.2.2.1.2.1.4' #INTEGER - enable(1), disable(2)
    }

    def set_oxc(self, oid_name, oid_index, value_to_set, datatype):
        """ Performs SNMP Set Operation on the specified Table Type . """
        oid = self.oxcPortTable[oid_name].lstrip('.1.3.6.1.4.1.')+"."+oid_index
        self.snmp_sess.snmp_set(oid, value_to_set, datatype)

    def get_oxc(self, oid_name, snmp_action=None, oid_index=None):
        """ Performs the SNMP Retrieve Operation on the OID specified.
            Arguments:
                oid_name : OID to Perform SNMP Retrieve Operation.
                snmp_action: What type of SNMP Operation to be carried out. If
                             "None" SNMP Get will be Performed.
                oid_index: Particular Index value to Fetch. If None It will
                            fetch the output for all the available indexes.
        """

        oid = self.oxcPortTable[oid_name]
        return self.get_snmp_value(oid, snmp_action, oid_index)

class VoaConfigTable(SnmpBaseClass):

    voaConfigTbl = {
        'polatisVoaLevel': '.1.3.6.1.4.1.26592.2.4.2.1.1.1.1', # INTEGER
        'polatisVoaRefport': '.1.3.6.1.4.1.26592.2.4.2.1.1.1.2', #UNSIGNED32
        'polatisVoaCurrentState': '.1.3.6.1.4.1.26592.2.4.2.1.1.1.3', #INTEGER - disabled (1), absolute (2), relative (3), maximum (5), fixed (6), pending (7)
        'polatisVoaDesiredState': '.1.3.6.1.4.1.26592.2.4.2.1.1.1.4' #INTEGER - disabled (1), absolute (2), relative (3), maximum (5), fixed (6), pending (7)
    }

    def set_voa(self, oid_name, oid_index, value_to_set, datatype):
        oid = self.voaConfigTbl[oid_name].lstrip('.1.3.6.1.4.1.')+"."+oid_index
        self.snmp_sess.snmp_set(oid, value_to_set, datatype)

    def get_voa(self, oid_name, snmp_action=None, oid_index=None):
        oid = self.voaConfigTbl[oid_name]
        return self.get_snmp_value(oid, snmp_action, oid_index)


class OpmConfigTable(SnmpBaseClass):
    
    opmConfigTable = {
        'polatisOpmWaveLength': '.1.3.6.1.4.1.26592.2.3.2.1.1.1.1', # UNSIGNED32
        'polatisOpmOffset': '.1.3.6.1.4.1.26592.2.3.2.1.1.1.2', # INTEGER
        'polatisOpmAtime':  '.1.3.6.1.4.1.26592.2.3.2.1.1.1.3', # UNSIGNED32
        'polatisOpmType':   '.1.3.6.1.4.1.26592.2.3.2.1.1.1.4'  # INTEGER - i/p(1), o/p(2)
    }

    def set_opm(self, oid_name, oid_index, value_to_set, datatype):
        oid = self.opmConfigTable[oid_name].lstrip('.1.3.6.1.4.1.')+"."+oid_index
        self.snmp_sess.snmp_set(oid, value_to_set, datatype)

    def get_opm(self, oid_name, snmp_action=None, oid_index=None):
        oid = self.opmConfigTable[oid_name]
        return self.get_snmp_value(oid, snmp_action, oid_index)

class OpmAlarmConfigTable(SnmpBaseClass):

    """ This Class covers both 'polatisOpmAlarmConfigTable' and
    'polatisOpmPowerTable'.
    """

    opmAlarmConfigTable = {
        'polatisOpmAlarmEdge': '.1.3.6.1.4.1.26592.2.3.2.1.2.1.1',   # INTEGER - low(1), high(2), both(3)
        'polatisOpmAlarmLowThresh': '.1.3.6.1.4.1.26592.2.3.2.1.2.1.2', # INTEGER
        'polatisOpmAlarmHighThresh': '.1.3.6.1.4.1.26592.2.3.2.1.2.1.3', # INTEGER
        'polatisOpmAlarmMode': '.1.3.6.1.4.1.26592.2.3.2.1.2.1.4', # INTEGER - off(1), single(2), continuous(3)
        'polatisOpmPower': '.1.3.6.1.4.1.26592.2.3.2.2.2.1.1'
    }

    def set_opm_alarm(self, oid_name, oid_index, value_to_set, datatype):
        oid = self.opmAlarmConfigTable[oid_name].lstrip('.1.3.6.1.4.1.')+"."+oid_index
        self.snmp_sess.snmp_set(oid, value_to_set, datatype)

    def get_opm_alarm(self, oid_name, snmp_action=None, oid_index=None):
        oid = self.opmAlarmConfigTable[oid_name]
        return self.get_snmp_value(oid, snmp_action, oid_index)

class ApsPortTable(SnmpBaseClass):

    apsPortTable = {
        'polatisApsPortCurrentState': '.1.3.6.1.4.1.26592.2.5.2.1.1.1.1', # INTEGER - is(1), oosma(2), oosau(3)
        'polatisApsPortDesiredState': '.1.3.6.1.4.1.26592.2.5.2.1.1.1.2', # INTEGER - is(1), oos(2)
        'polatisApsPortCurrentCond': '.1.3.6.1.4.1.26592.2.5.2.1.1.1.3', # INTEGER - none(1), inhswpr(2), inhswwkg(3)
        'polatisApsPortDesiredCond': '.1.3.6.1.4.1.26592.2.5.2.1.1.1.4' # INTEGER - none(1), inhswpr(2), inhswwkg(3)
    }

    def set_aps(self, oid_name, oid_index, value_to_set, datatype):
        oid = self.apsPortTable[oid_name].lstrip('.1.3.6.1.4.1.')+"."+oid_index
        self.snmp_sess.snmp_set(oid, value_to_set, datatype)

    def get_aps(self, oid_name, snmp_action=None, oid_index=None):
        oid = self.apsPortTable[oid_name]
        return self.get_snmp_value(oid, snmp_action, oid_index)

class ApsProtGroupTable(SnmpBaseClass):
    apsProtGrpTbl = {
        'polatisApsProtGroupPort': '.1.3.6.1.4.1.26592.2.5.2.1.2.1.1', #UNSIGNED32
        'polatisApsProtGroupPriority': '.1.3.6.1.4.1.26592.2.5.2.1.2.1.2', # UNSIGNED
        'polatisApsProtGroupStatus': '.1.3.6.1.4.1.26592.2.5.2.1.2.1.3' # INTEGER - active(1), notInService(2), notReady(3), createAndGo(4), createAndWait(5), destroy(6)
    }

    def create_del_protection_grp(self, oid_name, wrkg_prt, prctng_prt, value_to_set):
        oid = \
            self.apsProtGrpTbl[oid_name].lstrip('.1.3.6.1.4.1.')+"."+wrkg_prt+"."+prctng_prt
        self.snmp_sess.snmp_set(oid, value_to_set, 'INTEGER')

    def get_protection_grp(self, oid_name, snmp_action='walk', oid_index=None):
        oid = self.apsProtGrpTbl[oid_name]
        return self.get_snmp_value(oid, snmp_action, oid_index)

class ApsTriggerTable(SnmpBaseClass):

    apsTrigTbl = {
        'polatisApsTriggerPort': '.1.3.6.1.4.1.26592.2.5.2.1.3.1.1', # UNSIGNED32
        'polatisApsTriggerStatus': '.1.3.6.1.4.1.26592.2.5.2.1.3.1.2' # INTEGER - active(1), notInService(2), notReady(3), createAndGo(4), createAndWait(5), destroy(6)
    }

    def create_del_trigger_prt(self, oid_name, wrkg_prt, trig_prt, value_to_set):
        oid = \
            self.apsTrigTbl[oid_name].lstrip('.1.3.6.1.4.1.')+"."+wrkg_prt+"."+trig_prt
        self.snmp_sess.snmp_set(oid, value_to_set, 'INTEGER')

    def get_trigger_prt(self, oid_name, snmp_action='walk', oid_index=None):
        oid = self.apsTrigTbl[oid_name]
        return self.get_snmp_value(oid, snmp_action, oid_index)

class EventTable(SnmpBaseClass):

    eventTbl = {
        'polatisEventIndex': '.1.3.6.1.4.1.26592.2.6.2.1.1.1.1', # INTEGER
        'polatisEventDescription': '.1.3.6.1.4.1.26592.2.6.2.1.1.1.2', # DISPLAYSTRING.
        'polatisEventType': '.1.3.6.1.4.1.26592.2.6.2.1.1.1.3', # INTEGER - none(1), log(2), snmp-trap(3), log-and-trap(4)
        'polatisEventCommunity': '.1.3.6.1.4.1.26592.2.6.2.1.1.1.4', # OCTET STRING
        'polatisEventLastTimeSent': '.1.3.6.1.4.1.26592.2.6.2.1.1.1.5' # TIMETICKS
    }

    def set_event(self, oid_name, evnt_idx, value_to_set, datatype):
        oid = self.eventTbl[oid_name].lstrip('.1.3.6.1.4.1.')+"."+evnt_idx
        return self.snmp_sess.snmp_set(oid, value_to_set, datatype)

    def get_event(self, oid_name, snmp_action=None, oid_index=None):
        return self.get_snmp_value(self.eventTbl[oid_name], snmp_action,
            oid_index)

class EventLogTable(SnmpBaseClass):

    eventLogTbl = {
        'polatisEventIndex': '.1.3.6.1.4.1.26592.2.6.2.2.1.1.1', # INTEGER
        'polatisLogIndex': '.1.3.6.1.4.1.26592.2.6.2.2.1.1.2',   # INTEGER32
        'polatisLogTime': '.1.3.6.1.4.1.26592.2.6.2.2.1.1.3',    # TIMETICKS
        'polatisLogDescription': '.1.3.6.1.4.1.26592.2.6.2.2.1.1.4' # DISPLAYSTRING
    }

    def get_log(self, oid_name, snmp_action=None, oid_index=None):
        return self.get_snmp_value(self.eventLogTbl[oid_name], snmp_action,
            oid_index)

