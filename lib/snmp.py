""" SNMP Script that performs SNMP Get, SNMP GetNext, SNMP Walk, SNMP GetBulk
and SNMP Set Operations. Currently supports SNMPv1 and SNMPv2. 

"""

import netsnmp


class Snmp():
    def __init__(self, devIpAddr, version=2, community='public'):
        """ Arguments 
            devIpAddr : IpAddress of the box to query.
            community : SNMP Community String.
            versoin   : SNMP Version.
        """

        self.snmp_session = netsnmp.Session(DestHost=devIpAddr, Version=version,
            Community=community)

    def snmp_walk(self, oid_to_get):
        """ Performs SNMP Walk on the OID Specified. """

        oid = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
        self.snmp_session.walk(oid)
        results = {}
        for result in oid:
            results[('%s.%s') % (result.tag, result.iid)] = result.val
        return results

    def snmp_get(self, oid_to_get):
        """ Performs SNMP Get on the OID Specified. """

        oid = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
        self.snmp_session.get(oid)
        results = {}
        for result in oid:
            results[('%s.%s') % (result.tag, result.iid)] = result.val
        return results

    def snmp_get_next(self, oid_to_get):
        """ Performs SNMP Get Next on the OID Specified. """

        oid = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
        self.snmp_session.getnext(oid)
        results = {}
        for result in oid:
            results[('%s.%s') % (result.tag, result.iid)] = result.val
        return results

    def snmp_get_bulk(self, oid_to_get):
        """ Performs SNMP Get Bulk Operation."""

        oid = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
        out = self.snmp_session.getbulk(0, 100, oid)
        results = {}
        for result in oid:
            results[('%s.%s') % (result.tag, result.iid)] = result.val
        return results

    def snmp_set(self, oid_to_set, value_to_set, datatype):
        """ Performs SNMP Set Opertion on the OID specified.
        """

        oid = netsnmp.VarList(netsnmp.Varbind("enterprises",
                oid_to_set, value_to_set, datatype))
        return self.snmp_session.set(oid)

    def do_snmp_operations(self, oid_to_get, action):
        """ Performs SNMP Get, SNMP Walk and SNMP GetNext Operations on the OID
            Specified.
            Arguments:
                oid_to_get : OID to perform 'get', 'walk' and 'getnext' SNMP
                                Operations.
                action     : Action to be carried out. Valid actions are get,
                                walk and getnext.
        """

        oid = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
        snmp_action = {
            'get':      self.snmp_session.get,
            'walk':     self.snmp_session.walk,
            'getnext':  self.snmp_session.getnext
        }
        snmp_action[action](oid)
        results = {}
        for result in oid:
            results[('%s.%s') % (result.tag, result.iid)] = result.val
        return results

