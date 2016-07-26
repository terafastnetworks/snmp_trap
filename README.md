+++++++++++++++
snmp automation
+++++++++++++++

Installation:
********************
Make sure to run "sudo apt-get update" before installing the packages.

1. Install python(Python 2.7.6 or above) 
2. Install python-nose(apt-get install python-nose)
3. Install git(apt-get install git)
4. Install python pysnmp(sudo apt-get install python-pysnmp-common)
5. Install snmp(sudo apt-get install snmp)
6. Install python-pexpect(sudo apt-get install python-pexpect)
8. Install snmpd(sudo apt-get install snmpd)

Commands to invoke automation:
***************************
1. Clone the testsuite from git - https://github.com/terafastnetworks/snmp_trap
2. mv /etc/snmp/snmpd.conf  /etc/snmp/snmpd.conf.org
3. Create a new /etc/snmp/snmpd.conf file:
       rocommunity public
       syslocation "sholinganallur chennai Tamilnadu"
       syscontact admin@domain.com
4. Make snmpd use the newly created file and make it listen to all interfaces:
   Edit /etc/default/snmpd
   
   Change from:

       # snmpd options (use syslog, close stdin/out/err).
       SNMPDOPTS='-Lsd -Lf /dev/null -u snmp -g snmp -I -smux,mteTrigger,mteTriggerConf -p /var/run/snmpd.pid'
  
       # snmptrapd control (yes means start daemon).  As of net-snmp version
       # 5.0, master agentx support must be enabled in snmpd before snmptrapd
       # can be run.  See snmpd.conf(5) for how to do this.
       TRAPDRUN=no

       #snmptrapd options (use syslog).
       TRAPDOPTS='-Lsd -p /var/run/snmptrapd.pid'

       To:
 
       # snmpd options (use syslog, close stdin/out/err).
       SNMPDOPTS='-Lsd -Lf /dev/null -u snmp -g snmp -I -smux -p /var/run/snmpd.pid'
  
       # snmptrapd control (yes means start daemon).  As of net-snmp version
       # 5.0, master agentx support must be enabled in snmpd before snmptrapd
       # can be run.  See snmpd.conf(5) for how to do this.
       TRAPDRUN=yes

       #snmptrapd options (use syslog).
       TRAPDOPTS='-C -c /etc/snmp/snmptrapd.conf -Lsd -p /var/run/snmptrapd.pid'

5. Make sure "authcommunity log public" this line is present in /etc/snmp/snmptrapd.conf
6. Restart snmpd service(sudo service snmpd restart)
7. Check snmptrapd is running (ps -aef | grep snmptrapd)
7. Go to the directory - ~/snmp_trap/testsuites
8. Modify the config.txt file(eg: ip, trap_rcvr_ip)
9. Use python nosetests to run automation testsuites

nosetests command:
********************
1. nosetests -s python_file.py
2. nosetests -s python_file.py:class_name 
3. nosetests -s python_file.py:class_name.function_name 




















