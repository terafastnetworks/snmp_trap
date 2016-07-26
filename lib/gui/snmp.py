import time
from gui.node import Node
from selenium.webdriver.common.action_chains import ActionChains

def config_snmp(box_ip, snmp_dest_ip, notify_type='trap',
    community ='public', snmp_version='v1'):

    # login into the box
    node = Node(box_ip)
    sel = node.gui_login()
    time.sleep(10)

    sel.find_element_by_xpath("//a[contains(text(),'SNMP')]").click()
    time.sleep(10)
    sel.find_element_by_css_selector('[id=tab_snmpnotif]').click()

    sel.find_element_by_css_selector('[id=simplenotiftype]').send_keys(notify_type)
    sel.find_element_by_css_selector("#simpletablecanvas tr:nth-child(2) td:nth-child(4) [title='Edit Row']").click()
    time.sleep(2)
    element = sel.find_element_by_css_selector('[id=trapdest]')
    element.clear()
    element.send_keys(snmp_dest_ip)
    element = sel.find_element_by_css_selector('[id=trapcommunity]')
    element.clear()
    element.send_keys(community)
    sel.find_element_by_css_selector('[id=trapversion]').send_keys(snmp_version)

    sel.find_element_by_css_selector('[id=modalOKbutton]').click()
    time.sleep(2)

    # 'Configure' to save the configurations.
    sel.find_element_by_css_selector('[id=simpleconfirmbutton]').click()
    time.sleep(15)
    node.gui_logout()



def config_snmp_for_specific_event(box_ip, snmp_dest_ip, event, notify_type='trap',
    community ='public', snmp_version='v1'):
    

    # login into the box
    node = Node(box_ip)
    sel = node.gui_login()
    time.sleep(10)

    # Go to 'SNMP Config' -> 'Full Configuration'
    sel.find_element_by_xpath("//a[contains(text(),'SNMP')]").click()
    time.sleep(10)
    sel.find_element_by_css_selector('[id=tab_snmpnotif]').click()
    sel.find_element_by_css_selector('[id=tab_snmptrapfull]').click()


    ActionChains(sel).double_click(sel.find_element_by_xpath \
        ("//td[contains(text(), '%s')]" % event)).perform()
    time.sleep(5)

    sel.find_element_by_css_selector('[id=notiftype]').send_keys(notify_type)
        
    sel.find_element_by_css_selector("#tablecanvas tr:nth-child(2) td:nth-child(4) [title='Edit Row']").click()
    time.sleep(2)
    element = sel.find_element_by_css_selector('[id=trapdest]')
    element.clear()
    element.send_keys(snmp_dest_ip)
    element = sel.find_element_by_css_selector('[id=trapcommunity]')
    element.clear()
    element.send_keys('public')
    sel.find_element_by_css_selector('[id=trapversion]').send_keys(snmp_version)

    sel.find_element_by_css_selector('[id=modalOKbutton]').click()
    time.sleep(2)

    # 'Configure' to save the configurations.
    sel.find_element_by_css_selector('[id=modalConfigurebutton]').click()
    time.sleep(5)

    node.gui_logout()



def restart_snmp_agent(box_ip):


    # login into the box
    node = Node(box_ip)
    sel = node.gui_login()
    time.sleep(10)


    # Go to 'SNMP Config' -> 'Full Configuration'
    sel.find_element_by_xpath("//a[contains(text(),'SNMP')]").click()
    time.sleep(10)
    sel.find_element_by_css_selector('[id=tab_snmpnotif]').click()
    sel.find_element_by_css_selector('[id=tab_snmptrapfull]').click()

    sel.find_element_by_xpath("//button[contains(text(), 'Restart')]").click()
    time.sleep(1)
    node.gui_logout()


