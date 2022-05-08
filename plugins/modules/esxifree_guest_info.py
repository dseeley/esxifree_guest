#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022, Dougal Seeley
# https://github.com/dseeley/esxifree_guest
# BSD 3-Clause License

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'], 'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: esxifree_guest_info
short_description: Retrieves virtual machine info in ESXi without a dependency on the vSphere/ vCenter API.
description: >
   This module can be used to retrieve virtual machine info. When fetching all VM info, does so atomically (a single SOAP call), to prevent race conditions.  Returns VMs in moid order (which is also chronological)
version_added: '2.9'
author:
- Dougal Seeley (ansible@dougalseeley.com)
requirements:
- python >= 2.7
- xmltodict
notes:
  - Tested on ESXi 7.0u2
options:
  hostname:
    description:
    - The hostname or IP address of the ESXi server.
    required: true
    type: str
  username:
    description:
    - The username to access the ESXi server at C(hostname).
    required: true
    type: str
  password:
    description:
    - The password of C(username) for the ESXi server, or the password for the private key (if required).
    required: true
    type: str
  filters:
    description:
    - A dictionary of filters.  Only 'hw_name' currently supported.
    required: false
    type: dict
  name:
    description:
    - Name of the virtual machine to retrieve (optional).
    - Virtual machine names in ESXi are unique
    - This parameter is case sensitive.
    type: str
  moid:
    description:
    - Managed Object ID of the virtual machine (optional).
    type: str
'''
EXAMPLES = r'''
- name: Get virtual machine for ALL VMs
  esxifree_guest_info:
    hostname: "192.168.1.3"
    username: "svc"
    password: "my_passsword"
  delegate_to: localhost

- name: Get virtual machine for all VMs that match the name "gold-ubuntu2004-*".
  esxifree_guest_info:
    hostname: "192.168.1.3"
    username: "svc"
    password: "my_passsword"
    filters: { hw_name: "gold-ubuntu2004-*" }
  delegate_to: localhost

- name: Get virtual machine for specific VM
  esxifree_guest_info:
    hostname: "192.168.1.3"
    username: "svc"
    password: "my_passsword"
    name: "my_vm"
  delegate_to: localhost
'''

RETURN = r'''
instance:
    description: metadata about the virtual machine
    returned: always
    type: dict
    sample: None
'''

import json
import re
import sys
import time

try:
    from lxml import etree
    LXML_IMPORT_ERR = None
    parser = etree.XMLParser(ns_clean=True)

except ImportError as lxml_import_exception:
    LXML_IMPORT_ERR = lxml_import_exception

# For the soap client
try:
    from urllib.request import Request, build_opener, HTTPSHandler, HTTPCookieProcessor
    from urllib.response import addinfourl
    from urllib.error import HTTPError
    from http.cookiejar import CookieJar
    from http.client import HTTPResponse
except ImportError:
    from urllib2 import Request, build_opener, HTTPError, HTTPSHandler, HTTPCookieProcessor, addinfourl
    from cookielib import CookieJar
    from httplib import HTTPResponse
import ssl

try:
    from ansible.module_utils.basic import missing_required_lib
except:
    def missing_required_lib(library, reason=None, url=None):
        msg = "Failed to import the required Python library (%s) on Python %s." % (library, sys.executable)
        if reason:
            msg += " This is required %s." % reason
        if url:
            msg += " See %s for more info." % url

        return msg

try:
    from ansible.module_utils.basic import AnsibleModule
except:
    # For testing without Ansible (e.g on Windows)
    class cDummyAnsibleModule():
        def __init__(self):
            self.params={}
        def exit_json(self, changed, **kwargs):
            print(changed, json.dumps(kwargs, sort_keys=True, indent=4, separators=(',', ': ')))
        def fail_json(self, msg, exception=None):
            print("Failed: " + msg + str(exception))
            exit(1)


# Executes soap requests on the remote host.
class vmw_soap_client(object):
    def __init__(self, host, username, password):
        self.vmware_soap_session_cookie = None
        self.host = host
        response_fp, cookies = self.send_req("<RetrieveServiceContent><_this>ServiceInstance</_this></RetrieveServiceContent>")
        response = response_fp.read()
        xml_etree = etree.fromstring(response.decode().replace('\n','').replace('xmlns="urn:vim25"', '').encode())

        sessionManager_name = str(xml_etree.xpath("/soapenv:Envelope/soapenv:Body/RetrieveServiceContentResponse/returnval/sessionManager/text()", namespaces=xml_etree.nsmap)[0])

        response_fp, cookies = self.send_req("<Login><_this>" + sessionManager_name + "</_this><userName>" + username + "</userName><password>" + password + "</password></Login>")
        self.vmware_soap_session_cookie = cookies['vmware_soap_session'].value

    def send_req(self, envelope_body=None):
        envelope = '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' + '<Body>' + str(envelope_body) + '</Body></Envelope>'
        cj = CookieJar()
        req = Request(
            url='https://' + self.host + '/sdk/vimService.wsdl', data=envelope.encode(),
            headers={"Content-Type": "text/xml", "SOAPAction": "urn:vim25/6.7.3", "Accept": "*/*", "Cookie": "vmware_client=VMware; vmware_soap_session=" + str(self.vmware_soap_session_cookie)})

        opener = build_opener(HTTPSHandler(context=ssl._create_unverified_context()), HTTPCookieProcessor(cj))
        num_send_attempts = 3
        for send_attempt in range(num_send_attempts):
            try:
                response = opener.open(req, timeout=30)
            except HTTPError as err:
                response = str(err)
            except:
                if send_attempt < num_send_attempts - 1:
                    time.sleep(1)
                    continue
                else:
                    raise
            break

        cookies = {i.name: i for i in list(cj)}
        return (response[0] if isinstance(response, list) else response, cookies)  # If the cookiejar contained anything, we get a list of two responses


class esxiFreeScraper(object):
    def __init__(self, hostname, username='root', password=None):
        self.soap_client = vmw_soap_client(host=hostname, username=username, password=password)

    def get_vm_info(self, name=None, moid=None, filters=None):
        if moid:
            response_fp, cookies = self.soap_client.send_req('<RetrievePropertiesEx><_this type="PropertyCollector">ha-property-collector</_this><specSet><propSet><type>VirtualMachine</type><all>true</all></propSet><objectSet><obj type="VirtualMachine">' + str(moid) + '</obj><skip>false</skip></objectSet></specSet><options/></RetrievePropertiesEx>')
            response = response_fp.read()
            xml_etree = etree.fromstring(response.decode().replace('\n','').replace('xmlns="urn:vim25"', '').encode())
            return (self.parse_vm(xml_etree.xpath("/soapenv:Envelope/soapenv:Body/RetrievePropertiesExResponse/returnval/objects", namespaces=xml_etree.nsmap)))
        elif name:
            virtual_machines = self.get_all_vm_info(filters)
            return ([vm for vm in virtual_machines if vm['hw_name'] == name][0])

    def get_all_vm_info(self, filters=None):
        response_fp, cookies = self.soap_client.send_req('<RetrievePropertiesEx><_this type="PropertyCollector">ha-property-collector</_this><specSet><propSet><type>VirtualMachine</type><all>false</all><pathSet>name</pathSet><pathSet>config</pathSet><pathSet>configStatus</pathSet><pathSet>datastore</pathSet><pathSet>guest</pathSet><pathSet>layout</pathSet><pathSet>layoutEx</pathSet><pathSet>runtime</pathSet></propSet><objectSet><obj type="Folder">ha-folder-vm</obj><selectSet xsi:type="TraversalSpec"><name>traverseChild</name><type>Folder</type><path>childEntity</path> <selectSet><name>traverseChild</name></selectSet><selectSet xsi:type="TraversalSpec"><type>Datacenter</type><path>vmFolder</path><selectSet><name>traverseChild</name></selectSet> </selectSet> </selectSet> </objectSet></specSet><options type="RetrieveOptions"></options></RetrievePropertiesEx>')
        response = response_fp.read()
        xml_etree = etree.fromstring(response.decode().replace('\n','').replace('xmlns="urn:vim25"', '').encode())

        virtual_machines = []
        for vm_instance in self.parse_vm(xml_etree.xpath("/soapenv:Envelope/soapenv:Body/RetrievePropertiesExResponse/returnval/objects", namespaces=xml_etree.nsmap)[0]):
            virtual_machines.append(self.parse_vm(vm_instance))

        # Sort the VMs in order of moid (which is also chronological)
        virtual_machines.sort(key=lambda vm: int(vm['moid']))

        if filters and 'hw_name' in filters:
            return ([vm for vm in virtual_machines if re.search(filters['hw_name'], vm['hw_name'])])
        else:
            return (virtual_machines)

    # Return the parameter of an object but only if present, else return None.
    def _getObjSafe(self, inDict, *keys):
        for key in keys:
            try: inDict = inDict[key]
            except KeyError: return None
        return inDict

    def parse_vm(self, vmObj):
        configObj = vmObj.xpath("/objects/propSet[name='config']/val", namespaces=vmObj.nsmap)
        runtimeObj = [propSetObj for propSetObj in vmObj['propSet'] if propSetObj['name'] == 'runtime'][0]['val']
        guestObj = [propSetObj for propSetObj in vmObj['propSet'] if propSetObj['name'] == 'guest'][0]['val']
        layoutExObj = [propSetObj for propSetObj in vmObj['propSet'] if propSetObj['name'] == 'layoutEx'][0]['val']
        newObj = {}

        newObj.update({"advanced_settings": {advObj['key']: advObj['value'].get('#text') for advObj in configObj['extraConfig']}})
        newObj.update({"annotation": configObj['annotation']})
        newObj.update({"consolidationNeeded": runtimeObj['consolidationNeeded']})
        newObj.update({"guest_tools_status": guestObj['toolsRunningStatus'] if 'toolsRunningStatus' in guestObj else None})
        newObj.update({"guest_tools_version": guestObj['toolsVersion'] if 'toolsVersion' in guestObj else None})
        newObj.update({"hw_cores_per_socket": configObj['hardware']['numCoresPerSocket']})
        newObj.update({"hw_datastores": [configObj['datastoreUrl']['name']]})
        newObj.update({"hw_files": [file.get('name') for file in layoutExObj['file'] if file.get('type') in ['config', 'nvram', 'diskDescriptor', 'snapshotList', 'log']]})
        newObj.update({"hw_guest_full_name": guestObj['guestFullName'] if 'guestFullName' in guestObj else None})
        newObj.update({"hw_guest_id": guestObj['guestId'] if 'guestId' in guestObj else None})
        newObj.update({"hw_is_template": configObj['template']})
        newObj.update({"hw_memtotal_mb": int(configObj['hardware']['memoryMB'])})
        newObj.update({"hw_name": [propSetObj for propSetObj in vmObj['propSet'] if propSetObj['name'] == 'name'][0]['val'].get('#text')})
        newObj.update({"hw_power_status": runtimeObj['powerState']})
        newObj.update({"hw_processor_count": int(configObj['hardware']['numCPU'])})
        newObj.update({"hw_product_uuid": configObj['uuid']})
        newObj.update({"hw_version": configObj['version']})
        newObj.update({"ipv4": guestObj['ipAddress'] if 'ipAddress' in guestObj else None})
        newObj.update({"moid": vmObj['obj'].get('#text')})

        guest_disk_info = []
        for virtualDiskObj in [diskObj for diskObj in configObj['hardware']['device'] if diskObj['@xsi:type'] == 'VirtualDisk']:
            guest_disk_info.append({
                "backing_datastore": re.sub(r'^\[(.*?)\].*$', r'\1', virtualDiskObj['backing']['fileName']),
                "backing_disk_mode": virtualDiskObj['backing']['diskMode'],
                "backing_diskmode": virtualDiskObj['backing']['diskMode'],
                "backing_eagerlyscrub": self._getObjSafe(virtualDiskObj, 'backing', 'eagerlyScrub'),
                "backing_filename": virtualDiskObj['backing']['fileName'],
                "backing_thinprovisioned": self._getObjSafe(virtualDiskObj, 'backing', 'thinProvisioned'),
                "backing_type": re.sub(r'^VirtualDisk(.*?)BackingInfo$', r'\1', virtualDiskObj['backing']['@xsi:type']),
                "backing_uuid": self._getObjSafe(virtualDiskObj, 'backing', 'uuid'),
                "backing_writethrough": self._getObjSafe(virtualDiskObj, 'backing', 'writeThrough'),
                "capacity_in_bytes": int(virtualDiskObj['capacityInBytes']),
                "capacity_in_kb": int(virtualDiskObj['capacityInKB']),
                "controller_key": virtualDiskObj['controllerKey'],
                "controller_bus_number": [deviceObj['busNumber'] for deviceObj in configObj['hardware']['device'] if deviceObj['key'] == virtualDiskObj['controllerKey']][0],
                "controller_type": [deviceObj['@xsi:type'] for deviceObj in configObj['hardware']['device'] if deviceObj['key'] == virtualDiskObj['controllerKey']][0],
                "key": virtualDiskObj['key'],
                "label": virtualDiskObj['deviceInfo']['label'],
                "summary": virtualDiskObj['deviceInfo']['summary'],
                "unit_number": int(virtualDiskObj['unitNumber'])
            })
        newObj.update({"guest_disk_info": guest_disk_info})

        return newObj


def main():
    argument_spec = {
        "hostname": {"type": "str", "required": True},
        "username": {"type": "str", "required": True},
        "password": {"type": "str", "required": True},
        "filters": {"type": "dict", "required": False},
        "name": {"type": "str"},
        "moid": {"type": "str"}
    }

    if not (len(sys.argv) > 1 and sys.argv[1] == "console"):
        module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    else:
        # For testing without Ansible (e.g on Windows)
        module = cDummyAnsibleModule()
        ## Update VM
        module.params = {
            "hostname": "192.168.1.30",
            "username": "root",
            "password": sys.argv[2],
            "filters": {"hw_name": "gold-ubunutu2204-*"},
            "name": None,  # "parsnip-prod-sys-a0-1616868999",
            "moid": None  # 350
        }

    if LXML_IMPORT_ERR:
        module.fail_json(msg=missing_required_lib("lxml"), exception=LXML_IMPORT_ERR)

    iScraper = esxiFreeScraper(hostname=module.params['hostname'], username=module.params['username'], password=module.params['password'])

    if ("moid" in module.params and module.params['name']) or ("name" in module.params and module.params['moid']):
        vm_info = iScraper.get_vm_info(name=module.params['name'], moid=module.params['moid'], filters=module.params['filters'])
    else:
        vm_info = iScraper.get_all_vm_info(filters=module.params['filters'])

    module.exit_json(changed=False, virtual_machines=vm_info)


if __name__ == '__main__':
    main()
