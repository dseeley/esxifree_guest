#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'], 'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: esxifree_guest
short_description: Manages virtual machines in ESXi (free), i.e. without vCenter.
description: >
   This module can be used to create new virtual machines from templates or other virtual machines,
   manage power state of virtual machine such as power on, power off, suspend, shutdown, reboot, restart etc.,
version_added: '2.7'
author:
- Dougal Seeley (ansible@dougalseeley.com)
requirements:
- python >= 2.7
notes:
    - Please make sure the user used for esxifree_guest should have correct level of privileges.
options:
  state:
    description:
    - Specify state of the virtual machine be in.
    - 'If C(state) is set to C(present) and virtual machine exists, ensure the virtual machine
       configurations conforms to task arguments.'
    - 'If C(state) is set to C(absent) and virtual machine exists, then the specified virtual machine
      is removed with its associated components.'
    default: present
    choices: [ present, absent ]
  name:
    description:
    - Name of the virtual machine to work with.
    - This parameter is required, if C(state) is set to C(poweredon), C(poweredoff), C(present), C(restarted), C(suspended)
      and virtual machine does not exists.
    - This parameter is case sensitive.
    required: yes
  vmid:
    description:
    - vmid of the virtual machine to manage if known, this is VMware's unique identifier.
    - This is required if C(name) is not supplied.
    - If virtual machine does not exists, then this parameter is ignored.
    - Will be ignored on virtual machine creation
  template:
    description:
    - Template or existing virtual machine used to create new virtual machine.
    - If this value is not set, virtual machine is created without using a template.
    - If the virtual machine already exists, this parameter will be ignored.
    - This parameter is case sensitive.
  datastore:
    description:
    - Destination datastore, absolute path to create the new guest.
    - This parameter is case sensitive.
    - This parameter is required, while deploying new virtual machine.
    - 'Examples:'
    - '   datastore: /vmfs/volumes/sata-raid10-4tb-01/'
    - '   datastore: /vmfs/volumes/datastore1/'
  hardware:
    description:
    - Manage virtual machine's hardware attributes.
    - All parameters case sensitive.
    - 'Valid attributes are:'
    - ' - C(memory_mb) (integer): Amount of memory in MB.'
    - ' - C(num_cpus) (integer): Number of CPUs.'
    - ' - C(version) (integer): The Virtual machine hardware versions. Default is 14 (ESXi 6.7 and onwards).
  guest_id:
    description:
    - Set the guest ID.
    - This parameter is case sensitive.
    - 'Examples:'
    - "  virtual machine with RHEL7 64 bit, will be 'rhel7-64'"
    - "  virtual machine with CentOS 7 (64-bit), will be 'centos7-64'"
    - "  virtual machine with Debian 9 (Stretch) 64 bit, will be 'debian9-64'"
    - "  virtual machine with Ubuntu 64 bit, will be 'ubuntu-64'"
    - "  virtual machine with Windows 10 (64 bit), will be 'windows9-64'"
    - "  virtual machine with Other (64 bit), will be 'other-64'"
    - This field is required when creating a virtual machine.
  disk:
    description:
    - A list of disks to add.
    - This parameter is case sensitive.
    - Resizing disks is not supported.
    - Removing existing disks of the virtual machine is not supported.
    - 'Valid attributes are:'
    - ' - C(size_gb) (integer): Disk storage size in GB'
    - ' - C(type) (string): Valid values are:'
    - '     - C(thin) thin disk'
    - '     - C(eagerzeroedthick) eagerzeroedthick disk, added in version 2.5'
    - '     Default: C(None) thick disk, no eagerzero.'
  cdrom:
    description:
    - A CD-ROM configuration for the virtual machine.
    - 'Valid attributes are:'
    - ' - C(type) (string): The type of CD-ROM, valid options are C(none), C(client) or C(iso). With C(none) the CD-ROM will be disconnected but present.'
    - ' - C(iso_path) (string): The datastore path to the ISO file to use, in the form of C([datastore1] path/to/file.iso). Required if type is set C(iso).'
  hostname:
    description:
    - The hostname or IP address of the ESXi server.
  username:
    description:
    - The username to access the ESXi server.
  password:
    description:
    - The password of username for the ESXi server, or the password for the private key (if required).
  pkeyfile:
    description:
    - The private key file for the user of the ESXi server.
  pkeystr:
    description:
    - The private key (as a string) for the user of the ESXi server.
  force:
    description:
    - Delete the existing host if it exists.
  networks:
    description:
    - A list of networks (in the order of the NICs).
    - Removing NICs is not allowed, while reconfiguring the virtual machine.
    - All parameters and VMware object names are case sensetive.
    - 'One of the below parameters is required per entry:'
    - ' - C(networkName) (string): Name of the portgroup for this interface.
    - ' - C(virtualDev) (string): Virtual network device (one of C(e1000e), C(vmxnet3) (default), C(sriov)).'
  customvalues:
    description:
    - Define a list of custom values to set on virtual machine.
    - A custom value object takes two fields C(key) and C(value).
    - Incorrect key and values will be ignored.
    version_added: '2.3'
  wait:
    description:
    - Wait for the instance to reach its desired state before returning.
  wait_timeout:
    description:
    - How long before wait gives up, in seconds.
extends_documentation_fragment: vmware.documentation
'''
EXAMPLES = r'''
- name: Create a blank virtual machine
  esxifree_guest:
    hostname: "{{ esxi_ip }}"
    username: "{{ esxi_username }}"
    pkeyfile: "{{ esxi_pkey_file }}"
    datastore: "/vmfs/volumes/sata-raid10-4tb-01/"
    name: test_vm_0001
    state: poweredon
    guest_id: ubuntu-64
    cdrom:
      type: iso
      iso_path: "/vmfs/volumes/sata-raid10-4tb-01/ISOs/ubuntu-18.04.1.0-live-server-amd64.iso"
    disk:
    - size_gb: 16
      type: thin
    networks:
    - networkName: VM Network
      virtualDev: vmxnet3
    hardware:
      memory_mb: 2048
      num_cpus: 2
      version: 14
  delegate_to: localhost

- name: Clone a virtual machine
  esxifree_guest:
    hostname: "{{ esxi_ip }}"
    username: "{{ esxi_username }}"
    pkeystr: "{{ esxi_pkey_nopw }}"
    datastore: "/vmfs/volumes/sata-raid10-4tb-01/"
    name: test_vm_0001
    state: poweredon
    template: "centos7-template"
  delegate_to: localhost

- name: Delete a virtual machine
  esxifree_guest:
    hostname: "{{ esxi_ip }}"
    username: "{{ esxi_username }}"
    password: "{{ esxi_password }}"
    name: test_vm_0001
    state: absent
  delegate_to: localhost
'''

RETURN = r'''
instance:
    description: metadata about the new virtual machine
    returned: always
    type: dict
    sample: None
'''

import time
import re
import json
import socket
import collections
import paramiko
import sys
import os
import io

# paramiko.util.log_to_file("paramiko.log")

try:
    from ansible.module_utils.basic import AnsibleModule
except:
    pass


# Executes a command on the remote host.
class SSHCmdExec(object):
    def __init__(self, hostname, username=None, password=None, pkeyfile=None, pkeystr=None):
        self.hostname = hostname

        try:
            if pkeystr:
                pkey_fromstr = paramiko.RSAKey.from_private_key(io.StringIO(pkeystr), password)
            if pkeyfile:
                pkey_fromfile = paramiko.RSAKey.from_private_key_file(pkeyfile, password)
        except paramiko.ssh_exception.PasswordRequiredException as auth_err:
            print("Authentication failure, Password required" + "\n\n" + str(auth_err))
            exit(1)
        except paramiko.ssh_exception.SSHException as auth_err:
            print("Authentication failure, SSHException" + "\n\n" + str(auth_err))
            exit(1)
        except:
            print("Unexpected error: ", sys.exc_info()[0])
            raise
        else:
            if pkeystr:
                self.pkey = pkey_fromstr
                if pkeyfile:
                    if pkey_fromstr != pkey_fromfile:
                        print("Both private key file and private key string specified and not equal!")
                        exit(1)
            elif pkeyfile:
                self.pkey = pkey_fromfile

        # Create instance of SSHClient object
        self.remote_conn_client = paramiko.SSHClient()
        self.remote_conn_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # initiate SSH connection
        try:
            if self.pkey:
                self.remote_conn_client.connect(hostname=hostname, username=username, pkey=self.pkey, timeout=10, look_for_keys=False, allow_agent=False)
            else:
                self.remote_conn_client.connect(hostname=hostname, username=username, password=password, timeout=10, look_for_keys=False, allow_agent=False)
        except socket.error as sock_err:
            print("Connection timed-out to " + hostname)  # + "\n\n" + str(sock_err)
            exit(1)
        except paramiko.ssh_exception.AuthenticationException as auth_err:
            print("Authentication failure, unable to connect to " + hostname + " as " + username)  # + "\n\n" + str(auth_err)
            exit(1)
        except:
            print("Unexpected error: ", sys.exc_info()[0])
            raise

        # print("SSH connection established to " + hostname + " as " + username)

    def get_sftpClient(self):
        return self.remote_conn_client.open_sftp()

    # execute the command and wait for it to finish
    def exec_command(self, command_string):
        # print("Command is: {0}".format(command_string))

        (stdin, stdout, stderr) = self.remote_conn_client.exec_command(command_string)
        if stdout.channel.recv_exit_status() != 0: # Blocking call
            raise IOError(stderr.read())

        return stdin, stdout, stderr


class esxiFreeScraper(object):
    vmx_skeleton = collections.OrderedDict()
    vmx_skeleton['.encoding'] = "UTF-8"
    vmx_skeleton['config.version'] = "8"
    vmx_skeleton['pciBridge0.present'] = "TRUE"
    vmx_skeleton['svga.present'] = "TRUE"
    vmx_skeleton['svga.autodetect'] = "TRUE"
    vmx_skeleton['pciBridge4.present'] = "TRUE"
    vmx_skeleton['pciBridge4.virtualDev'] = "pcieRootPort"
    vmx_skeleton['pciBridge4.functions'] = "8"
    vmx_skeleton['pciBridge5.present'] = "TRUE"
    vmx_skeleton['pciBridge5.virtualDev'] = "pcieRootPort"
    vmx_skeleton['pciBridge5.functions'] = "8"
    vmx_skeleton['pciBridge6.present'] = "TRUE"
    vmx_skeleton['pciBridge6.virtualDev'] = "pcieRootPort"
    vmx_skeleton['pciBridge6.functions'] = "8"
    vmx_skeleton['pciBridge7.present'] = "TRUE"
    vmx_skeleton['pciBridge7.virtualDev'] = "pcieRootPort"
    vmx_skeleton['pciBridge7.functions'] = "8"
    vmx_skeleton['vmci0.present'] = "TRUE"
    vmx_skeleton['hpet0.present'] = "TRUE"
    vmx_skeleton['floppy0.present'] = "FALSE"
    vmx_skeleton['usb.present'] = "TRUE"
    vmx_skeleton['ehci.present'] = "TRUE"
    vmx_skeleton['tools.syncTime'] = "TRUE"
    vmx_skeleton['scsi0.virtualDev'] = "pvscsi"
    vmx_skeleton['scsi0.present'] = "TRUE"

    def __init__(self, hostname, username='root', password=None, pkeyfile=None, pkeystr=None, vmName=None, vmId=None):
        self.esxiCnx = SSHCmdExec(hostname=hostname, username=username, pkeyfile=pkeyfile, pkeystr=pkeystr, password=password)
        self.vmName, self.vmId = self.get_vm(vmName, vmId)
        if self.vmId is None:
            self.vmName = vmName

    def get_vm(self, vmName=None, vmId=None):
        (stdin, stdout, stderr) = self.esxiCnx.exec_command("vim-cmd vmsvc/getallvms")
        allVms = stdout.readlines()
        for vm in allVms:
            vm_params = re.search('^(?P<vmid>\d+)\s+(?P<vmname>.*?)\s+(?P<datastore>\[.*?\])\s+(?P<vmxpath>.*?)\s+(?P<guest>.*?)\s+(?P<ver>.*?)(:\s+(?P<annotation>.*))?$', vm)
            if vm_params and vm_params.group('vmname') and vm_params.group('vmid') and ((vmName and vmName == vm_params.group('vmname')) or (vmId and vmId == vm_params.group('vmid'))):
                return vm_params.group('vmname'), vm_params.group('vmid')
        return None, None

    def get_vmx(self, vmId):
        (stdin, stdout, stderr) = self.esxiCnx.exec_command("vim-cmd vmsvc/get.filelayout " + vmId + " | grep 'vmPathName = ' | sed -r 's/^\s+vmPathName = \"(.*?)\",/\\1/g'")
        vmxPathName = stdout.read().decode('UTF-8').lstrip("\r\n").rstrip(" \r\n")
        vmxPath = re.sub(r"^\[(.*?)]\s+(.*?)$", r"/vmfs/volumes/\1/\2", vmxPathName)

        if vmxPath:
            sftp_cnx = self.esxiCnx.get_sftpClient()
            vmxFileDict = {}
            for line in sftp_cnx.file(vmxPath).readlines():
                key, value = line.split("=")
                vmxFileDict[key.strip(" \"\r\n").lower()] = value.strip(" \"\r\n")

            return vmxFileDict

    def create_vm(self, vmTemplate=None, datastore=None, hardware=None, guest_id=None, disks=None, cdrom=None, customvalues=None, networks=None):
        # Create VM directory
        vmPath = datastore + "/" + self.vmName
        self.esxiCnx.exec_command("mkdir -p " + vmPath)

        vmxDict = collections.OrderedDict(esxiFreeScraper.vmx_skeleton)

        # First apply any vmx settings from the template.
        # These will be overridden by explicit configuration.
        if vmTemplate:
            templ_vmName, templ_vmId = self.get_vm(vmTemplate, None)
            if templ_vmId:
                templ_vmxDict = self.get_vmx(templ_vmId)

                # Generic settings
                vmxDict.update({"guestos": templ_vmxDict['guestos']})

                # Hardware settings
                if 'numvcpus' in templ_vmxDict:
                    vmxDict.update({"numvcpus": templ_vmxDict['numvcpus']})
                vmxDict.update({"memsize": templ_vmxDict['memsize']})
                vmxDict.update({"virtualhw.version": templ_vmxDict['virtualhw.version']})

                # Network settings
                netCount = 0
                while "ethernet" + str(netCount) + ".virtualdev" in templ_vmxDict:
                    vmxDict.update({"ethernet" + str(netCount) + ".virtualdev": templ_vmxDict["ethernet" + str(netCount) + ".virtualdev"]})
                    vmxDict.update({"ethernet" + str(netCount) + ".networkname": templ_vmxDict["ethernet" + str(netCount) + ".networkname"]})
                    vmxDict.update({"ethernet" + str(netCount) + ".addresstype": "generated"})
                    vmxDict.update({"ethernet" + str(netCount) + ".present": "TRUE"})
                    netCount = netCount + 1

                # Disk settings
                diskCount = 0
                while "scsi0:" + str(diskCount) + ".filename" in templ_vmxDict:
                    # See if vmTemplate disk exists
                    try:
                        (stdin, stdout, stderr) = self.esxiCnx.exec_command("find " + datastore + "/" + vmTemplate + "/" + templ_vmxDict["scsi0:" + str(diskCount) + ".filename"])
                    except IOError as e:
                        pass
                    else:
                        disk_count_suffix = "_" + diskCount if diskCount > 0 else ""
                        disk_filename = self.vmName + disk_count_suffix + ".vmdk"
                        self.esxiCnx.exec_command("vmkfstools -i " + datastore + "/" + vmTemplate + "/" + templ_vmxDict["scsi0:" + str(diskCount) + ".filename"] + " -d thin" + " " + vmPath + "/" + disk_filename)

                        vmxDict.update({"scsi0:" + str(diskCount) + ".devicetype": "scsi-hardDisk"})
                        vmxDict.update({"scsi0:" + str(diskCount) + ".present": "TRUE"})
                        vmxDict.update({"scsi0:" + str(diskCount) + ".filename": disk_filename})
                        diskCount = diskCount + 1

        # Now add remaining settings, overriding template copies.

        # Generic settings
        if guest_id:
            vmxDict.update({"guestos": guest_id})
        vmxDict.update({"displayname": self.vmName})
        vmxDict.update({"vm.createdate": time.time()})

        # Hardware settings
        if 'version' in hardware:
            vmxDict.update({"virtualhw.version": hardware['version']})
        if 'memory_mb' in hardware:
            vmxDict.update({"memsize": hardware['memory_mb']})
        if 'num_cpus' in hardware:
            vmxDict.update({"numvcpus": hardware['num_cpus']})

        # CDROM settings
        if cdrom['type'] == 'client':
            (stdin, stdout, stderr) = self.esxiCnx.exec_command("find /vmfs/devices/cdrom/ -mindepth 1 ! -type l")
            cdrom_dev = stdout.read().decode('UTF-8').lstrip("\r\n").rstrip(" \r\n")
            vmxDict.update({"ide0:0.devicetype": "atapi-cdrom"})
            vmxDict.update({"ide0:0.filename": cdrom_dev})
            vmxDict.update({"ide0:0.present": "TRUE"})
        elif cdrom['type'] == 'iso':
            if 'iso_path' in cdrom:
                vmxDict.update({"ide0:0.devicetype": "cdrom-image"})
                vmxDict.update({"ide0:0.filename": cdrom['iso_path']})
                vmxDict.update({"ide0:0.present": "TRUE"})
                vmxDict.update({"ide0:0.startconnected": "TRUE"})

        # Network settings
        for netCount in range(0, len(networks)):
            vmxDict.update({"ethernet" + str(netCount) + ".virtualdev": networks[netCount]['virtualDev']})
            vmxDict.update({"ethernet" + str(netCount) + ".networkname": networks[netCount]['networkName']})
            vmxDict.update({"ethernet" + str(netCount) + ".addresstype": "generated"})
            vmxDict.update({"ethernet" + str(netCount) + ".present": "TRUE"})

        # Disk settings
        for diskCount in range(0, len(disks)):
            disk_count_suffix = "_" + diskCount if diskCount > 0 else ""
            disk_filename = self.vmName + disk_count_suffix + ".vmdk"

            (stdin, stdout, stderr) = self.esxiCnx.exec_command("vmkfstools -c " + str(disks[diskCount]['size_gb']) + "G -d " + disks[diskCount]['type'] + " " + vmPath + "/" + disk_filename)

            vmxDict.update({"scsi0:" + str(diskCount) + ".devicetype": "scsi-hardDisk"})
            vmxDict.update({"scsi0:" + str(diskCount) + ".present": "TRUE"})
            vmxDict.update({"scsi0:" + str(diskCount) + ".filename": disk_filename})

        # Dump the VMX
        # print(json.dumps(vmxDict, sort_keys=True, indent=4, separators=(',', ': ')))
        vmxStr = io.StringIO()
        for vmxKey, vmxVal in vmxDict.items():
            vmxStr.write(str(vmxKey.lower()) + " = " + "\"" + str(vmxVal) + "\"\n")
        vmxStr.seek(0)
        sftp_cnx = self.esxiCnx.get_sftpClient()
        sftp_cnx.putfo(vmxStr, vmPath + "/" + self.vmName + ".vmx", file_size=0, callback=None, confirm=True)

        # Register the VM
        (stdin, stdout, stderr) = self.esxiCnx.exec_command("vim-cmd solo/registervm " + vmPath + "/" + self.vmName + ".vmx")
        self.vmId = int(stdout.readlines()[0])


def main():
    argument_spec = {
        "hostname": {"type": "str"},
        "username": {"type": "str"},
        "password": {"type": "str", "required": False},
        "pkeyfile": {"type": "str", "required": False},
        "pkeystr": {"type": "str", "required": False},
        "name": {"type": "str", "required": False},
        "vmid": {"type": "str", "required": False},
        "state": {"type": "str", "default": 'present', "choices": ['absent', 'present']},
        "force": {"type": "bool", "default": False, "required": False},
        "template": {"type": "str", "required": False},
        "datastore": {"type": "str", "required": True},
        "hardware": {"type": "dict", "default": {}},
        "guest_id": {"type": "str", "default": ""},
        "disk": {"type": "list", "default": []},
        "cdrom": {"type": "dict", "default": {"type": "client"}},
        "networks": {"type": "list", "default": []},
        "customvalues": {"type": "list", "default": []},
        "wait": {"type": "bool", "default": True, "required": False},
        "wait_timeout": {"type": "int", "default": 300, "required": False}
    }

    # For testing on Windows without Ansible
    if os.name != 'nt':
        module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True, required_one_of=[['name', 'vmid'], ['password', 'pkeyfile', 'pkeystr']])
    else:
        class cDummyAnsibleModule():
            ## Create blank VM
            # params = {
            #     "hostname": "192.168.1.3",
            #     "username": "root",
            #     "pkeyfile": "../id_rsa_esxisvc_nopw",
            #     "pkeystr": None,
            #     "password": None,
            #     "name": "dstest1",
            #     "state": "present",
            #     "guest_id": "centos7-64",
            #     "template": "",
            #     "datastore": "/vmfs/volumes/sata-raid10-4tb-01/",
            #     "hardware": {"version": "14", "num_cpus": "2", "memory_mb": "2048"},
            #     "disk": [{"size_gb": "16", "type": "thin"}],
            #     "cdrom": {"type": "iso", "iso_path": "/vmfs/volumes/sata-raid10-4tb-01/ISOs/CentOS-7-x86_64-Minimal-1810.iso"},
            #     "networks": [{"networkName": "VM Network", "virtualDev": "vmxnet3"}],
            #     "customvalues": [],
            #     "vmId": None,
            #     "wait": None,
            #     "wait_timeout": None
            # }

            ## Clone VM
            params = {
                "hostname": "192.168.1.3",
                "username": "root",
                "password": None,
                "pkeyfile": "../id_rsa_esxisvc_nopw",
                "pkeystr": None,
                "name": "dstest1",
                "state": "present",
                "force": True,
                "guest_id": "",
                "template": "ubuntu1804-packer-template",
                "datastore": "/vmfs/volumes/sata-raid10-4tb-01/",
                "hardware": {},
                "disk": [],
                "cdrom": {"type": "client"},
                "networks": [],
                "customvalues": [],
                "vmId": None,
                "wait": True,
                "wait_timeout": 300
            }

            ## Delete VM
            # params = {
            #     "hostname": "192.168.1.3",
            #     "username": "root",
            #     "password": None,
            #     "pkeyfile": "../id_rsa_esxisvc_nopw",
            #     "pkeystr": None,
            #     "name": "dstest1",
            #     "state": "absent",
            #     "vmId": None,
            #     "wait": None,
            #     "wait_timeout": None
            # }

            def exit_json(self, changed, **kwargs):
                print(changed, json.dumps(kwargs, sort_keys=True, indent=4, separators=(',', ': ')))

            def fail_json(self, msg):
                print("Failed: " + msg)
                exit(1)

        module = cDummyAnsibleModule()

    pyv = esxiFreeScraper(hostname=module.params['hostname'],
                          username=module.params['username'],
                          password=module.params['password'],
                          pkeyfile=module.params['pkeyfile'],
                          pkeystr=module.params['pkeystr'],
                          vmName=module.params['name'],
                          vmId=module.params['vmId'])

    if pyv.vmId is None and pyv.vmName is None:
        module.fail_json(msg="If VM doesn't already exist, you must provide a name for it")

    # Check if the VM exists before continuing
    if module.params['state'] == 'absent':
        if pyv.vmId:
            pyv.esxiCnx.exec_command("vim-cmd vmsvc/destroy " + str(pyv.vmId))
            module.exit_json(changed=True, meta={"msg": "Deleted " + pyv.vmName + ": " + str(pyv.vmId)})
        else:
            module.fail_json(msg="vm already absent")
    elif module.params['state'] == 'present':
        if pyv.vmId and module.params['force'] is False:
            module.fail_json(msg="vm already exists")
        elif pyv.vmId and module.params['force']:
            (stdin, stdout, stderr) = pyv.esxiCnx.exec_command("vim-cmd vmsvc/power.getstate " + str(pyv.vmId))
            if re.search('Powered on', stdout.read().decode('UTF-8')) is not None:
                pyv.esxiCnx.exec_command("vim-cmd vmsvc/power.off " + str(pyv.vmId))

            pyv.esxiCnx.exec_command("vim-cmd vmsvc/destroy " + str(pyv.vmId))

        pyv.create_vm(module.params['template'], module.params['datastore'], module.params['hardware'], module.params['guest_id'], module.params['disk'], module.params['cdrom'], module.params['customvalues'], module.params['networks'])

        pyv.esxiCnx.exec_command("vim-cmd vmsvc/power.on " + str(pyv.vmId))

        if module.params['wait']:
            time_s = int(module.params['wait_timeout'])

            while time_s > 0:
                (stdin, stdout, stderr) = pyv.esxiCnx.exec_command("vim-cmd vmsvc/get.guest " + str(pyv.vmId))

                guest_info = stdout.read().decode('UTF-8')
                vm_params = re.search('\s*hostName\s*=\s*\"?(?P<hostname>.*?)\"?,.*\n\s*ipAddress\s*=\s*\"?(?P<ip>.*?)\"?,.*', guest_info)
                if vm_params and vm_params.group('ip') != "<unset>" and vm_params.group('hostname') != "":
                    break
                else:
                    time.sleep(1)
                    time_s = time_s - 1

            module.exit_json(changed=True,
                             hostname=vm_params.group('hostname'),
                             ipAddress=vm_params.group('ip'),
                             vmName=module.params['name'],
                             vmID=pyv.vmId)

        else:
            module.exit_json(changed=True,
                             hostname="",
                             ipAddress="",
                             vmName=module.params['name'],
                             vmID=pyv.vmId)


if __name__ == '__main__':
    main()
