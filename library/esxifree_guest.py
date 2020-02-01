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
  esxi_hostname:
    description:
    - The esxi_hostname or IP address of the ESXi server.
  esxi_username:
    description:
    - The esxi_username to access the ESXi server.
  esxi_password:
    description:
    - The esxi_password of esxi_username for the ESXi server, or the esxi_password for the private key (if required).
  esxi_pkeyfile:
    description:
    - The private key file for the user of the ESXi server.
  esxi_pkeystr:
    description:
    - The private key (as a string) for the user of the ESXi server.
  vm_name:
    description:
    - Name of the virtual machine to work with.
    - This parameter is required, if C(state) is set to C(poweredon), C(poweredoff), C(present), C(restarted), C(suspended) and virtual machine does not exists.
    - This parameter is case sensitive.
    required: yes
  vm_id:
    description:
    - vm id of the virtual machine to manage if known, this is VMware's unique identifier.
    - This is required if C(vm_name) is not supplied.
    - If virtual machine does not exists, then this parameter is ignored.
    - Will be ignored on virtual machine creation
  vm_template:
    description:
    - Template or existing virtual machine used to create new virtual machine.
    - If this value is not set, virtual machine is created without using a template.
    - If the virtual machine already exists, this parameter will be ignored.
    - This parameter is case sensitive.
  state:
    description:
    - Specify state of the virtual machine be in.
    - 'If C(state) is set to C(present) and virtual machine exists, ensure the virtual machine configurations conforms to task arguments.'
    - 'If C(state) is set to C(absent) and virtual machine exists, then the specified virtual machine is removed with its associated components.'
    default: present
    choices: [ present, absent ]
  force:
    description:
    - Delete the existing host if it exists.
  datastore_path:
    description:
    - Destination datastore, absolute path to create the new guest.
    - This parameter is case sensitive.
    - This parameter is required, while deploying new virtual machine.
    - 'Examples:'
    - '   datastore_path: /vmfs/volumes/4tb-evo860-ssd/'
    - '   datastore_path: /vmfs/volumes/datastore1/'
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
  hardware:
    description:
    - Manage virtual machine's hardware attributes.
    - All parameters case sensitive.
    - 'Valid attributes are:'
    - ' - C(memory_mb) (integer): Amount of memory in MB.'
    - ' - C(num_cpus) (integer): Number of CPUs.'
    - ' - C(version) (integer): The Virtual machine hardware versions. Default is 14 (ESXi 6.7 and onwards).
  cloudinit_userdata:
    description:
    - cloud-init userdata
  disks:
    description:
    - This parameter is case sensitive.
    - Resizing disks is not supported.
    - Removing existing disks of the virtual machine is not supported.
    - Array of disks.
    - 'Valid attributes are:'
    - ' - C(size_gb) (integer): Disk storage size in GB'
    - ' - C(type) (string): Valid values are:'
    - '     - C(thin) thin disk'
    - '     - C(thick) no eagerzero'
    - '     - C(eagerzeroedthick) eagerzeroedthick disk, added in version 2.5'
    - '     Default: C(thin)'
  cdrom:
    description:
    - A CD-ROM configuration for the virtual machine.
    - 'Valid attributes are:'
    - ' - C(type) (string): The type of CD-ROM, valid options are C(none), C(client) or C(iso). With C(none) the CD-ROM will be disconnected but present.'
    - ' - C(iso_path) (string): The datastore path to the ISO file to use, in the form of C([datastore1] path/to/file.iso). Required if type is set C(iso).'
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
- name: Create vmware instances
  esxifree_guest:
    esxi_hostname: "192.168.1.3"
    esxi_username: "svc"
    esxi_pkeystr: "{{ esxi_pkeystr }}"
    datastore_path: "/vmfs/volumes/4tb-evo860-ssd/"
    vm_name: "test_asdf"
    state: present
    guest_id: ubuntu-64
    hardware: {"version": "15", "num_cpus": "2", "memory_mb": "2048"}
    cloudinit_userdata:
      - default
      - name: dougal
        primary_group: dougal
        sudo: "ALL=(ALL) NOPASSWD:ALL"
        groups: "admin"
        home: "/media/filestore/home/dougal"
        ssh_import_id: None
        lock_passwd: false
        passwd: $6$j212wezy$7...YPYb2F
        ssh_authorized_keys: ['ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACA+.................GIMhdojtl6mzVn38vXMzSL29LQ== ansible@dougalseeley.com']
    disks:
      root: {"size_gb": 16, "type": "thin"}
      volumes: [{"size_gb": 5, "type": "thin"},{"size_gb": 2, "type": "thin"}]
    networks:
      - networkName: VM Network
        virtualDev: vmxnet3
        cloudinit_ethernets:
          eth0:
            addresses: ["192.168.1.8/25"]
            dhcp4: false
            gateway4: 192.168.1.1
            nameservers:
              addresses: ["192.168.1.2", "8.8.8.8", "8.8.4.4"]
              search: ["local.dougalseeley.com"]
  delegate_to: localhost

- name: Clone a virtual machine
  esxifree_guest:
    esxi_hostname: "192.168.1.3"
    esxi_username: "svc"
    esxi_pkeystr: "{{ esxi_pkeystr }}"
    datastore_path: "/vmfs/volumes/4tb-evo860-ssd/"
    vm_template: "ubuntu1804-packer-template"
    vm_name: "test_asdf"
    state: present
    guest_id: ubuntu-64
    hardware: {"version": "15", "num_cpus": "2", "memory_mb": "2048"}
    cloudinit_userdata:
      - default
      - name: dougal
        primary_group: dougal
        sudo: "ALL=(ALL) NOPASSWD:ALL"
        groups: "admin"
        home: "/media/filestore/home/dougal"
        ssh_import_id: None
        lock_passwd: true
        ssh_authorized_keys: ['ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACA+.................GIMhdojtl6mzVn38vXMzSL29LQ== ansible@dougalseeley.com']
    disks:
      root: {}
      volumes: [{"size_gb": 5, "type": "thin"},{"size_gb": 2, "type": "thin"}]
    networks:
      - networkName: VM Network
        virtualDev: vmxnet3
        cloudinit_ethernets:
          eth0:
            addresses: ["192.168.1.8/25"]
            dhcp4: false
            gateway4: 192.168.1.1
            nameservers:
              addresses: ["192.168.1.2", "8.8.8.8", "8.8.4.4"]
              search: ["local.dougalseeley.com"]
  delegate_to: localhost

- name: Delete a virtual machine
  esxifree_guest:
    esxi_hostname: "{{ esxi_ip }}"
    esxi_username: "{{ esxi_username }}"
    esxi_password: "{{ esxi_password }}"
    vm_name: test_vm_0001
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
import base64
import yaml
import errno  # For the python2.7 IOError, because FileNotFound is for python3


if sys.version_info[0] < 3:
    from io import BytesIO as StringIO
else:
    from io import StringIO

# paramiko.util.log_to_file("paramiko.log")
# paramiko.common.logging.basicConfig(level=paramiko.common.DEBUG)

try:
    from ansible.module_utils.basic import AnsibleModule
except:
    pass


# Executes a command on the remote host.
class SSHCmdExec(object):
    def __init__(self, hostname, username=None, password=None, pkeyfile=None, pkeystr=None):
        self.hostname = hostname

        try:
            if pkeystr and pkeystr != "":
                pkey_fromstr = paramiko.RSAKey.from_private_key(StringIO(pkeystr), password)
            if pkeyfile and pkeyfile != "":
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
            print("Authentication failure, unable to connect to " + hostname + " as " + username + "\n\n" + str(auth_err) + "\n\n" + str(sys.exc_info()[0]))  # + str(auth_err))
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
        if stdout.channel.recv_exit_status() != 0:  # Blocking call
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

    def __init__(self, esxi_hostname, esxi_username='root', esxi_password=None, esxi_pkeyfile=None, esxi_pkeystr=None, vm_name=None, vm_id=None):
        self.esxiCnx = SSHCmdExec(hostname=esxi_hostname, username=esxi_username, pkeyfile=esxi_pkeyfile, pkeystr=esxi_pkeystr, password=esxi_password)
        self.vm_name, self.vm_id = self.get_vm(vm_name, vm_id)
        if self.vm_id is None:
            self.vm_name = vm_name

    def get_vm(self, vm_name=None, vm_id=None):
        (stdin, stdout, stderr) = self.esxiCnx.exec_command("vim-cmd vmsvc/getallvms")
        allVms = stdout.readlines()
        for vm in allVms:
            vm_params = re.search('^(?P<vmid>\d+)\s+(?P<vmname>.*?)\s+(?P<datastore>\[.*?\])\s+(?P<vmxpath>.*?)\s+(?P<guest>.*?)\s+(?P<ver>.*?)(:\s+(?P<annotation>.*))?$', vm)
            if vm_params and vm_params.group('vmname') and vm_params.group('vmid') and ((vm_name and vm_name == vm_params.group('vmname')) or (vm_id and vm_id == vm_params.group('vmid'))):
                return vm_params.group('vmname'), vm_params.group('vmid')
        return None, None

    def get_vmx(self, vm_id):
        (stdin, stdout, stderr) = self.esxiCnx.exec_command("vim-cmd vmsvc/get.filelayout " + str(vm_id) + " | grep 'vmPathName = ' | sed -r 's/^\s+vmPathName = \"(.*?)\",/\\1/g'")
        vmxPathName = stdout.read().decode('UTF-8').lstrip("\r\n").rstrip(" \r\n")
        vmxPath = re.sub(r"^\[(.*?)]\s+(.*?)$", r"/vmfs/volumes/\1/\2", vmxPathName)

        if vmxPath:
            sftp_cnx = self.esxiCnx.get_sftpClient()
            vmxFileDict = {}
            for vmxline in sftp_cnx.file(vmxPath).readlines():
                vmxline_params = re.search('^(?P<key>.*?)\s*=\s*(?P<value>.*)$', vmxline)
                if vmxline_params and vmxline_params.group('key') and vmxline_params.group('value'):
                    vmxFileDict[vmxline_params.group('key').strip(" \"\r\n").lower()] = vmxline_params.group('value').strip(" \"\r\n")

            return vmxPath, vmxFileDict

    def put_vmx(self, vmxDict, vmxPath):
        # Dump the VMX
        # print(json.dumps(vmxDict, sort_keys=True, indent=4, separators=(',', ': ')))

        vmxDict = collections.OrderedDict(sorted(vmxDict.items()))
        vmxStr = StringIO()
        for vmxKey, vmxVal in vmxDict.items():
            vmxStr.write(str(vmxKey.lower()) + " = " + "\"" + str(vmxVal) + "\"\n")
        vmxStr.seek(0)
        sftp_cnx = self.esxiCnx.get_sftpClient()
        try:
            sftp_cnx.stat(vmxPath)
            sftp_cnx.remove(vmxPath)
        except IOError as e:  # python 2.7
            if e.errno == errno.ENOENT:
                pass
        except FileNotFoundError:  # python 3.x
            pass
        sftp_cnx.putfo(vmxStr, vmxPath, file_size=0, callback=None, confirm=True)

    def create_vm(self, vmTemplate=None, datastore_path=None, hardware=None, guest_id=None, disks=None, cdrom=None, customvalues=None, networks=None, cloudinit_userdata=None):

        # Create VM directory
        vmPath = datastore_path + "/" + self.vm_name
        self.esxiCnx.exec_command("mkdir -p " + vmPath)

        vmxDict = collections.OrderedDict(esxiFreeScraper.vmx_skeleton)

        # First apply any vmx settings from the template.
        # These will be overridden by explicit configuration.
        diskCount = 0
        if vmTemplate:
            templ_vmName, templ_vmId = self.get_vm(vmTemplate, None)
            if templ_vmId:
                templ_vmxPath, templ_vmxDict = self.get_vmx(templ_vmId)

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

                ### Disk cloning
                # Clone first (root) if present
                try:
                    (stdin, stdout, stderr) = self.esxiCnx.exec_command("find " + datastore_path + "/" + vmTemplate + "/" + templ_vmxDict["scsi0:0.filename"])
                except IOError as e:
                    pass
                else:
                    disk_filename = self.vm_name + ".vmdk"
                    self.esxiCnx.exec_command("vmkfstools -i " + datastore_path + "/" + vmTemplate + "/" + templ_vmxDict["scsi0:0.filename"] + " -d thin" + " " + vmPath + "/" + disk_filename)

                    vmxDict.update({"scsi0:0.devicetype": "scsi-hardDisk"})
                    vmxDict.update({"scsi0:0.present": "TRUE"})
                    vmxDict.update({"scsi0:0.filename": disk_filename})
                    diskCount = diskCount + 1
                # If no new volumes have been defined, or have been deliberately set to None, copy existing from template
                if "volumes" not in disks or ("volumes" in disks and disks["volumes"] is None):
                    while "scsi0:" + str(diskCount) + ".filename" in templ_vmxDict:
                        # See if vmTemplate disk exists
                        try:
                            (stdin, stdout, stderr) = self.esxiCnx.exec_command("find " + datastore_path + "/" + vmTemplate + "/" + templ_vmxDict["scsi0:" + str(diskCount) + ".filename"])
                        except IOError as e:
                            pass
                        else:
                            diskIdxSuffix = "_" + str(diskCount) if diskCount > 0 else ""
                            disk_filename = self.vm_name + diskIdxSuffix + ".vmdk"
                            self.esxiCnx.exec_command("vmkfstools -i " + datastore_path + "/" + vmTemplate + "/" + templ_vmxDict["scsi0:" + str(diskCount) + ".filename"] + " -d thin" + " " + vmPath + "/" + disk_filename)

                            vmxDict.update({"scsi0:" + str(diskCount) + ".devicetype": "scsi-hardDisk"})
                            vmxDict.update({"scsi0:" + str(diskCount) + ".present": "TRUE"})
                            vmxDict.update({"scsi0:" + str(diskCount) + ".filename": disk_filename})
                            diskCount = diskCount + 1
            else:
                return (vmTemplate + " not found!")

        ## Now add remaining settings, overriding template copies.

        # Generic settings
        if guest_id:
            vmxDict.update({"guestos": guest_id})
        vmxDict.update({"displayname": self.vm_name})
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
        cloudinit_nets = {"version": 2}
        for netCount in range(0, len(networks)):
            vmxDict.update({"ethernet" + str(netCount) + ".virtualdev": networks[netCount]['virtualDev']})
            vmxDict.update({"ethernet" + str(netCount) + ".networkname": networks[netCount]['networkName']})
            if "macAddress" in networks[netCount]:
                vmxDict.update({"ethernet" + str(netCount) + ".addresstype": "static"})
                vmxDict.update({"ethernet" + str(netCount) + ".address": networks[netCount]['macAddress']})
                vmxDict.update({"ethernet" + str(netCount) + ".checkmacaddress": "FALSE"})
            else:
                vmxDict.update({"ethernet" + str(netCount) + ".addresstype": "generated"})
            vmxDict.update({"ethernet" + str(netCount) + ".present": "TRUE"})
            if "cloudinit_netplan" in networks[netCount]:
                cloudinit_nets.update(networks[netCount]['cloudinit_netplan'])

        # Add cloud-init metadata (hostname & network)
        cloudinit_metadata = {"local-hostname": self.vm_name}
        if cloudinit_nets['ethernets'].keys():
            cloudinit_metadata.update({"network": base64.b64encode(yaml.dump(cloudinit_nets, width=4096, encoding='utf-8')).decode('ascii'), "network.encoding": "base64"})
        vmxDict.update({"guestinfo.metadata": base64.b64encode((str(cloudinit_metadata)).encode('utf-8')).decode('ascii'), "guestinfo.metadata.encoding": "base64"})

        # Add cloud-init userdata (must be in MIME multipart format)
        if cloudinit_userdata and len(cloudinit_userdata):
            import sys
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            combined_message = MIMEMultipart()
            sub_message = MIMEText(yaml.dump({"users": cloudinit_userdata}, width=4096), "cloud-config", sys.getdefaultencoding())
            sub_message.add_header('Content-Disposition', 'attachment; filename="cloud-config.yaml"')
            combined_message.attach(sub_message)
            vmxDict.update({"guestinfo.userdata": base64.b64encode(combined_message.as_bytes()).decode('ascii'), "guestinfo.userdata.encoding": "base64"})

        # Disk settings
        if "scsi0:0.filename" not in vmxDict:
            if "root" not in disks:
                return ("Root disk parameters not defined for new VM")

            disk_filename = self.vm_name + ".vmdk"
            (stdin, stdout, stderr) = self.esxiCnx.exec_command("vmkfstools -c " + str(disks["root"]['size_gb']) + "G -d " + disks["root"]['type'] + " " + vmPath + "/" + disk_filename)

            vmxDict.update({"scsi0:0.devicetype": "scsi-hardDisk"})
            vmxDict.update({"scsi0:0.present": "TRUE"})
            vmxDict.update({"scsi0:0.filename": disk_filename})
            diskCount = diskCount + 1
        if "volumes" in disks:
            for newDiskIdx in range(len(disks["volumes"])):
                vmxDict_diskIdx = newDiskIdx + diskCount
                disk_filename = self.vm_name + "_" + str(vmxDict_diskIdx) + ".vmdk"

                (stdin, stdout, stderr) = self.esxiCnx.exec_command("vmkfstools -c " + str(disks["volumes"][newDiskIdx]['size_gb']) + "G -d " + disks["volumes"][newDiskIdx]['type'] + " " + vmPath + "/" + disk_filename)

                vmxDict.update({"scsi0:" + str(vmxDict_diskIdx) + ".devicetype": "scsi-hardDisk"})
                vmxDict.update({"scsi0:" + str(vmxDict_diskIdx) + ".present": "TRUE"})
                vmxDict.update({"scsi0:" + str(vmxDict_diskIdx) + ".filename": disk_filename})

        # write the vmx
        self.put_vmx(vmxDict, vmPath + "/" + self.vm_name + ".vmx")

        # Register the VM
        (stdin, stdout, stderr) = self.esxiCnx.exec_command("vim-cmd solo/registervm " + vmPath + "/" + self.vm_name + ".vmx")
        self.vm_id = int(stdout.readlines()[0])

    # Delete the cloud-init guestinfo.metadata info from the .vmx file, otherwise it will be impossible to change the network configuration or hostname.
    def delete_cloudinit(self):
        vmxPath, vmxDict = self.get_vmx(self.vm_id)
        if 'guestinfo.metadata' in vmxDict:
            del vmxDict['guestinfo.metadata']
        if 'guestinfo.metadata.encoding' in vmxDict:
            del vmxDict['guestinfo.metadata.encoding']
        if 'guestinfo.userdata' in vmxDict:
            del vmxDict['guestinfo.userdata']
        if 'guestinfo.userdata.encoding' in vmxDict:
            del vmxDict['guestinfo.userdata.encoding']

        # write the vmx
        self.put_vmx(vmxDict, vmxPath)


def main():
    argument_spec = {
        "esxi_hostname": {"type": "str", "required": True},
        "esxi_username": {"type": "str", "required": True},
        "esxi_password": {"type": "str"},
        "esxi_pkeyfile": {"type": "str"},
        "esxi_pkeystr": {"type": "str"},
        "vm_name": {"type": "str"},
        "vm_id": {"type": "str"},
        "vm_template": {"type": "str"},
        "state": {"type": "str", "default": 'present', "choices": ['absent', 'present']},
        "force": {"type": "bool", "default": False},
        "datastore_path": {"type": "str"},
        "guest_id": {"type": "str", "default": "ubuntu-64"},
        "hardware": {"type": "dict", "default": {"version": "15", "num_cpus": "2", "memory_mb": "2048"}},
        "cloudinit_userdata": {"type": "list", "default": []},
        "disks": {"type": "dict", "default": {"root": {"size_gb": 16, "type": "thin"}}},
        "cdrom": {"type": "dict", "default": {"type": "client"}},
        "networks": {"type": "list", "default": [{"networkName": "VM Network", "virtualDev": "vmxnet3"}]},
        "customvalues": {"type": "list", "default": []},
        "wait": {"type": "bool", "default": True},
        "wait_timeout": {"type": "int", "default": 180}
    }

    if not (len(sys.argv) > 1 and sys.argv[1] == "console"):
        module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True, required_one_of=[['vm_name', 'vm_id'], ['esxi_password', 'esxi_pkeyfile', 'esxi_pkeystr']])
    else:
        # For testing without Ansible (e.g on Windows)
        class cDummyAnsibleModule():
            ## Create blank VM
            # params = {
            #     "esxi_hostname": "192.168.1.3",
            #     "esxi_username": "svc",
            #     "esxi_pkeyfile": "../id_rsa_esxisvc_nopw",
            #     "esxi_pkeystr": None,
            #     "esxi_password": None,
            #     "vm_name": "test-asdf",
            #     "vm_id": None,
            #     "vm_template": None,
            #     "state": "present",
            #     "force": False,
            #     "datastore_path": "/vmfs/volumes/4tb-evo860-ssd/",
            #     "guest_id": "ubuntu-64",
            #     "hardware": {"version": "15", "num_cpus": "2", "memory_mb": "2048"},
            #     "cloudinit_userdata": [],
            #     "disks": {"root": {"size_gb": 16, "type": "thin"}, "volumes": [{"size_gb": 5, "type": "thin"},{"size_gb": 2, "type": "thin"}]},
            #     "cdrom": {"type": "iso", "iso_path": "/vmfs/volumes/4tb-evo860-ssd/ISOs/ubuntu-18.04.2-server-amd64.iso"},
            #     "networks": [{"networkName": "VM Network", "virtualDev": "vmxnet3"}],
            #     "customvalues": [],
            #     "wait": True,
            #     "wait_timeout": 180,
            # }

            ## Clone VM
            # params = {
            #     "esxi_hostname": "192.168.1.3",
            #     "esxi_username": "svc",
            #     "esxi_password": None,
            #     "esxi_pkeyfile": "../id_rsa_esxisvc_nopw",
            #     "esxi_pkeystr": None,
            #     "vm_name": "test-asdf",
            #     "vm_id": None,
            #     "vm_template": "gold-ubuntu1804-20200104203707",
            #     "state": "present",
            #     "force": False,
            #     "datastore_path": "/vmfs/volumes/4tb-evo860-ssd/",
            #     "guest_id": "ubuntu-64",
            #     "hardware": {"version": "15", "num_cpus": "2", "memory_mb": "2048"},
            #     "cloudinit_userdata": [],
            #     "disks": {"volumes": [{"size_gb": 2, "type": "thin"}]},
            #     "cdrom": {"type": "client"},
            #     "networks": [{"networkName": "VM Network", "virtualDev": "vmxnet3", "cloudinit_netplan": {"ethernets": {"eth0": {"dhcp4": True}}}}],
            #     "customvalues": [],
            #     "wait": True,
            #     "wait_timeout": 180,
            # }

            ## Delete VM
            # params = {
            #     "esxi_hostname": "192.168.1.3",
            #     "esxi_username": "svc",
            #     "esxi_password": None,
            #     "esxi_pkeyfile": "../id_rsa_esxisvc_nopw",
            #     "esxi_pkeystr": None,
            #     "vm_name": "test-asdf",
            #     "vm_id": None,
            #     "state": "absent"
            # }

            def exit_json(self, changed, **kwargs):
                print(changed, json.dumps(kwargs, sort_keys=True, indent=4, separators=(',', ': ')))

            def fail_json(self, msg):
                print("Failed: " + msg)
                exit(1)

        module = cDummyAnsibleModule()

    iScraper = esxiFreeScraper(esxi_hostname=module.params['esxi_hostname'],
                               esxi_username=module.params['esxi_username'],
                               esxi_password=module.params['esxi_password'],
                               esxi_pkeyfile=module.params['esxi_pkeyfile'],
                               esxi_pkeystr=module.params['esxi_pkeystr'],
                               vm_name=module.params['vm_name'],
                               vm_id=module.params['vm_id'])

    # module.fail_json(msg=str(module.params['disks']))

    if iScraper.vm_id is None and iScraper.vm_name is None:
        module.fail_json(msg="If VM doesn't already exist, you must provide a name for it")

    # Check if the VM exists before continuing
    if module.params['state'] == 'absent':
        if iScraper.vm_id:
            # If it's turned on, turn it off (can't destroy it if it's on)
            (stdin, stdout, stderr) = iScraper.esxiCnx.exec_command("vim-cmd vmsvc/power.getstate " + str(iScraper.vm_id))
            if re.search('Powered on', stdout.read().decode('UTF-8')) is not None:
                iScraper.esxiCnx.exec_command("vim-cmd vmsvc/power.off " + str(iScraper.vm_id))

            iScraper.esxiCnx.exec_command("vim-cmd vmsvc/destroy " + str(iScraper.vm_id))
            module.exit_json(changed=True, meta={"msg": "Deleted " + iScraper.vm_name + ": " + str(iScraper.vm_id)})
        else:
            module.exit_json(changed=False, meta={"msg": "VM " + iScraper.vm_name + ": " + str(iScraper.vm_id) + " already absent."})

    elif module.params['state'] == 'present':
        # If the VM already exists, and the 'force' flag is set, then we delete it (and recreate it)
        if iScraper.vm_id and module.params['force']:
            # If it's turned on, turn it off (can't destroy it if it's on)
            (stdin, stdout, stderr) = iScraper.esxiCnx.exec_command("vim-cmd vmsvc/power.getstate " + str(iScraper.vm_id))
            if re.search('Powered on', stdout.read().decode('UTF-8')) is not None:
                iScraper.esxiCnx.exec_command("vim-cmd vmsvc/power.off " + str(iScraper.vm_id))
            iScraper.esxiCnx.exec_command("vim-cmd vmsvc/destroy " + str(iScraper.vm_id))
            iScraper.vm_id = None

        # If the VM doesn't exist, create it.
        if iScraper.vm_id is None:
            createVmResult = iScraper.create_vm(module.params['vm_template'], module.params['datastore_path'], module.params['hardware'], module.params['guest_id'], module.params['disks'], module.params['cdrom'], module.params['customvalues'], module.params['networks'], module.params['cloudinit_userdata'])
            if createVmResult != None:
                module.fail_json(msg=createVmResult)
            iScraper.esxiCnx.exec_command("vim-cmd vmsvc/power.on " + str(iScraper.vm_id))

            # Wait for the VM to start up
            time_s = int(module.params['wait_timeout'])
            while time_s > 0:
                (stdin, stdout, stderr) = iScraper.esxiCnx.exec_command("vim-cmd vmsvc/power.getstate " + str(iScraper.vm_id))
                if re.search('Powered on', stdout.read().decode('UTF-8')) is not None:
                    break
                else:
                    time.sleep(1)
                    time_s = time_s - 1

            # Delete the cloud-init config
            iScraper.delete_cloudinit()
            isChanged = True
        else:
            isChanged = False

        if "wait" in module.params and module.params['wait']:
            time_s = int(module.params['wait_timeout'])
            while time_s > 0:
                (stdin, stdout, stderr) = iScraper.esxiCnx.exec_command("vim-cmd vmsvc/get.guest " + str(iScraper.vm_id))
                guest_info = stdout.read().decode('UTF-8')
                vm_params = re.search('\s*hostName\s*=\s*\"?(?P<vm_hostname>.*?)\"?,.*\n\s*ipAddress\s*=\s*\"?(?P<vm_ip>.*?)\"?,.*', guest_info)
                if vm_params and vm_params.group('vm_ip') != "<unset>" and vm_params.group('vm_hostname') != "":
                    break
                else:
                    time.sleep(1)
                    time_s = time_s - 1

            module.exit_json(changed=isChanged,
                             guest_info=guest_info,
                             hostname=vm_params.group('vm_hostname'),
                             ip_address=vm_params.group('vm_ip'),
                             vm_name=module.params['vm_name'],
                             vm_id=iScraper.vm_id)

        else:
            module.exit_json(changed=isChanged,
                             hostname="",
                             ip_address="",
                             vm_name=module.params['vm_name'],
                             vm_id=iScraper.vm_id)


if __name__ == '__main__':
    main()
