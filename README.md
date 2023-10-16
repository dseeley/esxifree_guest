# Ansible Collection - dseeley.esxifree_guest

These modules can be used to get the info from, and create new ESXi virtual machines, including cloning from templates or other virtual machines. 

It does so using direct SOAP calls and Paramiko SSH to the host - without using the vSphere API - meaning it can be used on the free hypervisor.

## Configuration
Your ESXi host needs some config:
+ Enable SSH
  + Inside the web UI, navigate to “Manage”, then the “Services” tab. Find the entry called: “TSM-SSH”, and enable it.
+ Enable “Guest IP Hack”
  + `esxcli system settings advanced set -o /Net/GuestIPHack -i 1`

## Requirements
+ python 3
+ paramiko

## Execution
This can be run as an Ansible module (see inline documentation), or from the console:
```bash
python3 ./esxifree_guest.py console
```