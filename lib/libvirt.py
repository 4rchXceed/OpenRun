from typing import Literal
import libvirt
import subprocess
import uuid
import os
import xml.etree.ElementTree as ET
import threading
from lib.webserver import run_server
import lib.webserver
import time
import ipaddress
import random
import json

instance = None


class LibvirtVMManager:
    def __init__(self):
        global instance
        instance = self
        self.conn = libvirt.open("qemu:///system")
        self.setup_files_thread = threading.Thread(target=run_server)
        self.setup_files_thread.start()
        self.vnc_thread = None
        self._ip: dict[str, str] = {}
        self._mac: dict[str, str] = {}
        self._subnet: dict[str, ipaddress.IPv4Network] = {}
        self._dhcp_range: dict[
            str, tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]
        ] = {}
        self.load_net_config()

    def stop_threads(self):
        self.setup_files_thread.join()
        if self.vnc_thread:
            self.vnc_thread.join()

    def get_host_ip(self, os_type):
        return self._ip.get(os_type, None)

    def check_vm_status(self, os_type: Literal["win11", "win10"]):
        try:
            dom = self.conn.lookupByName(f"{os_type}_openrunvm")
            return dom.isActive()
        except libvirt.libvirtError:
            return False

    def list_vms(self):
        return [vm.name() for vm in self.conn.listAllDomains()]

    def generate_mac(self):
        mac = [
            0x52,
            0x54,
            0x00,
            random.randint(0x00, 0x7F),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
        ]
        return ":".join(f"{x:02x}" for x in mac)

    def load_net_config(self, config_file="config/net.json"):
        if not os.path.exists(config_file):
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, "w") as f:
                json.dump([{}, {}], f)
        with open(config_file, "r") as f:
            ips, macs = json.load(f)

        for os_type in ips:
            ip = ips[os_type]
            self._ip[os_type] = ip
            self._subnet[os_type] = ipaddress.ip_network(
                f"{self._ip[os_type]}/24", strict=False
            )
            self._dhcp_range[os_type] = [
                self._subnet[os_type].network_address + 2,
                self._subnet[os_type].broadcast_address - 1,
            ]

    def save_net_config(self, config_file="config/net.json"):
        with open(config_file, "w") as f:
            json.dump([self._ip, self._mac], f)

    def create_snapshot(self, os_type):
        vm_name = f"{os_type}_openrunvm"
        try:
            dom = self.conn.lookupByName(vm_name)
        except libvirt.libvirtError:
            print(f"Failed to find domain {vm_name}.")
            return False
        disk_path = f"{os.getcwd()}/{os_type}.qcow2"
        snapshot = dom.snapshotCreateXML(
            f"""
            <domainsnapshot>
              <name>{vm_name}_clean</name>
              <description>Clean snapshot</description>
              <memory file='{os.getcwd()}/disks/{vm_name}_memory_snapshot.img'/>
              <disk name='sda' snapshot='external'>
                   <driver type='qcow2'/>
                   <source file='{os.getcwd()}/disks/{disk_path}_snapshot.qcow2'/>
              </disk>
            </domainsnapshot>
            """
        )
        if snapshot is None:
            print("Failed to create snapshot.")
            return False
        print(f"Snapshot created successfully: {snapshot}")

    def create_or_resume_network(self, os_type, ip=None):
        network_name = f"{os_type}_network"
        print(f"Setting up a network (NAT) for {os_type} VM... (name: {network_name})")
        try:
            self.conn.networkLookupByName(network_name)
            print(f"Network {network_name} already exists. Resuming...")
            return network_name
        except libvirt.libvirtError:
            pass

        if not self._ip.get(os_type):
            if ip is None:
                print("ERROR: IP address is required for the network setup.")
                return False
            self._ip[os_type] = ip
        else:
            print("A VM with this IP already exists. Exiting network creation.")
            return False
        if not self._mac.get(os_type):
            self._mac[os_type] = self.generate_mac()
        # Check if IP already exists
        self._subnet[os_type] = ipaddress.ip_network(
            f"{self._ip[os_type]}/24", strict=False
        )
        self._dhcp_range[os_type] = [
            self._subnet[os_type].network_address + 2,
            self._subnet[os_type].broadcast_address - 1,
        ]
        self.save_net_config()

        self.conn.networkCreateXML(
            f"""
        <network connections="1">
          <name>{network_name}</name>
          <uuid>{uuid.uuid4()}</uuid>
          <forward mode="nat">
            <nat>
              <port start="1024" end="8001"/>
            </nat>
          </forward>
            <bridge name="openrun0" stp="on" delay="0"/>
            <mac address="{self._mac[os_type]}"/>
          <ip address="{self._ip[os_type]}" netmask="{self._subnet[os_type].netmask}">
            <dhcp>
              <range start="{self._dhcp_range[os_type][0]}" end="{self._dhcp_range[os_type][1]}"/>
            </dhcp>
          </ip>
        </network>
        """
        )
        return network_name

    def setup_vm(
        self,
        os_type: Literal["win11", "win10"],
        iso_path: str,
        disk_dir: str = "disks/",
        memory_mb: int = 4096,
        vcpus: int = 2,
        ip: str = "192.168.222.1",
    ):

        result = self.create_or_resume_network(os_type, ip)
        if not result:
            print("Failed to create or resume network.")
            return False
        print(
            f"Setting up a {os_type} VM with ISO: {iso_path} and disk path: {disk_dir}"
        )
        network_name = result
        disk_path = f"{disk_dir}{os_type}.qcow2"
        size = 40
        if os_type == "win11":
            size = 64
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", disk_path, f"{size}G"], check=True
        )
        disk_path = f"{disk_dir}{os_type}.qcow2"
        vm_name = f"{os_type}_openrunvm"
        xml = f"""
        <domain type='kvm'>
          <name>{vm_name}</name>
          <memory unit='MiB'>{memory_mb}</memory>
          <vcpu placement='static'>{vcpus}</vcpu>
          <os>
            <type arch='x86_64' machine='pc-q35-6.2'>hvm</type>
          </os>
          <features>
            <acpi/>
            <apic/>
            <vmport state='off'/>
          </features>
          <kvm>
            <hidden state='on'/>
          </kvm>
          <cpu mode='host-passthrough' check='partial'>
            <model fallback='allow'/>
            <feature policy='disable' name='hypervisor'/>
          </cpu>
          <clock offset='localtime'/>
          <on_poweroff>destroy</on_poweroff>
          <on_reboot>restart</on_reboot>
          <on_crash>destroy</on_crash>
          <devices>
            <emulator>/usr/bin/qemu-system-x86_64</emulator>

            <disk type="file" device="disk">
                <driver name="qemu" type="qcow2" discard="unmap"/>
                <source file="{os.getcwd()}/{disk_path}"/>
                <target dev="sda" bus="sata"/>
                <boot order="1"/>
                <address type="drive" controller="0" bus="0" target="0" unit="0"/>
            </disk>

            <disk type="file" device="cdrom">
                <driver name="qemu" type="raw"/>
                <source file="{iso_path}"/>
                <target dev="sdb" bus="sata"/>
                <readonly/>
                <boot order="2"/>
                <address type="drive" controller="0" bus="0" target="0" unit="1"/>
            </disk>

            <interface type='network'>
              <source network='{network_name}'/>
              <model type='e1000e'/>
            </interface>
            <input type='tablet' bus='usb'/>
            <graphics type='vnc' port='5901' listen='0.0.0.0' autoport='no' sharePolicy='ignore'/>
            <video>
              <model type='virtio' vram='16384' heads='1'/>
            </video>
            <memballoon model='virtio'/>

          </devices>
        </domain>"""
        try:
            dom = self.conn.defineXML(xml)
            if dom is None:
                print("Failed to define the domain.")
                return False
            if dom.create() < 0:
                print("Failed to start the domain.")
                return False
            print(f"VM {vm_name} created and started successfully.")
            self.vnc_thread = threading.Thread(
                target=subprocess.run, args=(["vncviewer", f"localhost:5901"],)
            )
            self.vnc_thread.start()
            host_ip = self.get_host_ip(os_type)
            lib.webserver.srv_ip = host_ip
            lib.webserver.setupwin_cmd = lib.webserver.setupwin_cmd.replace(
                b"localhost", host_ip.encode()
            )
            return f"""
            Now, you need to install the OS manually.
            After the installation is complete, press Win+R and run:
            {lib.webserver.setupwin_cmd.decode()}

            (To get the command to copy, go to: http://{host_ip}:8000/inst_win_cmd)
            This will run the script from the host webserver as administrator inside the VM.
            """
        except libvirt.libvirtError as e:
            print(f"Libvirt error: {e}")
            return False
        except subprocess.CalledProcessError as e:
            print(f"Subprocess error: {e}")
            return False

    def uninstall_vm(self, os_type):
        vm_name = f"{os_type}_openrunvm"
        try:
            dom = self.conn.lookupByName(vm_name)
            if dom is None:
                print(f"VM {vm_name} not found.")
                return False
            dom.destroy()
            dom.undefine()

            print(f"VM {vm_name} uninstalled successfully.")
            return True
        except libvirt.libvirtError as e:
            print(f"Libvirt error: {e}")
            return False

    def stop_vm(self, os_type):
        vm_name = f"{os_type}_openrunvm"
        try:
            dom = self.conn.lookupByName(vm_name)
            if dom is None:
                print(f"VM {vm_name} not found.")
                return False
            if not dom.isActive():
                print(f"VM {vm_name} is not running.")
                return False
            dom.shutdown()
            print(f"VM {vm_name} stopped successfully.")
            return True
        except libvirt.libvirtError as e:
            print(f"Libvirt error: {e}")
            return False

    def restore_snapshot(self, os_type):
        vm_name = f"{os_type}_openrunvm"
        try:
            dom = self.conn.lookupByName(vm_name)
            if dom is None:
                print(f"VM {vm_name} not found.")
                return False
            snapshot = dom.snapshotLookupByName(f"{vm_name}_clean")
            if snapshot is None:
                print(f"Snapshot for VM {vm_name} not found.")
                return False
            dom.revertToSnapshot(snapshot)
            print(f"VM {vm_name} restored to snapshot successfully.")
            return True
        except libvirt.libvirtError as e:
            print(f"Libvirt error: {e}")
            return False

    def run_vm(self, os_type: Literal["win11", "win10"], zip_path: str):
        self.restore_snapshot(os_type)  # Restore snapshot before running
        self.create_or_resume_network(os_type)
        vm_name = f"{os_type}_openrunvm"
        host_ip = self.get_host_ip(os_type)
        lib.webserver.srv_ip = host_ip
        lib.webserver.setupwin_cmd = lib.webserver.setupwin_cmd.replace(
            b"localhost", host_ip.encode()
        )

        try:
            dom = self.conn.lookupByName(vm_name)
            if dom is None:
                print(f"VM {vm_name} not found.")
                return False
            if not dom.isActive():
                print(f"VM {vm_name} is not running. Starting it now...")
                dom.create()
            # dom.resume()
            lib.webserver.is_session_active = True
            lib.webserver.session = uuid.uuid4()
            print(f"VM {vm_name} resumed successfully.")
            if not self.vnc_thread or not self.vnc_thread.is_alive():
                self.vnc_thread = threading.Thread(
                    target=subprocess.run, args=(["vncviewer", f"localhost:5901"],)
                )
                self.vnc_thread.start()
            return True
        except libvirt.libvirtError as e:
            print(f"Libvirt error: {e}")
            return False

    def only_run_vm(self, os_type: Literal["win11", "win10"]):
        vm_name = f"{os_type}_openrunvm"

        try:
            dom = self.conn.lookupByName(vm_name)
            if dom is None:
                print(f"VM {vm_name} not found.")
                return False
            if not dom.isActive():
                print(f"VM {vm_name} is not running. Starting it now...")
                dom.create()
            # dom.resume()
            print(f"VM {vm_name} resumed successfully.")
            if not self.vnc_thread or not self.vnc_thread.is_alive():
                self.vnc_thread = threading.Thread(
                    target=subprocess.run, args=(["vncviewer", f"localhost:5901"],)
                )
                self.vnc_thread.start()
            host_ip = self.get_host_ip(os_type)
            print(f"Host IP for {vm_name}: {host_ip}")
            lib.webserver.srv_ip = host_ip
            lib.webserver.setupwin_cmd = lib.webserver.setupwin_cmd.replace(
                b"localhost", host_ip.encode()
            )
            return True
        except libvirt.libvirtError as e:
            print(f"Libvirt error: {e}")
            return False
