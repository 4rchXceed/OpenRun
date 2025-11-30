# Install

## WORKS ONLY ON LINUX

## Prerequisites

Make sure you have python3 and git installed on your system.

Because we're using virtual machines, you also need KVM, qemu, libvirt, and virt-manager. 
You also need iptables, which is usually pre-installed on most Linux distributions.
(I won't include iptables installation instructions here, as they may break docker if you don't install the correct version of iptables for your system.)
You can install them using your package manager. For example, on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager
```

Arch Linux btw:
```bash
sudo pacman -Syu qemu libvirt virt-manager
```

(The script will interact with libvirt, so you can use other hypervisors than qemu, but qemu is the only one tested.)

## Clone the repository

```bash
git clone https://github.com/4rchXceed/OpenRun.git
cd OpenRun
```

## Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Install dependencies

```bash
pip install -r requirements.txt
```

## Configure the network security

!! DO NOT SKIP THIS STEP !!
Run the setup_fw.sh script with superuser privileges to configure the firewall rules:

```bash
sudo bash setup_fw.sh
```

You will be prompted to enter your WAN interface name and the VM network base address.
For the WAN name, you can find it by running `ip a` and looking for the interface connected to the internet (usually something like eth0, wlan0, enp3s0, wlo1, etc.).
For the VM network base address, you can usually leave it as the default (192.168.222.0). YOU NEED TO REMEMBER THIS ADDRESS FOR LATER.

!! IMPORTANT STEP TO HAVE INTERNET ACCESS IN THE VM !!
You need to edit the file: /etc/libvirt/network.conf and add the following line at the end of the file:

```bash
firewall_backend = "iptables"
```

Then restart libvirt:

```bash
sudo systemctl restart libvirtd
```

## Get a Windows 10/11 ISO

### !! I only tested with Windows 10 !!
You need a Windows 10 ISO.
You can download it from the official Microsoft website: https://www.microsoft.com/en-us/software-download/windows10ISO

## Run the program

```bash
python3 main.py
```

## Config the install

1. Choose if you are installing Windows 10 or Windows 11.
2. Paste the absolute path to the Windows ISO you downloaded earlier. (e.g., /home/user/Downloads/Win10_21H2_English_x64.iso) into "ISO file path".
3. Write a custom IP address or leave it blank to use the default one (192.168.222.1). Make sure the IP address is in the same subnet as the one you set in the firewall setup step (e.g., 192.168.222.x).
4. Click on "Setup VM".

## Install Windows

Normally, 1-2 seconds after clicking "Setup VM", a new window should pop up with the virtual machine running. (it does not capture some shortcuts, so be careful)

Follow the Windows installation process in the virtual machine window that appears. (No need for a product key, you can skip that step.), choose the Pro version when prompted.

! Do NOT choose a password you are using, as this is for malware analysis purposes.

## Check Internet Connection

During my tests, I often found that the VM did not have internet access by default. To fix this, follow these steps:
1. Win+R, type "ncpa.cpl", and press Enter.
2. Right-click on the "Ethernet" adapter and select "Properties".
3. Select "Internet Protocol Version 4 (TCP/IPv4)" and click "Properties
4. Select "Use the following IP address" and enter the following details:
   - IP address:
        - If you used the default IP (192.168.222.1), enter 192.168.222.2
        - If you used a custom IP, enter the same IP but with the last octet incremented by 1
   - Subnet mask: 255.255.255.0
   - Default gateway: 192.168.222.1 if you used the default IP, otherwise use the custom IP you set earlier.
5. Select "Use the following DNS server addresses" and enter:
   - Preferred DNS server: (1.1.1.1, 8.8.8.8)
6. Click "OK" to save the settings.

## Install OpenRun Sniffer Service

1. Once Windows is installed and running, you can close the virtual machine window.
2. In the main OpenRun browser window, select the win10/11 VM from the dropdown menu.
3. Click on "Install VM Script".
4. A new VM window should pop up. You need to go to: http://<the-ip-you-set-earlier>:8000/inst_win_cmd in the VM browser, copy the command shown on that page. the-ip-you-set-earlier is the IP address you configured (e.g., 192.168.222.1)
5. Win+R, type "powershell", and press Enter.
6. Paste the command you copied earlier into the PowerShell window and press Enter.
7. Allow the script to run with admin privileges when prompted.
8. A popup will appear, click "Ok".
9. Install mitmproxy when prompted by the script. !!! Leave all other options as default.
11. Authorize network access for mitmproxy when prompted.
10. If a new window pops up (and after allowing network access), close it.
11. Normally, the script will finish and the PowerShell window will close automatically. You can see some requests on the openrun cli output.
12. Close the VM window.

## Finish installation
1. In the main OpenRun browser window, click on "Finish Install (Backup)". -> This will create a snapshot of the VM in its current state.

## Try it out!

1. Prepare a .zip file containing the malware sample(s) you want to analyze.
2. In the main OpenRun browser window, select the win10/11 VM from the dropdown menu.
3. Click on Choose File and select the .zip file you prepared earlier.
4. Click on "Run VM".
5. A new VM window should pop up. The malware samples will be automatically extracted and executed inside the VM, in Desktop\temp\ directory.
6. There are some errors shown in the OpenRun CLI output, but they can be ignored for now. (I will fix them later.)

## Stop the VM

1. In the main OpenRun browser window, click on "Stop VM".
2. Close the VM window.

## Troubleshooting
- If, when you open a browser, you get a certificate warning, follow these steps to reset the certificate:
   - Open C:\Windows\System32\config\systemprofile
   - Open the .mitmproxy directory
   - Right-click on the mitmproxy-ca-cert.cert file and select "Install PFX".
   - Choose to install it for the Local Machine.
   - Leave everything as default, until you reach the "Certificate Store" step.
   - Select "Place all certificates in the following store" and click "Browse".
   - Select "Trusted Root Certification Authorities" and click "OK".
   - Click "Next" and then "Finish".

## Setting up AI-Mode (optional)

See [USAGE.md](USAGE.md) section: AI Mode -> Installation of the AI-Mode for more information.



See [USAGE.md](USAGE.md) for more information on how to use OpenRun.
