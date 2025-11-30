#!/bin/bash
read -p "Enter the name of your WAN interface (e.g., eth0, wlan0): " WAN
read -p "Enter the VM network base address (e.g., 192.168.222.0): " VM_NET_BASE
VM_NET="$VM_NET_BASE/24"
VM_HOST=$(echo $VM_NET_BASE | sed 's/0$/1/')

echo "Settings: "
echo "WAN Interface: $WAN"
echo "VM Network: $VM_NET"
echo "VM Host IP: $VM_HOST"

read -p "Press Enter to continue with these settings... Press Ctrl+C to abort."

echo "Enabling IP forwarding..."
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

sudo iptables -N OPENRUN0_FILTER 2>/dev/null || sudo iptables -F OPENRUN0_FILTER
sudo iptables -N OPENRUN0_FORWARD 2>/dev/null || sudo iptables -F OPENRUN0_FORWARD

# Allow established connections
sudo iptables -A OPENRUN0_FILTER -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specific host ports if needed
sudo iptables -A OPENRUN0_FILTER -p tcp --dport 8000 -j ACCEPT

# Default DROP anything else to host
sudo iptables -A OPENRUN0_FILTER -j DROP

# Drop private LANs first
sudo iptables -A OPENRUN0_FORWARD -s $VM_NET -d 10.0.0.0/8 -j DROP
sudo iptables -A OPENRUN0_FORWARD -s $VM_NET -d 172.16.0.0/12 -j DROP
sudo iptables -A OPENRUN0_FORWARD -s $VM_NET -d 192.168.0.0/16 -j DROP

# Allow the VM network to forward (internet) 
sudo iptables -A OPENRUN0_FORWARD -s $VM_NET -j ACCEPT

# Allow established/related return traffic
sudo iptables -A OPENRUN0_FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Default DROP
sudo iptables -A OPENRUN0_FORWARD -j DROP

sudo iptables -I INPUT   -i openrun0 -j OPENRUN0_FILTER
sudo iptables -I FORWARD -i openrun0 -j OPENRUN0_FORWARD
sudo iptables -I FORWARD -o openrun0 -j OPENRUN0_FORWARD

sudo iptables -t nat -A POSTROUTING -s $VM_NET -o $WAN -j MASQUERADE

sudo iptables-save | sudo tee /etc/iptables/rules.v4

echo "Firewall and NAT rules for OpenRun0 have been successfully applied."
