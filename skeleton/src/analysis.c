#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>                                                                                                                                         
#include <signal.h>
#include <pthread.h>
/* In order to print a report, all count variables must be global so that each individual call to analyse can update a global count*/
unsigned int volatile cnt_xmasscan = 0; //Counts for xmas scan, arp cache poisoning and blacklisted urls along with a count for total number of packets.
unsigned int volatile cnt_arppois = 0;
unsigned int volatile cnt_blacklisturl = 0;
unsigned int volatile cnt_pkts = 0;

pthread_mutex_t muxlock2 = PTHREAD_MUTEX_INITIALIZER; //Initializing a mutex lock for threading to ensure that the global counts return the correct values


/*The sig_handler function is used to catch any linux signals, in this case it is used when CTRL+C are pressed in order to print the intrusion report*/
void sig_handler(int signo){
 if (signo == SIGINT){
  pthread_mutex_lock(&muxlock2); //Mutex lock to ensure that the printed values are correct
  printf("\nIntrusion Detection Report:");
  printf("\n %d Xmas Scans (host fingerprinting)", cnt_xmasscan);
  printf("\n %d ARP responses (cache poisoning)", cnt_arppois);
  printf("\n %d URL Blacklist violations", cnt_blacklisturl);
  printf("\n %d Packet(s) Sniffed\n", cnt_pkts);
  pthread_mutex_unlock(&muxlock2);
  exit(EXIT_SUCCESS); //Once the report has been printed the process can exit
 }
}

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
  //This call to sig_handler implements it in the system kernal, allowing the above report to be printed. Valdiation is added in the case that the signal is not caught correctly
  if (signal(SIGINT, sig_handler) == SIG_ERR)
    printf("Can't catch SIGINT");
  
  //==Parsing pcap packet header==
  bpf_u_int32 caplen = header->caplen; //Total length of packet captures
  bpf_u_int32 pktlen = header->len; //Total length of packet
  struct timeval pktts = header->ts; //Timevalue of packet in seconds
  long timesec = pktts.tv_sec; 
  unsigned int i; //To be used in for loops
  
  
  //Input pcap packet header parsing
  /* To help with initial debugging the verbose tag was used to print all header information parsed to ensure the correct data was being parsed 
   In this statement the pcap packet header information is parsed and printed*/
  if (verbose == 1){
    printf("\nParsing PCAP Packet Header\n");
    printf("=====================\n");
    printf("Portion length: %lu \n", ntohl(caplen)); //ntohl is used as caplen is of size long
    printf("Packet length: %lu \n", ntohl(pktlen)); //Similar to above
    printf("Timestamp in secs: %ld \n", timesec);
  }
  
  //==Parsing Ethernet Header==
  /*The ethernet header is at the start of the packet and lasts 14 btyes*/
  struct ether_header * eth_header = (struct ether_header *) packet; //A pointer to the start of the packet
  unsigned short eth_type = ntohs(eth_header->ether_type); //Ethernet type or (ether_type) determines whether the packet is IPv4 (TCP/IP) or ARP
  
  //Verbose flag used to print out packet information, in this case the data contained within the ethernet header
  if (verbose == 1){
    printf("\n\nEthernet Header:");
    printf("\n================");
    printf("\nType: %hu", eth_type);
    printf("\nSource MAC: ");
    for (i = 0; i < 6; ++i){ //Converts the input source host array into a MAC address in readable format (FF:FF:FF:FF:FF:FF) by printing each element of the array in hexadecimal format
      printf("%02x", eth_header->ether_shost[i]);
      if (i < 5 ){
	printf(":");  
      }
    }
    printf("\nDestination MAC: "); 
    for (i = 0; i < 6; ++i){ //Similar to the input source host, the destination host is converted to readable format
      printf("%02x", eth_header->ether_dhost[i]);  
      if (i < 5)
	printf(":");
    }
  }
  /*The rest of the packet is determined by the ether_type data passed in the packet.
   In the case that ether_type is 0x0806, or 2054 in denary, the packet protocol is Address Resolution Protocol (ARP).
   Hence the next header is the ARP header.*/
  if (eth_type == 2054){
    
    pthread_mutex_lock(&muxlock2); //When the type is determined lock the mutex lock and increment the packet count
    cnt_pkts++;
    pthread_mutex_unlock(&muxlock2);//Unlock & continue
    
    /*To begin parsing the data for the next header the pointer must first be moved to the beginning of the next header.
     As the ethernet header is of length 14 bytes we can move the pointer forward 14 bytes (+ 14) and typecast the rest of the payload to the arphdr type
     to parse its data. This will only typecast the size of the arphdr structure and not the entire packet*/
    const unsigned char *arpheaderpayload = packet + 14; //Moving pointer to start of ARP header
    struct ether_arp * arphdr = (struct ether_arp *) arpheaderpayload; //Typecasting for arphdr structure
    
    //Similar to before a verbose flag is used when the header data is to be printed
    if (verbose == 1){
      printf("\n\nARP Header");
      printf("\n==========");
      printf("\nSource Hardware Address: ");
      for (i = 0; i < 6; ++i){ //Similar to the ether header the arp source hardware address is converted to hexadecimal format and printed
	printf("%02x", arphdr->arp_sha[i]);
	if (i < 5 )
	  printf(":"); 
      }
      printf("\nTarget Hardware Address: "); //As above but for the target hardware address
      for (i = 0; i < 6; ++i){
	printf("%02x", arphdr->arp_tha[i]);
	if (i < 5 )
	  printf(":"); 
      }
      printf("\nSource Protocol Address: "); //Again for the source protocol address but in integer format
      for (i = 0; i < 4; ++i){
	printf("%u", arphdr->arp_spa[i]);
	if (i < 3 )
	  printf("."); 
      }
      printf("\nTarget Protocol Address: "); //Again for the target protocol address but also in integer format
      for (i = 0; i < 4; ++i){
	printf("%u", arphdr->arp_tpa[i]);
	if (i < 3 )
	  printf(".");
      }
      printf("\nARP Operation: %hu", ntohs(arphdr->arp_op)); //This prints the ARP operation type, in the case that this value is 2 the packet is an ARP response
      
    }
    
    /*To detect if a packet is a potential ARP cache poisoning packet the ARP operation type can be inspected.
     If the ARP operation type is 2 then the packet is an ARP response and must be reported as a possible threat.
     In this case we increment the arp cache poisoning counter.*/
    if (ntohs(arphdr->arp_op) == 2){ 
      pthread_mutex_lock(&muxlock2); //Mutex lock to ensure thread safety
      cnt_arppois++;
      pthread_mutex_unlock(&muxlock2); //Unlock & continue
    }
  }
  
  //If the ether_type is 0x0800, or 2048, the packet protocol is IPv4 (TCP/IP) and the header following the ethernet header is the ip header
  if (eth_type == 2048){
    
    pthread_mutex_lock(&muxlock2); //Mutex lock to ensure thread safety
    cnt_pkts++; //Incrementing packet count
    pthread_mutex_unlock(&muxlock2); //Unlock & continue
    
    //==Parsing IP Header==
    /*Similar to the ARP header to parse the next header we must first move the pointer to the beginning of the header.
     * The next step is to create a structure for the header type before parsing it's elements.
     * As the ethernet header is always 14 bytes we can move the pointer 14 bytes forward and create the structure*/
    const unsigned char *datalinkpayload = packet + ETH_HLEN; //ETH_HLEN = 14, this moves the original pointer 14 bytes forward to the beginning of the ip header
    struct iphdr * iphdr = (struct iphdr *) datalinkpayload; //Creating the ip header structure
    
    /*The main data held within the ip header is the source and destination address, which both come in an unsigned long format (32 bits).
     * Each byte segment of the source and destination address is a segment of the ip address.*/
    unsigned int saddr = ntohl(iphdr->saddr); //network to host (long) as the source and destination address are of long int format
    unsigned int daddr = ntohl(iphdr->daddr);
    
    /* To parse the IP addresses from the IP header the 32 bits must be seperated into 4 bytes each representing a segment of the IP Address.
    In this case the last 8 bits will be the last segment, 2nd last 8 will be the 2nd last segment and so on. To ensure the pointer is adding 8 bits each step the segments are
    type cast as an unsigned char before being type cast back to an unsigned int in the print function.*/
    const unsigned char saddr4 = (saddr) & 0xFF; //Designating an unsigned char to the last 8 bits in the source address
    const unsigned char saddr3 = (saddr >> 8) & 0xFF;
    const unsigned char saddr2 = (saddr >> 16) & 0xFF;
    const unsigned char saddr1 = (saddr >> 24) & 0xFF;  
    if (verbose == 1){ //If the verbose flag is set print the source address
      printf("\n\nIP Header:");
      printf("\n==========");
      printf("\nSource Address: %u . %u . %u . %u", saddr1, saddr2, saddr3, saddr4);
    }
    //Repeating this process for the destination address
    const unsigned char daddr4 = (daddr) & 0xFF; //Designating an unsigned char to the last 8 bits in the destination address
    const unsigned char daddr3 = (daddr >> 8) & 0xFF;
    const unsigned char daddr2 = (daddr >> 16) & 0xFF;
    const unsigned char daddr1 = (daddr >> 24) & 0xFF;  
    
    if (verbose == 1){ //If the verbose flag is set print the destination address
      printf("\nDestination Address: %u . %u . %u . %u", daddr1, daddr2, daddr3, daddr4);
      printf("IP Header Length: %u", iphdr->ihl);
      printf("\n\n");
    }
   
    
    //==Parsing TCP Header==
    /*Similar to parsing the previous headers to parse the TCP header the pointer must be moved to the beginning of the next header.
     In the case of the ip header the size is not always constant. Fortunately the iphdr structure contains an element
     which indicates the size of the ip header in 4 byte words (ihl).
     This can be used to move the pointer to the beginning of the TCP header by multiplying it by 4 to convert it to single byte words.*/
    const unsigned char *networkpayload = packet + ETH_HLEN + 4*(iphdr->ihl); //Move pointer past ip header to beginning of tcp header
    struct tcphdr * tcphdr = (struct tcphdr *) networkpayload; //Create a tcp header structure
    
    //When verbose flag is set print all elements of the tcp header 
    if (verbose == 1){
      printf("\nTCP Header:");
      printf("\n============");
      printf("\nSource Port: %hu\n", ntohs(tcphdr->source));
      printf("Destination Port: %hu\n", ntohs(tcphdr->dest));
      printf("Urgent Flag: %u\n", tcphdr->urg); //These three flags can be used to indicate whether a packet is an xmas scan or not
      printf("Push Flag: %u\n", tcphdr->psh); //If all three are set (1) then the packet is an xmas scan
      printf("Finish Flag: %u\n", tcphdr->fin);
      printf("TCP Header Length: %u bytes\n", 4*(tcphdr->doff));
    }
    
    //If all three flags are set then the packet is an xmas scan packet and should be recorded as such
    if ((tcphdr->psh == 1) && (tcphdr->urg == 1) && (tcphdr->fin == 1)){
      pthread_mutex_lock(&muxlock2); //Mutex lock to ensure thread safety
      cnt_xmasscan++; //Increment xmas scan count
      pthread_mutex_unlock(&muxlock2); //Unlock & continue
    }
    
    /*To detect if a packet is an http request to a blacklisted website first the destination address must be inspected.
     * In the case that the destination port is 80 then the packet is an http request.
     * To check if it is being sent to a blacklisted URL a string comparison is used to see if the packet contains 'Host: <website url>'
     * In the case it does then the packet is for a blacklisted website and should be recorded as such.*/
    if (ntohs(tcphdr->dest)==80){ //Inspect destination port
      const unsigned char *payload = networkpayload + 4*(tcphdr->doff); //Packet - all headers = payload
      if (strstr(payload, "Host: www.bbc.co.uk") != NULL){ //String comparison to detect the http request for www.bbc.co.uk
	  pthread_mutex_lock(&muxlock2); //Mutex lock to ensure thread safety
	  cnt_blacklisturl++; //Increment blacklisted url count
	  pthread_mutex_unlock(&muxlock2); //Unlock & continue
      }
    }
  }
}
