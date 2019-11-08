#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#define ETH_HDR_LEN 18
/* Quantum is the number of intervals per second to use when attempting to reach a certain packet rate per second */
#define QUANTUM 1000
extern int errno;
void print_usage() {
	printf("Usage: dpt <DESTINATION> -s SOURCE_ADDRESS -P DESTINATION_PORT -p PROTOCOL -l BYTE_LENGTH -f NUMBER OF FLOWS -q TOS -d DURATION -t TTL -r PPS Rate\n");
}
enum proto_int {
	ICMP=1,
	IPIP=4,
	TCP=6,
	UDP=17,
	GRE=47,
	AUGGIENET=255
};
struct datagram_node {
	char *datagram;   
	struct datagram_node *next;
	struct datagram_node *prev;
};	
struct grehdr {
	uint16_t flags;
	uint16_t proto;
};
struct udp_pseudo_hdr {
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t length;
	uint16_t source_port;
	uint16_t destination_port;
	uint16_t proto_length;
	uint16_t check;
	char *data;
};
struct tcp_pseudo_hdr {
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t reserved;
	uint8_t protocol;
	uint16_t length;
	uint16_t source_port;
	uint16_t destination_port;
	uint32_t seq;
	uint32_t ack_seq;
	/* Little endian */
	unsigned res:4;
	unsigned doff:4;
	unsigned fin:1;
	unsigned syn:1;
	unsigned rst:1;
	unsigned psh:1;
	unsigned ack:1;
	unsigned urg:1;
	unsigned ece:1;
	unsigned cwr:1;
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
	char *data;
};
struct aughdr {
	/* auggie_net - proto 255.  An innovative, synergy-driven, hyper-converged application-centric enterprise protocol. */
	/* A more elegant protocol for a more civilized age */
	uint32_t msg_id;
	uint32_t timestamp;
	uint16_t length;
	char *data;
};
unsigned short csum(unsigned short *ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;
	sum = 0;
	while(nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if(nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}
	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer = (short) ~sum;
	return (answer);
};
void append_datagram_node(struct datagram_node **head, char *datagram) {
	struct datagram_node *new_datagram_node = (struct datagram_node *)malloc(sizeof(struct datagram_node));
	struct datagram_node *last = *head;
	new_datagram_node->datagram = datagram;
	new_datagram_node->next = NULL;
	if(*head == NULL) {
		new_datagram_node->prev = NULL;
		*head = new_datagram_node;
		return;
	}
	while(last->next != NULL) {
		last = last->next;
	}
	last->next = new_datagram_node;
	new_datagram_node->prev = last;
	return;
}
void pad_data(uint8_t header_len, uint16_t packet_size, char **data, char **strdata) {
	if(packet_size >= (64)) {
		packet_size -= (header_len + ETH_HDR_LEN);
		(*strdata) = malloc(packet_size + 1);
		memset((*strdata), 'X', packet_size);
		strcpy((*data), (*strdata));
	}
};
void set_udp_phdr(struct udp_pseudo_hdr **upsh, struct iphdr *iph, uint16_t source_port, uint16_t dest_port, char *data, char *pseudogram) {
	(*upsh)->source_address = iph->saddr;
	(*upsh)->dest_address = iph->daddr;
	(*upsh)->placeholder = 0;
	(*upsh)->protocol = 17;
	(*upsh)->check = 0;
	(*upsh)->source_port = htons(source_port);
	(*upsh)->destination_port = htons(dest_port);
	(*upsh)->length = htons(sizeof(struct udphdr));
	(*upsh)->proto_length = htons(sizeof(struct udphdr));
	(*upsh)->length = htons(sizeof(struct udphdr) + strlen(data));
	(*upsh)->proto_length = htons(sizeof(struct udphdr) + strlen(data));
	(*upsh)->data = pseudogram + sizeof(struct udp_pseudo_hdr);
	memcpy(&(*upsh)->data,data,strlen(data));
};
uint64_t usend(struct datagram_node *head, uint16_t send_size, uint16_t duration, int socket, struct sockaddr *sin, int sin_size) {
	uint64_t diff_time = 0;
	uint64_t total_packets_sent = 0;
	struct timespec start, current;
	uint64_t usec_duration = duration * 1000000;
	int errnum;
	struct datagram_node *node_to_send = head;
	clock_gettime(CLOCK_MONOTONIC_RAW,&start);
	clock_gettime(CLOCK_MONOTONIC_RAW,&current);
	while(diff_time < usec_duration) {
		if(sendto(socket, node_to_send->datagram, send_size, MSG_NOSIGNAL | MSG_DONTWAIT, sin, sin_size) < 0) {
			errnum = errno;
			if(errnum != 11) {
				/* Don't exit if socket would block/be unavailable - just try again */
				fprintf(stderr,"Failed to sendto packet: %s\n", strerror(errnum));
				exit(EXIT_FAILURE);
			} else {
				total_packets_sent--;
			}
		}
		total_packets_sent++;
		if(total_packets_sent % 1000 == 0) {
			clock_gettime(CLOCK_MONOTONIC_RAW,&current);
		}
		diff_time = (current.tv_sec - start.tv_sec) * 1000000 + (current.tv_nsec - start.tv_nsec) / 1000;
		/* Advance the pointer, tail already has next pointer set to head */
		node_to_send = node_to_send->next;
	}
	return total_packets_sent;

};
uint64_t rsend(struct datagram_node *head, uint16_t send_size, uint16_t duration, uint32_t packet_rate, int socket, struct sockaddr *sin, int sin_size) {
	uint64_t diff_time = 0;
	uint64_t total_packets_sent = 0;
	struct timespec start, current, rate_quantum_start, rate_quantum_current;
	uint64_t usec_duration = duration * 1000000;
	int packet_per_quantum = (packet_rate / QUANTUM);
	int packet_rate_bucket = packet_per_quantum;
	int errnum;
	struct datagram_node *node_to_send = head;
	clock_gettime(CLOCK_MONOTONIC_RAW,&start);
	clock_gettime(CLOCK_MONOTONIC_RAW,&current);
	clock_gettime(CLOCK_MONOTONIC_RAW,&rate_quantum_start);
	clock_gettime(CLOCK_MONOTONIC_RAW,&rate_quantum_current);
	while(diff_time < usec_duration) {
		/* User defined packet rate - define a bucket of packets to send per quantum, send so long as the bucket is non-zero, and refill the bucket every quantum */
		if(packet_rate_bucket > 0) {
			if(sendto(socket, node_to_send->datagram, send_size, MSG_NOSIGNAL | MSG_DONTWAIT, sin, sin_size) < 0) {
				errnum = errno;
				if(errnum != 11) {
					/* Don't exit if socket would block/be unavailable - just try again */
					fprintf(stderr,"Failed to sendto packet: %s\n", strerror(errnum));
					exit(EXIT_FAILURE);
				} else {
					total_packets_sent--;
					packet_rate_bucket++;
				}
			}
			total_packets_sent++;
			packet_rate_bucket--;
		}
		if(total_packets_sent % (QUANTUM / 100) == 0) {
			clock_gettime(CLOCK_MONOTONIC_RAW,&rate_quantum_current);
		}
		/* Sample 1000 times a second */
		if(((rate_quantum_current.tv_sec - rate_quantum_start.tv_sec) * 1000000 + (rate_quantum_current.tv_nsec - rate_quantum_start.tv_nsec) / 1000) >= QUANTUM) {
			packet_rate_bucket = packet_per_quantum;
			clock_gettime(CLOCK_MONOTONIC_RAW,&rate_quantum_start);
		}
		if(total_packets_sent % 1000 == 0) {
			clock_gettime(CLOCK_MONOTONIC_RAW,&current);
		}
		diff_time = (current.tv_sec - start.tv_sec) * 1000000 + (current.tv_nsec - start.tv_nsec) / 1000;
		/* Advance the pointer, tail already has next pointer set to head */
		node_to_send = node_to_send->next;
	}
	return total_packets_sent;

};
char* create_udp_packet(uint8_t protocol, uint8_t ttl, uint8_t tos, char *daddr, char *saddr, uint16_t src_port, uint16_t dst_port, uint16_t packet_size) {
	uint16_t header_len = (sizeof(struct iphdr) + sizeof(struct udphdr));
	uint16_t byte_size = header_len + (packet_size - 64);
	char *datagram, *pseudogram, *data, *strdata;
	datagram = malloc(byte_size);
	pseudogram = malloc(byte_size);
	memset(datagram,0,byte_size);
	memset(pseudogram,0,byte_size);
	struct iphdr *iph = (struct iphdr *) datagram;
	struct udp_pseudo_hdr *upsh;
	struct udphdr *udph;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = tos;
	iph->protocol = protocol;
	iph->frag_off = 0;
	iph->ttl = ttl;
	iph->saddr = inet_addr(saddr);
	iph->daddr = inet_addr(daddr);

	udph = (struct udphdr *) (datagram + sizeof(struct iphdr));
	data = datagram + header_len;
	pad_data(header_len, packet_size, &data, &strdata);
	uint16_t data_len = strlen(data);
	/* Set IP length - inclusive of all encapsulated data */
	iph->tot_len = header_len + data_len;
	udph->dest = htons(dst_port);
	udph->len = htons(sizeof(struct udphdr) + data_len);
	udph->source = htons(src_port);

	upsh = (struct udp_pseudo_hdr *) pseudogram;
	set_udp_phdr(&upsh, iph, src_port, dst_port, data, pseudogram);
	udph->check = csum((unsigned short*)upsh , sizeof(struct udp_pseudo_hdr) + data_len);
	return datagram;
};
char* create_gre_packet(uint8_t protocol, uint8_t ttl, uint8_t tos, char *daddr, char *saddr, uint16_t src_port, uint16_t dst_port, uint16_t packet_size) {
	uint16_t header_len = sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
	uint16_t byte_size = header_len + (packet_size - 64);
	char *datagram, *pseudogram, *data, *strdata;
	datagram = malloc(byte_size);
	pseudogram = malloc(byte_size);
	memset(datagram,0,byte_size);
	memset(pseudogram,0,byte_size);

	struct iphdr *iph = (struct iphdr *) datagram;
	struct grehdr *greh = (struct grehdr *) (datagram + sizeof(struct iphdr));
	struct iphdr *iph_inner = (struct iphdr *) (datagram + sizeof(struct iphdr) + sizeof(struct grehdr));
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr));
	struct udp_pseudo_hdr *upsh;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = tos;
	iph->protocol = protocol;
	iph->frag_off = 0;
	iph->ttl = ttl;
	iph->saddr = inet_addr(saddr);
	iph->daddr = inet_addr(daddr);

	/* GRE and inner IP headers */
	greh->flags = htons(0);
	greh->proto = htons(2048);

	iph_inner->ihl = 5;
	iph_inner->version = 4;
	iph_inner->tos = 0;

	/* Inner IP protocol should be UDP */
	iph_inner->protocol = 17;
	iph_inner->frag_off = 0;
	iph_inner->ttl = ttl;
	iph_inner->saddr = inet_addr(saddr);
	iph_inner->daddr = inet_addr(daddr);
	data = datagram + header_len;
	pad_data((sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr)), packet_size, &data, &strdata);
	uint16_t data_len = strlen(data);
	/* Set IP length - inclusive of all encapsulated data */
	iph_inner->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
	iph->tot_len = header_len + data_len;
	/* No kernel/hardware assistance for encapsulated IP header checksums - do it manually */
	iph_inner->check = csum((unsigned short*)iph_inner, sizeof(struct iphdr));

	udph->dest = htons(dst_port);
	udph->len = htons(sizeof(struct udphdr) + data_len);
	udph->source = htons(src_port);

	upsh = (struct udp_pseudo_hdr *) pseudogram;
	set_udp_phdr(&upsh, iph, src_port, dst_port, data, pseudogram);
	udph->check = csum((unsigned short*)upsh , sizeof(struct udp_pseudo_hdr) + data_len);
	return datagram;
};
int main(int argc, char *argv[]) {
	uint8_t protocol = 0;
	uint16_t packet_size = 0;
	uint16_t num_flows = 1;
	int option = 0;
	uint8_t tos;
	uint8_t ttl = 255;
	uint16_t duration = 10;
	uint32_t packet_rate = 0;
	char* destination;
	char* source;
	uint16_t destination_port = 1985;
	while((option = getopt(argc, argv, "s:p:P:l:f:q:d:r:t:h:")) != -1) {
		switch(option) {
			case 's':
				source = optarg;
				break;
			case 'p':
				protocol = atoi(optarg);
				break;
			case 'P':
				if(atoi(optarg) <= 65535 && atoi(optarg) >= 1) {
					destination_port = atoi(optarg);
				} else {
					fprintf(stderr,"Destination port must be between 1 and 65535\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'l':
				if(atoi(optarg) <= 1500 && atoi(optarg) >= 64) {
					packet_size = atoi(optarg);
				} else {
					fprintf(stderr,"Packet size must be between 64 and 1500 bytes\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'f':
				if(atoi(optarg) <= 16384 && atoi(optarg) >= 1) {
					num_flows = atoi(optarg);
				} else {
					fprintf(stderr,"Maximum flows supported: 16384\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'q':
				tos = atoi(optarg);
				break;
			case 'd':
				duration = atoi(optarg);
				break;
			case 'r':
				if(atoi(optarg) <= 1000000 && atoi(optarg) >= 1000 && (atoi(optarg) % 10000 == 0)){
					packet_rate = atoi(optarg);
				} else {
					fprintf(stderr,"Packet rate must be between 10000 and 1000000 packets/sec, and in increments of 10000\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 't':
				if(atoi(optarg) <= 255 && atoi(optarg) > 0) {
					ttl = atoi(optarg);
				} else {
					fprintf(stderr,"TTL Must be between 1 and 255");
					exit(EXIT_FAILURE);
				}
				break;
			case 'h':
				print_usage();
				exit(EXIT_SUCCESS);
			default: print_usage();
				 exit(EXIT_FAILURE);
		}
	}
	if(argc < 2) {
		print_usage();
		exit(EXIT_FAILURE);
	}
	destination = argv[argc - 1];
	printf("Targeting: %s\nSource: %s\nProtocol: %d\nDestination Port: %d\nPacket Size: %d\nFlow Count: %d\nDuration: %d\nPacket Rate: %d KPPS\n",
			destination, source, protocol, destination_port, packet_size, num_flows, duration, (packet_rate/1000));

	uint64_t total_packets_sent = 0;
	uint16_t send_size = 0;
	int errnum;
	struct sockaddr_in sin;
	uint16_t sin_size = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(1024);
	sin.sin_addr.s_addr = inet_addr(destination);
	uint16_t dst_port = destination_port;
	uint16_t src_port = 1024;
	uint16_t iterator = 0;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		errnum = errno;
		fprintf(stderr,"Failed to create socket: %s\n",strerror(errnum));
		exit(EXIT_FAILURE);
	}
	uint8_t sockflag = 1;
	const uint8_t *val = &sockflag;
	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (1)) < 0) {
		errnum = errno;
		fprintf(stderr,"Error setting IP_HDRINCL: %s\n",strerror(errnum));
		exit(EXIT_FAILURE);
	}
	struct datagram_node *head = NULL;
	struct datagram_node *tail = NULL;
	switch(protocol){
		case UDP:
			send_size = sizeof(struct iphdr) + sizeof(struct udphdr) + (packet_size - 64);
			for(iterator = 0;iterator < num_flows;iterator++) {
				char *datagram = create_udp_packet(protocol,ttl,tos,destination,source,src_port,dst_port,packet_size);
				append_datagram_node(&head,datagram);
				src_port++;
			}

			break;
		case GRE:
			send_size = sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + (packet_size - 64);
			for(iterator = 0;iterator < num_flows;iterator++) {
				char *datagram = create_gre_packet(protocol,ttl,tos,destination,source,src_port,dst_port,packet_size);
				append_datagram_node(&head,datagram);
				src_port++;
			}
			break;
			/*
			   case IPIP:
			   header_len = sizeof(struct iphdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
			   data = datagram + header_len;;

			   pad_data((sizeof(struct iphdr) + sizeof(struct udphdr)), packet_size, &data, &strdata);
			   data_len = strlen(data);
			   printf("Size of data: %d\n", data_len);
			   iph_inner = (struct iphdr *) (datagram + sizeof(struct iphdr));

			   iph_inner->ihl = 5;
			   iph_inner->version = 4;
			   iph_inner->tos = 0;

			   iph_inner->protocol = 17;
			   iph_inner->frag_off = 0;
			   iph_inner->ttl = ttl;
			   iph_inner->saddr = inet_addr(source);
			   iph_inner->daddr = inet_addr(destination);
			   iph->protocol = 4;

			   udph = (struct udphdr *) (datagram + sizeof(struct iphdr) + sizeof(struct iphdr));

			   iph->tot_len = header_len + data_len;
			   iph_inner->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);

			   iph_inner->check = csum((unsigned short*)iph_inner, sizeof(struct iphdr));
			   udph->dest = htons(destination_port);
			   udph->len = htons(sizeof(struct udphdr) + data_len);
			   udph->source = htons(initial_source_port);

			   upsh = (struct udp_pseudo_hdr *) pseudogram;
			   set_udp_phdr(&upsh, iph, initial_source_port, destination_port, data, pseudogram);
			   total_packets_sent = nsend(duration, packet_rate, datagram, (iph->tot_len), num_flows, data_len, sock, (struct sockaddr *)&sin, current_source_port, initial_source_port, sin_size, upsh, udph);
			   break;
			   case AUGGIENET:
			   fprintf(stderr,"Hold those horses - auggienet is not currently supported.  Good things take time :).\n");
			   exit(EXIT_FAILURE);
			   header_len = sizeof(struct iphdr) + sizeof(struct aughdr);
			   data = datagram + header_len;;
			   pad_data((sizeof(struct iphdr) + sizeof(struct udphdr)), packet_size, &data, &strdata);
			   data_len = strlen(data);
			   augh = (struct aughdr *) (datagram + sizeof(struct iphdr));
			   augh->msg_id = 1;
			   augh->timestamp = 1;
			   augh->length = sizeof(struct aughdr) + data_len;
			   augh->data = data;

			   iph->tot_len = header_len + data_len;
			   total_packets_sent = nsend(duration, packet_rate, datagram, (iph->tot_len), num_flows, data_len, sock, (struct sockaddr *)&sin, current_source_port, initial_source_port, sin_size, upsh,udph );
			   break;
			   */
		default:
			fprintf(stderr,"Protocol number not supported");
			exit(EXIT_FAILURE);
	}
	tail = head;
	while(tail->next != NULL) {
		tail = tail->next;
	}
	/* Set tail->next to head so we can loop through the linked list repeatedly */
	if(tail->next == NULL) {
		tail->next = head;
	}
	if(packet_rate == 0) {
		total_packets_sent = usend(head,send_size,duration,sock,(struct sockaddr *)&sin,sin_size);
	} else {
		total_packets_sent = rsend(head,send_size,duration,packet_rate,sock,(struct sockaddr *)&sin,sin_size);
	}
	printf("%lu packets sent in %d seconds\n",total_packets_sent,duration);
	exit(EXIT_SUCCESS);
}
