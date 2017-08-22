#include <stdio.h>		
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>		/* To set non blocking on socket  */
#include <sys/socket.h>		/* Generic socket calls */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <stdarg.h>
#include <errno.h>
#include "headers.h"


static unsigned char dhopt_buff[500];
/* Pointers for all layer data structures */
struct vlan_eth_hdr *vlan_hg;
struct iphdr *iph_g = { 0 };
struct udphdr *uh_g = { 0 };
static struct arp_hdr *arp_hg;
static struct icmp_hdr *icmp_hg;
static unsigned char *dhopt_pointer_g;

/* DHCP packet, option buffer and size of option buffer */
static unsigned char dhcp_packet_send[1518];
static unsigned char dhcp_packet_recv[1518];
static u_int16_t dhcp_hdr_size = sizeof(struct dhcpv4_hdr);
static u_int32_t dhopt_size;
static struct sockaddr_ll ll = { 0 };	/* Socket address structure */
static int sock_packet;
static u_char arp_icmp_packet[1514] = { 0 };
static u_char arp_icmp_reply[1514] = { 0 };
static u_int16_t icmp_len = 0;
static int have_set_promisc;
static unsigned int lease_time;
u_char dmac[ETHER_ADDR_LEN];




static void read_options(int len);
static int check_packet(int pkt_type, int len);
static int map_all_layer_ptr(int pkt_type);



/*
 * Opens PF_PACKET socket and return error if socket
 * opens fails
 */

int open_socket()
{
	sock_packet = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock_packet < 0)
		return SOCKET_ERR;
	/* Set link layer parameters */
	ll.sll_family = AF_PACKET;
	ll.sll_protocol = htons(ETH_P_ALL);
	ll.sll_ifindex = iface; 
	ll.sll_hatype = ARPHRD_ETHER;
	ll.sll_pkttype = PACKET_OTHERHOST;
	ll.sll_halen = 6;

	bind(sock_packet, (struct sockaddr *)&ll, sizeof(struct sockaddr_ll));
	return 0;
}

/*
 * Sets the promiscous mode on the interface
 */
static int set_clear_promisc(int op) 
{
	struct ifreq ifr;

	if (!op && !have_set_promisc)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, iface_name);

	if (ioctl(sock_packet, SIOCGIFFLAGS, &ifr))
		goto error;

	if (op) {
		if ((ifr.ifr_flags & IFF_PROMISC)) {
			have_set_promisc = 0;
			return 0;
		}
		have_set_promisc = 1;
	}

	if (op)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~IFF_PROMISC;

	if (ioctl(sock_packet, SIOCSIFFLAGS, &ifr))
		goto error;

	return 0;

error:
	critical("Error on setting promisc: %m");
}

int set_promisc() 
{
	return set_clear_promisc(1);
}

int clear_promisc() 
{
	return set_clear_promisc(0);
}

/*
 * Get address from the interface
 */
u_int32_t get_interface_address()
{
	int status;
	struct ifreq ifr;

	strcpy(ifr.ifr_name, iface_name);
	ifr.ifr_addr.sa_family = AF_INET;
	status = ioctl(sock_packet, SIOCGIFADDR, &ifr);

	if(status < 0)
		critical("Error getting interface address: %m");

	return ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
}

/*
 * Sends DHCP packet on the socket. Packet type 
 * is passed as argument. Extended to send ARP and ICMP packets
 */
int send_packet(int pkt_type)
{
	int ret;
	switch (pkt_type) {
		case DHCP_MSGDISCOVER:
		case DHCP_MSGREQUEST:
		case DHCP_MSGRELEASE:
			ret = sendto(sock_packet,\
					dhcp_packet_send,\
					(l2_hdr_size + l3_hdr_size + l4_hdr_size + dhcp_hdr_size + dhopt_size),\
					0,\
					(struct sockaddr *) &ll,\
					sizeof(ll));
			break;

		case ARP_SEND:
			ret = sendto(sock_packet,\
					arp_icmp_reply,\
					60,\
					0,\
					(struct sockaddr *) &ll,\
					sizeof(ll));
			break;

		case ICMP_SEND:
			ret = sendto(sock_packet,\
					arp_icmp_reply,\
					(l2_hdr_size + l3_hdr_size + ICMP_H + icmp_len),\
					0,\
					(struct sockaddr *) &ll,\
					sizeof(ll));
			break;

		default:
			abort();
	}

	if(ret < 0)
		critical("Packet send failure: %m");

	if(pkt_type == DHCP_MSGDISCOVER) {
		if (!nagios_flag && !quiet) {
			printf("DHCP discover sent\t - ");
			printf("Client MAC : " ETH_F_FMT "\n", ETH_F_ARG(dhmac));
		}
	} else if (pkt_type == DHCP_MSGREQUEST) {
		if (!nagios_flag && !quiet) {
			printf("DHCP request sent\t - ");
			printf("Client MAC : " ETH_F_FMT "\n", ETH_F_ARG(dhmac));
		}
	} else if (pkt_type == DHCP_MSGRELEASE) { 
		if (!nagios_flag && !quiet) {
			printf("DHCP release sent\t - ");
			printf("Client MAC : " ETH_F_FMT "\n", ETH_F_ARG(dhmac));
		}
	}
	return 0;
}

/*
 * Receives DHCP packet. Packet type is passed as argument
 * Extended to recv ARP and ICMP packets
 */
int recv_packet(int pkt_type) 

{
	int ret, retval, chk_pkt_state;
	socklen_t sock_len;
	fd_set read_fd;
	struct timeval tval, *tvp;
	int timeout_rv, recv_len;
	unsigned char *recv_buf;

	tval.tv_sec = 5; 
	tval.tv_usec = 0;
	tvp = &tval;

	switch (pkt_type) {
		case DHCP_MSGOFFER:
			timeout_rv = DHCP_DISC_RESEND;
			recv_buf = dhcp_packet_recv;
			recv_len = sizeof(dhcp_packet_recv);
			break;
		case DHCP_MSGACK:
			timeout_rv = DHCP_REQ_RESEND;
			recv_buf = dhcp_packet_recv;
			recv_len = sizeof(dhcp_packet_recv);
			break;
		case ARP_ICMP_RCV:
			tvp = &tval_listen;
			timeout_rv = LISTEN_TIMEOUT;
			recv_buf = arp_icmp_packet;
			recv_len = sizeof(arp_icmp_packet);
			break;
		default:
			abort();
	}

	while(tvp->tv_sec != 0) {
		FD_ZERO(&read_fd);
		FD_SET(sock_packet, &read_fd);
		retval = select(sock_packet + 1, &read_fd, NULL, NULL, tvp);
		if (retval == 0)
			return timeout_rv;
		if (retval < 0)
			abort();

		sock_len = sizeof(ll);
		ret = recvfrom(sock_packet,
				recv_buf,
				recv_len,
				0,
				(struct sockaddr *)&ll,
				&sock_len);

		if (ret < 0)
			return timeout_rv;

		chk_pkt_state = check_packet(pkt_type, ret);

		switch (chk_pkt_state) {
			case DHCP_OFFR_RCVD:
			case DHCP_ACK_RCVD:
			case DHCP_NAK_RCVD:
			case ARP_RCVD:
			case ICMP_RCVD:
				return chk_pkt_state;
		}
	}
	return timeout_rv;
}

/* Debug function - Prints the buffer on HEX format */
int print_buff(u_int8_t *buff, int size)
{
	int tmp;
	printf("\n---------Buffer data-------\n");
	for(tmp = 0; tmp < size; tmp++) {
		printf("%02X ", buff[tmp]);
		if((tmp % 16) == 0 && tmp != 0) {
			printf("\n");
		}
	}
	printf("\n");
	return 0;
}

/* Reset the DHCP option buffer to zero and dhopt_size to zero */
int reset_dhopt_size()
{
	bzero(dhopt_buff, sizeof(dhopt_buff));
	dhopt_size = 0;
	return 0;
}

void init_rand() {
	srand(time(NULL) ^ (getpid() << 16));
}

/*
 * Sets a random DHCP xid
 */
int set_rand_dhcp_xid()
{
	if(dhcp_xid == 0)
		dhcp_xid = (rand() % 0xfffffff0) + 1;
	return 0;
}

/*
 * IP checksum function - Calculates the IP checksum
 */
u_int16_t ipchksum(u_int16_t *buff, int words) 
{
	unsigned int sum;
	int i;

	sum = 0;
	for(i = 0;i < words; i++){
		sum = sum + *(buff + i);
	}
	sum = (sum >> 16) + sum;
	return (u_int16_t)~sum;
}

/*
 * ICMP checksum function - Calculates the ICMP checksum
 */
u_int16_t icmpchksum(u_int16_t *buff, int words) 
{
	unsigned int sum;
	unsigned int last_word = 0;
	int i;

	/* Checksum enhancement for odd packets */
	if((icmp_len % 2) == 1) {
		last_word = *((u_int8_t *)buff + icmp_len + ICMP_H - 1);
		last_word = (htons(last_word) << 8);
		sum = 0;
		for(i = 0;i < words; i++){
			sum = sum + *(buff + i);
		}
		sum = sum + last_word;
		sum = (sum >> 16) + sum;
		return (u_int16_t)~sum;
	} else {
		sum = 0;
		for(i = 0;i < words; i++){
			sum = sum + *(buff + i);
		}
		sum = (sum >> 16) + sum;
		return (u_int16_t)~sum;
	}
}

/*
 * TCP/UDP checksum function
 */
u_int16_t l4_sum(u_int16_t *buff, int words, u_int16_t *srcaddr, u_int16_t *dstaddr, u_int16_t proto, u_int16_t len) 
{
	unsigned int sum, last_word = 0;
	int i;

	/* Checksum enhancement - Support for odd byte packets */
	if((htons(len) % 2) == 1) {
		last_word = *((u_int8_t *)buff + ntohs(len) - 1);
		last_word = (htons(last_word) << 8);
		sum = 0;
		for(i = 0;i < words; i++){
			sum = sum + *(buff + i);
		}
		sum = sum + last_word;
		sum = sum + *(srcaddr) + *(srcaddr + 1) + *(dstaddr) + *(dstaddr + 1) + proto + len;
		sum = (sum >> 16) + sum;
		return ~sum;
	} else {
		/* Original checksum function */
		sum = 0;
		for(i = 0;i < words; i++){
			sum = sum + *(buff + i);
		}

		sum = sum + *(srcaddr) + *(srcaddr + 1) + *(dstaddr) + *(dstaddr + 1) + proto + len;
		sum = (sum >> 16) + sum;
		return ~sum;
	}
}

/*
 * Builds DHCP option53 on dhopt_buff
 */
int build_option53(int msg_type)
{
	dhopt_buff[dhopt_size++] = DHCP_MESSAGETYPE;
	dhopt_buff[dhopt_size++] = 1;
	dhopt_buff[dhopt_size++] = (unsigned char) msg_type;
	return 0;
}

/*
 * Builds DHCP option50 on dhopt_buff
 */
int build_option50()
{
	dhopt_buff[dhopt_size++] = DHCP_REQUESTEDIP;
	dhopt_buff[dhopt_size++] = 4;
	memcpy(dhopt_buff + dhopt_size, &option50_ip, 4);
	dhopt_size += 4;
	return 0;
}

/*
 * Builds DHCP option51 on dhopt_buff - DHCP lease time requested
 */
int build_option51()
{
	u_int32_t msg = htonl(option51_lease_time);

	dhopt_buff[dhopt_size++] = DHCP_LEASETIME;
	dhopt_buff[dhopt_size++] = 4;
	memcpy(dhopt_buff + dhopt_size, &msg, 4);
	dhopt_size += 4;
	return 0;
}
/*
 * Builds DHCP option54 on dhopt_buff
 */
int build_option54()
{
	dhopt_buff[dhopt_size++] = DHCP_SERVIDENT;
	dhopt_buff[dhopt_size++] = 4;
	memcpy(dhopt_buff + dhopt_size, &server_id, 4);
	dhopt_size += 4;
	return 0;
}

/*
 * Builds DHCP option55 on dhopt_buff
 */
int build_option55() 
{
	dhopt_buff[dhopt_size++] = DHCP_PARAMREQUEST;
	dhopt_buff[dhopt_size++] = 4;
	dhopt_buff[dhopt_size++] = DHCP_SUBNETMASK;
	dhopt_buff[dhopt_size++] = DHCP_ROUTER;
	dhopt_buff[dhopt_size++] = DHCP_DOMAINNAME;
	dhopt_buff[dhopt_size++] = DHCP_DNS;
	return 0;
}

/*
 * Builds DHCP option60 on dhopt_buff
 */
int build_option60_vci()
{
	dhopt_buff[dhopt_size++] = DHCP_CLASSID;
	dhopt_buff[dhopt_size++] = (unsigned char) strlen(vci_buff);
	memcpy(dhopt_buff + dhopt_size, vci_buff, strlen(vci_buff));
	dhopt_size += strlen(vci_buff);
	return 0;
}

/*
 * Builds DHCP option 12, hostname, on dhopt_buff
 */
int build_option12_hostname()
{
	dhopt_buff[dhopt_size++] = DHCP_HOSTNAME;
	dhopt_buff[dhopt_size++] = (unsigned char) strlen(hostname_buff);
	memcpy(dhopt_buff + dhopt_size, hostname_buff, strlen(hostname_buff));
	dhopt_size += strlen(hostname_buff);
	return 0;
}


/*
 * Builds DHCP option 81, fqdn, on dhopt_buff
 */
int build_option81_fqdn()
{
	unsigned char flags = 0;

	if (fqdn_n)
		flags |= FQDN_N_FLAG;
	if (fqdn_s)
		flags |= FQDN_S_FLAG;

	dhopt_buff[dhopt_size++] = DHCP_FQDN;
	dhopt_buff[dhopt_size++] = (unsigned char) strlen(fqdn_buff) + 3;
	dhopt_buff[dhopt_size++] = flags;
	dhopt_buff[dhopt_size++] = 0;
	dhopt_buff[dhopt_size++] = 0;
	memcpy(dhopt_buff + dhopt_size, fqdn_buff, strlen(fqdn_buff));
	dhopt_size += strlen(fqdn_buff);

	return 0;
}

/*
 * Builds DHCP end of option on dhopt_buff
 */
int build_optioneof()
{
	dhopt_buff[dhopt_size++] = 0xff;
	return 0;
}

static void vlanize(struct vlan_eth_hdr *vhdr) {
	if (!vlan)
		return;
	vhdr->vlan_len = vhdr->vlan_tpi;
	vhdr->vlan_tpi = htons(ETHERTYPE_VLAN);
	vhdr->vlan_priority_c_vid = htons(vlan);
}

/*
 * Build DHCP packet. Packet type is passed as argument
 */
int build_dhpacket(int pkt_type)
{
	u_int32_t dhcp_packet_size = dhcp_hdr_size + dhopt_size;
	if(!dhcp_release_flag) {
		u_char dmac_tmp[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		memcpy(dmac, dmac_tmp, ETHER_ADDR_LEN);
	}

	struct vlan_eth_hdr *vhdr = (struct vlan_eth_hdr *)dhcp_packet_send;
	memcpy(vhdr->vlan_dhost, dmac, ETHER_ADDR_LEN);
	memcpy(vhdr->vlan_shost, dhmac, ETHER_ADDR_LEN);
	vhdr->vlan_tpi = htons(ETHERTYPE_IP);
	vlanize(vhdr);

	//print_buff(dhcp_packet_disc, sizeof(struct ethernet_hdr));

	if (padding_flag && dhcp_packet_size < MINIMUM_PACKET_SIZE) {
		memset(dhopt_buff + dhopt_size, 0, MINIMUM_PACKET_SIZE - dhcp_packet_size);
		dhopt_size += MINIMUM_PACKET_SIZE - dhcp_packet_size;
	}

	struct iphdr *iph = (struct iphdr *)(dhcp_packet_send + l2_hdr_size);
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = l3_tos;
	iph->tot_len = htons(l3_hdr_size +  l4_hdr_size + dhcp_hdr_size + dhopt_size);  
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = 17;
	iph->check = 0; // Filled later;

	switch (pkt_type) {
		case DHCP_MSGDISCOVER:
		case DHCP_MSGREQUEST:
			if (unicast_flag)
				iph->saddr = unicast_ip_address;
			else
				iph->saddr = inet_addr("0.0.0.0");
			iph->daddr = inet_addr(server_addr);
			break;
			
		case DHCP_MSGRELEASE:
			iph->saddr = option50_ip; //inet_addr("0.0.0.0");
			iph->daddr = server_id; //inet_addr("255.255.255.255");
			break;
	}
	iph->check = ipchksum((u_int16_t *)(dhcp_packet_send + l2_hdr_size), iph->ihl << 1);

	struct udphdr *uh = (struct udphdr *) (dhcp_packet_send + l2_hdr_size + l3_hdr_size);
	uh->source = htons(port + 1);
	uh->dest = htons(port);
	u_int16_t l4_proto = 17;
	u_int16_t l4_len = (l4_hdr_size + dhcp_hdr_size + dhopt_size);
	uh->len = htons(l4_len);
	uh->check = 0; /* UDP checksum will be done after dhcp header*/

	struct dhcpv4_hdr *dhpointer = (struct dhcpv4_hdr *)(dhcp_packet_send + l2_hdr_size + l3_hdr_size + l4_hdr_size);
	dhpointer->dhcp_opcode = DHCP_REQUEST;
	dhpointer->dhcp_htype = ARPHRD_ETHER;
	dhpointer->dhcp_hlen = ETHER_ADDR_LEN;
	dhpointer->dhcp_hopcount = 0;
	dhpointer->dhcp_xid = htonl(dhcp_xid);
	dhpointer->dhcp_secs = 0;
	dhpointer->dhcp_flags = bcast_flag;
	dhpointer->dhcp_yip = 0;
	if (unicast_flag)
		dhpointer->dhcp_cip = unicast_ip_address;
	else
		dhpointer->dhcp_cip = 0;

	switch (pkt_type) {
		case DHCP_MSGDISCOVER:
			dhpointer->dhcp_sip = 0;
			break;

		case DHCP_MSGRELEASE:
			dhpointer->dhcp_cip = option50_ip;
			dhpointer->dhcp_sip = 0;
			break;

		case DHCP_MSGREQUEST:
			dhpointer->dhcp_sip = server_id;
			break;
	}
	dhpointer->dhcp_gip = inet_addr(giaddr);
	memcpy(dhpointer->dhcp_chaddr, dhmac, ETHER_ADDR_LEN);
	/*dhpointer->dhcp_sname 
	  dhpointer->dhcp_file*/
	dhpointer->dhcp_magic = htonl(DHCP_MAGIC);

	/* DHCP option buffer is copied here to DHCP packet */
	u_char *dhopt_pointer = (u_char *)(dhcp_packet_send + l2_hdr_size + l3_hdr_size + l4_hdr_size + dhcp_hdr_size);
	memcpy(dhopt_pointer, dhopt_buff, dhopt_size);    

	/* UDP checksum is done here */
	uh->check = l4_sum((u_int16_t *) (dhcp_packet_send + l2_hdr_size + l3_hdr_size), ((dhcp_hdr_size + dhopt_size + l4_hdr_size) / 2), (u_int16_t *)&iph->saddr, (u_int16_t *)&iph->daddr, htons(l4_proto), htons(l4_len)); 

	return 0;
}

/*
 * build packet - Builds ARP reply and ICMP reply packets
 */
int build_packet(int pkt_type)
{
	bzero(arp_icmp_reply, sizeof(arp_icmp_reply));
	if(pkt_type == ARP_SEND) {
		struct vlan_eth_hdr *vhdr = (struct vlan_eth_hdr *)arp_icmp_reply;
		memcpy(vhdr->vlan_dhost, vlan_hg->vlan_shost, ETHER_ADDR_LEN);
		memcpy(vhdr->vlan_shost, dhmac, ETHER_ADDR_LEN);
		vhdr->vlan_tpi = htons(ETHERTYPE_ARP);
		vlanize(vhdr);

		struct arp_hdr *arph = (struct arp_hdr *)(arp_icmp_reply + l2_hdr_size);
		arph->ar_hrd = htons(ARPHRD_ETHER);
		arph->ar_pro = htons(ETHERTYPE_IP);
		arph->ar_hln = ETHER_ADDR_LEN;
		arph->ar_pln = IP_ADDR_LEN;
		arph->ar_op = htons(ARPOP_REPLY);
		u_int32_t ip_addr_tmp;
		ip_addr_tmp = htonl(ip_address);
		memcpy(arph->sender_mac, dhmac, ETHER_ADDR_LEN);
		memcpy(arph->sender_ip, (u_char *)&ip_addr_tmp, ETHER_ADDR_LEN);
		memcpy(arph->target_mac, arp_hg->sender_mac, ETHER_ADDR_LEN);
		memcpy(arph->target_ip, arp_hg->sender_ip, IP_ADDR_LEN);
	} else if(ICMP_SEND) {
		struct vlan_eth_hdr *vhdr = (struct vlan_eth_hdr *)arp_icmp_reply;
		memcpy(vhdr->vlan_dhost, vlan_hg->vlan_shost, ETHER_ADDR_LEN);
		memcpy(vhdr->vlan_shost, dhmac, ETHER_ADDR_LEN);
		vhdr->vlan_tpi = htons(ETHERTYPE_IP);
		vlanize(vhdr);

		//print_buff(dhcp_packet_request, sizeof(struct ethernet_hdr));

		struct iphdr *iph = (struct iphdr *)(arp_icmp_reply + l2_hdr_size);
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = l3_tos;
		iph->tot_len = 0; /* Filled later */
		iph->id = 0; /* (iph_g->id + 5000); */
		iph->frag_off = 0;
		iph->ttl = 128;
		iph->protocol = 1;
		iph->check = 0; // Filled later;
		iph->saddr = htonl(ip_address); 
		iph->daddr = iph_g->saddr; 
		/* iph->daddr = inet_addr("255.255.255.255"); */

		struct icmp_hdr *ich = (struct icmp_hdr *)(arp_icmp_reply + l2_hdr_size + l3_hdr_size);
		ich->icmp_type = ICMP_ECHOREPLY;
		ich->icmp_code = 0;
		ich->icmp_sum = 0;
		ich->id = icmp_hg->id;
		ich->seq = icmp_hg->seq;
		icmp_len = (ntohs(iph_g->tot_len) - (iph_g->ihl << 2) - ICMP_H);
		memcpy((((u_char *)&ich->seq) + 1), (((u_char *)&icmp_hg->seq) +1), (icmp_len + 1)); 
		iph->tot_len = htons((l3_hdr_size + ICMP_H + icmp_len));
		iph->check = ipchksum((u_int16_t *)(arp_icmp_reply + l2_hdr_size), iph->ihl << 1);
		ich->icmp_sum = icmpchksum((u_int16_t *)(arp_icmp_reply + l2_hdr_size + l3_hdr_size), ((icmp_len + ICMP_H) / 2)); 
	}
	return 0;
}

/*
 * Checks whether received packet is DHCP offer/ACK/NACK/ARP/ICMP
 * and retunrs the received packet type
 */
static int check_packet(int pkt_type, int len)
{
	int ret;

	if (len < 40)
		return UNKNOWN_PACKET;

	if(pkt_type == DHCP_MSGOFFER || pkt_type == DHCP_MSGACK) {
		if (map_all_layer_ptr(pkt_type))
			return UNKNOWN_PACKET;

		if (vlan) {
			if (ntohs(vlan_hg->vlan_priority_c_vid) != vlan || ntohs(vlan_hg->vlan_tpi) != ETHERTYPE_VLAN)
				return UNKNOWN_PACKET;
		}

		if (dhopt_pointer_g > dhcp_packet_recv + len)
			return UNKNOWN_PACKET;

		if (iph_g->protocol != 17 || uh_g->source != htons(port) || uh_g->dest != htons(port + 1))
			return UNKNOWN_PACKET;
		if (htonl(dhcph_g->dhcp_xid) != dhcp_xid)
			return UNKNOWN_PACKET;

		if(*(dhopt_pointer_g + 2) == DHCP_MSGOFFER)
			ret = DHCP_OFFR_RCVD;
		else if(*(dhopt_pointer_g + 2) == DHCP_MSGACK)
			ret = DHCP_ACK_RCVD;
		else if(*(dhopt_pointer_g + 2) == DHCP_MSGNACK)
			ret = DHCP_NAK_RCVD;
		else
			return UNKNOWN_PACKET;

		read_options(len);

		return ret;

	} else if(pkt_type == ARP_ICMP_RCV) {
		if (map_all_layer_ptr(ARP_MAP))
			return UNKNOWN_PACKET;

		if(!vlan && vlan_hg->vlan_tpi != htons(ETHERTYPE_ARP))
			goto not_arp;
		if (vlan && (ntohs(vlan_hg->vlan_priority_c_vid) != vlan
					|| vlan_hg->vlan_len != htons(ETHERTYPE_ARP)))
			goto not_arp;

		if ((unsigned char *) arp_hg + sizeof(*arp_hg) > arp_icmp_packet + len)
			return UNKNOWN_PACKET;

		if((ntohs(arp_hg->ar_op)) == ARPOP_REQUEST && htonl(ip_address) == arp_hg->target_ip32) {
			if (!quiet)
				printf("Arp request received\n");
			return ARP_RCVD;
		}
		return UNKNOWN_PACKET;

not_arp:
		if (map_all_layer_ptr(ICMP_MAP))
			return UNKNOWN_PACKET;

		if(!vlan && vlan_hg->vlan_tpi != htons(ETHERTYPE_IP))
			goto not_icmp;
		if (vlan && (ntohs(vlan_hg->vlan_priority_c_vid) != vlan
					|| vlan_hg->vlan_len != htons(ETHERTYPE_IP)))
			goto not_icmp;

		if ((unsigned char *) icmp_hg + sizeof(*icmp_hg) > arp_icmp_packet + len)
			return -1;

		if (iph_g->protocol != 1)
			goto not_icmp;

		if(ip_address == ntohl(iph_g->daddr) && icmp_hg->icmp_type == ICMP_ECHO)
			return ICMP_RCVD;

not_icmp:
		return UNKNOWN_PACKET;
	}
	return 0;
}

/*
 * Sets the server ip and offerered ip on serv_id, option50_ip
 * from the DHCP offer packet
 */
int set_serv_id_opt50()
{
	option50_ip = dhcph_g->dhcp_yip;

	return 0;
}

static void read_options(int len) {
	unsigned char *p = dhopt_pointer_g,
		      *end = dhcp_packet_recv + len;

	while(*(p) != DHCP_END && p < end) {
		if ((p + *(p + 1) + 2) > end)
			break;

		switch(*(p)) {
			case DHCP_SERVIDENT:
				server_id = *(u_int32_t *)(p + 2);
				break;

			case DHCP_LEASETIME:
				lease_time = ntohl(*(u_int32_t *)(p + 2));
				break;
		}

		p = p + *(p + 1) + 2;
	}
}

/*
 * Prints the DHCP offer/ack info
 */
int print_dhinfo(int pkt_type) 
{
	u_int16_t tmp;
	unsigned char *p;

	if(pkt_type == DHCP_MSGOFFER) {
		printf("\nDHCP offer details\n");
		printf("----------------------------------------------------------\n");
		printf("DHCP offered IP from server - %s\n", get_ip_str(dhcph_g->dhcp_yip));
		printf("Next server IP(Probably TFTP server) - %s\n", get_ip_str(dhcph_g->dhcp_sip));
		printf("Boot File Name (Probably used in PXE) - %s\n", dhcph_g->dhcp_file);
		if(dhcph_g->dhcp_gip) {
			printf("DHCP Relay agent IP - %s\n", get_ip_str(dhcph_g->dhcp_gip));
		}
	} else if( pkt_type == DHCP_MSGACK) {
		printf("\nDHCP ack details\n");
		printf("----------------------------------------------------------\n");
		printf("DHCP offered IP from server - %s\n", get_ip_str(dhcph_g->dhcp_yip));
		printf("Next server IP(Probably TFTP server) - %s\n", get_ip_str(dhcph_g->dhcp_sip));
		printf("Boot File Name (Probably used in PXE) - %s\n", dhcph_g->dhcp_file);
		if(dhcph_g->dhcp_gip) {
			printf("DHCP Relay agent IP - %s\n", get_ip_str(dhcph_g->dhcp_gip));
		}
	}

	p = dhopt_pointer_g;
	while(*(p) != DHCP_END) {

		switch(*(p)) {
			case DHCP_SERVIDENT:
				printf("DHCP server  - %s\n", get_ip_str(*(u_int32_t *)(p + 2)));
				break;

			case DHCP_LEASETIME: 
				printf("Lease time - %d Days %d Hours %d Minutes\n", \
						(ntohl(*(u_int32_t *)(p + 2))) / (3600 * 24), \
						((ntohl(*(u_int32_t *)(p + 2))) % (3600 * 24)) / 3600, \
						(((ntohl(*(u_int32_t *)(p + 2))) % (3600 * 24)) % 3600) / 60);
				break;

			case DHCP_SUBNETMASK:
				printf("Subnet mask - %s\n", get_ip_str(*(u_int32_t *)(p + 2)));
				break;

			case DHCP_ROUTER:
				for(tmp = 0; tmp < (*(p + 1) / 4); tmp++) {
					printf("Router/gateway - %s\n", get_ip_str(*(u_int32_t *)(p + 2 + (tmp * 4))));
				}
				break;

			case DHCP_DNS:
				for(tmp = 0; tmp < ((*(p + 1)) / 4); tmp++) {
					printf("DNS server - %s\n", get_ip_str(*(u_int32_t *)(p + 2 + (tmp * 4))));
				}
				break;

			case DHCP_FQDN:
				{
					/* Minus 3 beacause 3 bytes are used to flags, rcode1 and rcode2 */
					u_int32_t size = (u_int32_t)*(p + 1) - 3;
					/* Plus 2 to add string terminator */
					u_char fqdn_client_name[size + 1];

					/* Plus 5 to reach the beginning of the string */
					memcpy(fqdn_client_name, p + 5, size);
					fqdn_client_name[size] = '\0';

					printf("FQDN Client name - %s\n", fqdn_client_name);
				}
		}

		p = p + *(p + 1) + 2;
	}

	printf("----------------------------------------------------------\n\n");
	return 0;
}

/*
 * Function maps all pointers on OFFER/ACK/ARP/ICMP packet
 */
static int map_all_layer_ptr(int pkt_type)
{
	switch (pkt_type) {
		case DHCP_MSGOFFER:
		case DHCP_MSGACK:
			vlan_hg = (struct vlan_eth_hdr *)dhcp_packet_recv; 
			iph_g = (struct iphdr *)(dhcp_packet_recv + l2_hdr_size);
			uh_g = (struct udphdr *)(dhcp_packet_recv + l2_hdr_size + l3_hdr_size);
			dhcph_g = (struct dhcpv4_hdr *)(dhcp_packet_recv + l2_hdr_size + l3_hdr_size + l4_hdr_size);
			dhopt_pointer_g = (u_int8_t *)(dhcp_packet_recv + l2_hdr_size + l3_hdr_size + l4_hdr_size + sizeof(struct dhcpv4_hdr));
			break;
		case ARP_MAP:
			vlan_hg = (struct vlan_eth_hdr *)arp_icmp_packet;
			arp_hg = (struct arp_hdr *)(arp_icmp_packet + l2_hdr_size);
			break;
		case ICMP_MAP:
			vlan_hg = (struct vlan_eth_hdr *)arp_icmp_packet;
			iph_g = (struct iphdr *)(arp_icmp_packet + l2_hdr_size);
			icmp_hg = (struct icmp_hdr *)(arp_icmp_packet + l2_hdr_size + l3_hdr_size);
			break;
	}

	return 0;
}

/*
 * Logs DHCP info to the log file
 * This file is used later for DHCP release
 */
int log_dhinfo()
{
	int dh_file;
	struct dhcp_status ds;

	dh_file = open(dhmac_fname, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (dh_file < 0)
		critical("Error opening file: %m");

	memset(&ds, 0, sizeof(ds));

	ds.magic = STATUS_MAGIC;
	memcpy(&ds.client_mac, dhmac, sizeof(ds.client_mac));
	if (dhcph_g && vlan_hg) {
		ds.have_ip = 1;
		ds.client_ip = dhcph_g->dhcp_yip;
		ds.server_ip = server_id;
		memcpy(&ds.server_mac, vlan_hg->vlan_shost, sizeof(ds.server_mac));
		time(&ds.acquired_at);
		ds.lease_time = lease_time;
	}

	if (ip_listen_flag)
		ds.listen_pid = getpid();

	if (write(dh_file, &ds, sizeof(ds)) != sizeof(ds))
		critical("Error writing to file: %m");

	close(dh_file);

	return 0;
}

/*
 * Takes the DHCP info from log file and removes it(unlinks it)
 * Used for DHCP release
 */
int get_dhinfo()
{
	int dh_file;
	struct dhcp_status ds;

	dh_file = open(dhmac_fname, O_RDONLY);
	if(dh_file < 0)
		return errno;

	if (read(dh_file, &ds, sizeof(ds)) != sizeof(ds))
		return errno;

	memcpy(dhmac, ds.client_mac, sizeof(dhmac));
	if (ds.have_ip) {
		option50_ip = ds.client_ip;
		server_id = ds.server_ip;
		memcpy(dmac, ds.server_mac, sizeof(dmac));
		if (ds.listen_pid)
			kill(ds.listen_pid, SIGKILL); /* XXX what about promisc mode? */
		option51_lease_time = ds.lease_time;
		lease_expires_at = ds.acquired_at + ds.lease_time;
	}

	close(dh_file);
	return 0;
}

char *get_ip_str(u_int32_t ip)
{
	struct in_addr src;
	src.s_addr = ip;
	inet_ntop(AF_INET, ((struct sockaddr_in *) &src),
			ip_str, sizeof(ip_str));
	return ip_str;
}

void critical (const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	if (nagios_flag) {
		printf("CRITICAL: ");
		vprintf(fmt, ap);
	}
	else {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}
	exit(2);
}
