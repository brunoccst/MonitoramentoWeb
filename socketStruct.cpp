/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - envio de mensagens com struct          */
/*-------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <stdint.h>
#include "dhcp.h"

#define SOCKETSTRUCT_H
 
#define BROADCAST_ADDR 			0xFFFFFFFF
#define DHCP_MESSAGE_TYPE 		0X350100
#define SUBNET_MASK 			0x010400000000
#define RENEWAL_TIME_VALUE 		0x3A0400000000
#define REBINDING_TIME_VALUE	0x3B0400000000
#define IP_ADDRES_LEASE_TIME	0x330400000000
#define SERVER_IDENTIFIER 		0x360400000000
#define ROUTER			 		0x030400000000
#define NETBIOS_NAME_SERVICE	0x2C0400000000
#define NETBIOS_NODE_TYPE		0x2E0100
#define END						0xFF

typedef struct ether_header _ethernet;
typedef struct iphdr _ip;
typedef struct udphdr _udp;
typedef struct dhcp_packet _dhcp;
typedef struct option_field {
	unsigned char 	dhcp_message_type; // 53 0X35
	uint32_t 	  	subnet_mask; //01 0X01
	uint32_t 		renewal_time_value; //58 0X3A
	uint32_t 		rebinding_time_value;//59 0X3B
	uint32_t 		ip_address_lease_time;//51 0X
	uint32_t 		server_identifier;//54 0X36
	uint32_t 		router;//03 0X03
	uint32_t 		netBIOS_name_service; //44 0X2C size n octects adress
	unsigned char 	netBIOS_node_type; // 46 0X2E

	unsigned char end = END;
} options_field;

typedef struct package_header{
	_ethernet eth;
	_ip ip;
	_udp udp;
	_dhcp dhcp;
} package ;

unsigned char net_ip[4] = [10,32,143,0];
unsigned char next_free_ip = 201;


unsigned char buff[1500];
int sock;

package * curr_pack = (package *)&buff[0];

in_addr convertInt32(u_int32_t toConvert)
{
	return *( struct in_addr * ) &toConvert;
}

void monta_options(option_field *option_pointer)
{
	option_pointer->dhcp_message_type = 		DHCP_MESSAGE_TYPE; // 53
	option_pointer->subnet_mask = 				SUBNET_MASK; //01
	option_pointer->renewal_time_value= 		RENEWAL_TIME_VALUE; //58
	option_pointer->rebinding_time_value= 		REBINDING_TIME_VALUE;//59
	option_pointer->ip_address_lease_time= 		IP_ADDRES_LEASE_TIME;//51
	option_pointer->server_identifier= 			SERVER_IDENTIFIER;//54
	option_pointer->router= 					ROUTER;//03
	option_pointer->netBIOS_name_service= 		NETBIOS_NAME_SERVICE; //44 size n octects adress
	option_pointer->netBIOS_node_type= 			NETBIOS_NODE_TYPE; // 46
}
/// recebe parametros em formato ordenado da rede ( funcções noths(), ntohl(),htons(),htonl())
void monta_eth(uint32_t mac_dst, uint32_t mac_src, uint16_t type)
{ 
	unsigned char * mac = (unsigned char *)&mac_dst;

	curr_pack->eth.ether_dhost[0] = mac[0];
	curr_pack->eth.ether_dhost[1] = mac[1];
	curr_pack->eth.ether_dhost[2] = mac[2];
	curr_pack->eth.ether_dhost[3] = mac[3];
	curr_pack->eth.ether_dhost[4] = mac[4];
	curr_pack->eth.ether_dhost[5] = mac[5];

	mac = (unsigned char *)&mac_src;

	curr_pack->eth.ether_shost[0] = mac[0];
	curr_pack->eth.ether_shost[1] = mac[1];
	curr_pack->eth.ether_shost[2] = mac[2];
	curr_pack->eth.ether_shost[3] = mac[3];
	curr_pack->eth.ether_shost[4] = mac[4];
	curr_pack->eth.ether_shost[5] = mac[5];
	
 	curr_pack->eth.ether_type = type;
}

void monta_ip(uint32_t ip_server)
{ 
	curr_pack->ip.saddr = ip_server;
	curr_pack->ip.daddr = BROADCAST_ADDR;
}

void monta_udp(){ }

void monta_dhcp(){ }

void monta_DHCP_OFFER()
{
	curr_pack->dhcp.op = 2; //Op Code
	curr_pack->dhcp.yiaddr =  convertInt32(curr_pack->ip.saddr); //Your IP Address
	
	memcpy(&curr_pack->dhcp.options[0],0,DHCP_MAX_OPTION_LEN);

	monta_options(( options_field * ) &curr_pack->dhcp.options[0]);
}


void monta_pacote()
{
	// as struct estao descritas nos seus arquivos .h
	// por exemplo a ether_header esta no net/ethert.h
	// a struct ip esta descrita no netinet/ip.h
	struct ether_header *eth;

	// coloca o ponteiro do header ethernet apontando para a 1a. posicao do buffer
	// onde inicia o header do ethernet.
	eth = (struct ether_header *) &buff[0];

	//Endereco Mac Destino
	eth->ether_dhost[0] = 0X00;
	eth->ether_dhost[1] = 0X06;
	eth->ether_dhost[2] = 0X5B;
	eth->ether_dhost[3] = 0X28;
	eth->ether_dhost[4] = 0XAE;
	eth->ether_dhost[5] = 0X73;

	//Endereco Mac Origem
	eth->ether_shost[0] = 0X00;
	eth->ether_shost[1] = 0X08;
	eth->ether_shost[2] = 0X74;
	eth->ether_shost[3] = 0XB5;
	eth->ether_shost[4] = 0XB5;
	eth->ether_shost[5] = 0X8E;

 	eth->ether_type = htons(0X800);
}

void enviaPacote()
{
	struct sockaddr_ll to;
	socklen_t len;
	unsigned char addr[6];

	struct ifreq ifr;

    /* Inicializa com 0 os bytes de memoria apontados por ifr. */
	memset(&ifr, 0, sizeof(ifr));

	/* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
	to.sll_protocol= htons(ETH_P_ALL);
	to.sll_ifindex = 2; /* indice da interface pela qual os pacotes serao enviados */
	addr[0]=0x00;
	addr[0]=0x06;
	addr[0]=0x5B;
	addr[0]=0x28;
	addr[0]=0xae;
	addr[0]=0x73;
	memcpy (to.sll_addr, addr, 6);
	len = sizeof(struct sockaddr_ll);

	monta_pacote();

	if(sendto(sock, (char *) buff, sizeof(buff), 0, (struct sockaddr*) &to, len)<0)
			printf("sendto maquina destino.\n");
}

int main(int argc,char *argv[])
{
    /* Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro na criacao do socket.\n");
        exit(1);
 	}

	bool recebeuDhcpDiscover = false;

	while(1)
	{
		//Le mensagens
		recv(sock,(char *) &buff, sizeof(buff), 0x0);
		curr_pack = (package *) &buff[0];

		//Verifica o tipo de protocolo no ethernet
		switch (ntohs(curr_pack->eth.ether_type))
		{
			case ETH_P_IP: //IPv4
				if (curr_pack->ip.protocol == 17 && curr_pack->udp.uh_dport == 67) //UDP
				{
					int * options = (int *)&(curr_pack->dhcp.options[0]);

					if(*options == DHCPDISCOVER) //DHCP Discover
					{
						monta_DHCP_OFFER();
						recebeuDhcpDiscover = true;
					}
				}
				break;

			/*
			case ETH_P_IPV6: //IPv6
				switch (ipv6.ip6_nxt)
				{
					case 17: //UDP
                        break;
				}
				break;
			*/
		}
		
		//Se DHCP Discovery identificada...
		if (recebeuDhcpDiscover)
		{
			enviaPacote();
		}
	}
}
