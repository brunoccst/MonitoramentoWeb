/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - envio de mensagens com struct          */
/*-------------------------------------------------------------*/

#include <stdio.h>
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

#define BROADCAST_ADDR 0xFFFFFFFF

unsigned char buff[1500];
int sock;

typedef struct ether_header ethernet;
typedef struct iphdr ip;
typedef struct udphdr udp;
typedef struct dhcp_packet dhcp;

struct package_header{
	ethernet eth;
	ip ip;
	udp udp;
	dhcp dhcp;
};

typedef struct package package;

package * curr_pack = (package *)&buff[0];


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
	
 	eth->ether_type = type;
}

void monta_ip(uint32_t ip_server)
{ 
	curr_pack->ip.saddr = ip_server;
	curr_pack->ip.daddr = BROADCAST_ADDR
}

void monta_udp(){ }

void monta_dhcp(){ }

void monta_DHCP_OFFER()
{
	curr_pack->dhcp.op = 2;
	//curr_pack->dhcp.flags = 

	curr_pack->dhcp.yiaddr = curr_pack->ip.saddr;
	curr_pack->dhcp.options = unsigned char[DHCP_OPTION_LEN];
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
    /* Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. D� um "man" para ver os par�metros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro na criacao do socket.\n");
        exit(1);
 	}

	while(1)
	{
		//Le mensagens
		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
		curr_pack = (package *) &buff[0];
		switch (ntohs(curr_pack->eth->ether_type))
		{
			case ETH_P_IP: //IPv4
				if (curr_pack->ip.ip_p == 17 
				&& curr_pack->udp.uh_dport == 67) //UDP
				{
					int * options = (int *)&(curr_pack->dhcp->options[0]);
					if(*options == DHCPDISCOVER)
					{
						monta_DHCP_OFFER();
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
		if (false)
		{
			enviaPacote();
		}
	}
}
