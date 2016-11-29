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
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <stdint.h>

/*	Pacotes	*/
#include "Pacotes/MonitorDeRede.cpp"
#include "Pacotes/Structs/dhcp.h"

/*	Funcionalidades	*/
//#include "Funcionalidades/Conversor.cpp"
#include "Funcionalidades/in_cksum.cpp"

/*	INFORMAÇÕES DA REDE	*/
#define BROADCAST_ADDR 			0xFFFFFFFF // 255.255.255.255
#define NET_MASK				0x11111100 // 255.255.255.0
#define LEASE_TIME_DEFAULT		0X00000078 // 120 segundos

/*	DHCP OPTIONS DEFAULT	*/
#define DHCP_MESSAGE_TYPE 		0X3501
#define IP_ADDRES_LEASE_TIME	0x3304
#define SUBNET_MASK 			0x0104
#define DHCP_OPT_BROADCAST		0x1C04
#define ROUTER			 		0x0304
#define DOMAIN_NAME 			0x0F12
#define SERVER_IDENTIFIER 		0x3608
#define DOMAIN_NAME_SERVER_ID	0x0608
#define NETBIOS_NAME_SERVICE	0x2C08
#define END						0xFF

typedef struct ether_header _ethernet;
typedef struct ip _ip;
typedef struct udphdr _udp;
typedef struct dhcp_packet _dhcp;

_ethernet* eth;
_ip* ip;
_udp* udp;
_dhcp* dhcp;

unsigned char my_mac[16];
uint32_t my_ip = 0;
uint32_t net_ip = 0; // 10.32.143.0
char ip_to_send[] = "10.32.143.42";

unsigned char buff[1502];
int sock;
struct sockaddr_ll to;
socklen_t len;
unsigned char addr[6];

void inverteEthernet()
{
	// Copia DHOST
	u_char aux[6];
	memcpy(&aux, &eth->ether_dhost, sizeof(&aux));

	// Troca dhost por shost
	for (int i = 0; i < 6; i++)
	{
		eth->ether_dhost[i] = eth->ether_shost[i];
	}

	// Troca shost por dhost
	for (int i = 0; i < 6; i++)
	{
		eth->ether_shost[i] = aux[i];
	}
}

void montaPacoteDHCPOffer()
{
	// Monta ETHERNET
	inverteEthernet();
	char my_ip_char[16];
	sprintf(my_ip_char,"%lu", my_ip);

	// Monta IP
	ip->ip_v = 0x4;
	ip->ip_hl = 0x5;
	ip->ip_tos = 0x0;
	ip->ip_len = htons(0x150);
	ip->ip_id = htons(0);
	ip->ip_off = htons(0);
	ip->ip_ttl = 0x80;
	ip->ip_p = 0x11;
	ip->ip_sum = htons(0);

	inet_aton(my_ip_char, &ip->ip_src);
	inet_aton(ip_to_send, &ip->ip_dst);

	char ipChecksum[20];
	memcpy(&ipChecksum, &buff[14], 20);
	ip->ip_sum = (in_cksum((unsigned short *) ipChecksum, sizeof(struct ip)));

	// Monta UDP
	udp->source = htons(67);
	udp->dest = htons(68);
	udp->len = htons(316);
	udp->check = htons(0);

	// Monta DHCP
	dhcp->op = 0x2;
	dhcp->htype = 0x1;
	dhcp->hlen = 0x6;
	dhcp->hops = 0x0;
	dhcp->xid = 0x9999;
	dhcp->secs = 0x0;
	dhcp->flags = 0x0000;

	inet_aton("0.0.0.0", &dhcp->ciaddr);
	inet_aton(ip_to_send, &dhcp->yiaddr);
	inet_aton(my_ip_char, &dhcp->siaddr);
	inet_aton("0.0.0.0", &dhcp->ciaddr);

	memcpy(&dhcp->chaddr, &my_mac, sizeof(&dhcp->chaddr));
	dhcp->options[0] = 0x63;	
	dhcp->options[1] = 0x82;
	dhcp->options[2] = 0x53;
	dhcp->options[3] = 0x63;

	dhcp->options[4] = 0x35;
	dhcp->options[5] = 0x01;
	dhcp->options[6] = 0x02;
	dhcp->options[7] = 0x36;

	dhcp->options[8] = 0x04;
	memcpy(&dhcp->options[9], &my_ip, sizeof(&my_ip));
	dhcp->options[13] = 0x33;
	dhcp->options[14] = 0x04;

	dhcp->options[15] = 0x99;
	dhcp->options[16] = 0x99;
	dhcp->options[17] = 0x99;
	dhcp->options[18] = 0x99;

	dhcp->options[19] = 0x01;
	dhcp->options[20] = 0x04;
	dhcp->options[21] = 0xFF;
	dhcp->options[22] = 0xFF;

	dhcp->options[23] = 0xFF;
	dhcp->options[24] = 0x00;
	dhcp->options[25] = 0x1C;
	dhcp->options[26] = 0x04;

	dhcp->options[27] = 10;
	dhcp->options[28] = 32;
	dhcp->options[29] = 143;
	dhcp->options[30] = 255;

	dhcp->options[31] = 0x03;
	dhcp->options[32] = 0x04;
	memcpy(&dhcp->options[33], &my_ip, sizeof(&my_ip));

	dhcp->options[37] = 0x0F;
	dhcp->options[38] = 0x0C;
	dhcp->options[39] = 0x39;
	dhcp->options[40] = 0x6E;
	dhcp->options[41] = 0x66;
	dhcp->options[42] = 0x2E;
	dhcp->options[43] = 0x70;
	dhcp->options[44] = 0x75;
	dhcp->options[45] = 0x63;
	dhcp->options[46] = 0x72;
	dhcp->options[47] = 0x73;
	dhcp->options[48] = 0x2E;
	dhcp->options[49] = 0x62;
	dhcp->options[50] = 0x72;

	dhcp->options[51] = 0x06;
	dhcp->options[52] = 0x08;
	dhcp->options[53] = 0x0A;
	dhcp->options[54] = 0x28;
	dhcp->options[55] = 0x30;
	dhcp->options[56] = 0x0A;
	dhcp->options[57] = 0x0A;
	dhcp->options[58] = 0x28;
	dhcp->options[59] = 0x30;
	dhcp->options[60] = 0x0B;

	dhcp->options[61] = 0x2C;
	dhcp->options[62] = 0x08;
	dhcp->options[63] = 0x0A;
	dhcp->options[64] = 0x28;
	dhcp->options[65] = 0x30;
	dhcp->options[66] = 0x0A;
	dhcp->options[67] = 0x0A;
	dhcp->options[68] = 0x28;
	dhcp->options[69] = 0x30;
	dhcp->options[70] = 0x0B;
	dhcp->options[71] = 0xFF;
}

int main(int argc,char *argv[])
{
	struct sockaddr_ll to;
	socklen_t len;

	struct ifreq ifr;

    /* Inicializa com 0 os bytes de memoria apontados por ifr. */
	memset(&ifr, 0, sizeof(ifr));

	/* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
	to.sll_protocol= htons(ETH_P_ALL);
	to.sll_ifindex = 2; /* indice da interface pela qual os pacotes serao enviados */

	printf("Iniciando o sniffer\n\n");
	GetIPDaRede(my_ip, net_ip);
	EscreveInformacoesIP(&my_ip, &net_ip);

    /* Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro na criacao do socket.\n");
        exit(1);
 	}

	bool recebendoPacotes = false;

	while(1)
	{
		if (!recebendoPacotes)
		{
			printf("\nRecebendo pacotes.\n");
			recebendoPacotes = true;
		}

		int err_no = 0;
		err_no = recv(sock,(char *) &buff, sizeof(buff), 0x0);

		//Le mensagens
		if(!err_no || err_no == -1){
			printf("Falha no recebimento de pacotes.\n");
			continue;
		}
			 
		// Pega o pacote ETHERNET
		eth = (struct ether_header *) &buff[0];

		//Verifica o tipo de protocolo no ethernet
		if(ntohs(eth->ether_type) == ETHERTYPE_IP
			&& 	eth->ether_shost[0] == 0xa4 //TODO: Deletar
			&&	eth->ether_shost[1] == 0x1f //TODO: Deletar
			&&	eth->ether_shost[2] == 0x72 //TODO: Deletar
			&&	eth->ether_shost[3] == 0xf5 //TODO: Deletar
			&&	eth->ether_shost[4] == 0x90 //TODO: Deletar
			&&	eth->ether_shost[5] == 0x8f //TODO: Deletar
		)
		{
				// Pega o pacote IP e UDP
				ip = (struct ip *) &buff[14];
				udp = (struct udphdr *) &buff[34];

				if (ip->ip_p == 17 && udp->source == htons(68)) //UDP
				{
					dhcp = (struct dhcp_packet *) &buff[42];

					if(dhcp->options[6] == DHCPDISCOVER) //DHCP Discover
					{
						printf("DHCP Discover recebido\n");
						len = sizeof(struct sockaddr_ll);
						montaPacoteDHCPOffer();
						if(sendto(sock, (char *) buff, sizeof(buff), 0, (struct sockaddr*) &to, len)<0)
								printf("sendto maquina destino.\n");

						recebendoPacotes = false;
					}
				}
		}
	}
	return 0;
}
