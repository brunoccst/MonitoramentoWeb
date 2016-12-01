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
#include "Pacotes/LeitorDePacote.cpp"
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

// INFORMACOES DA MAQUINA RODANDO O SNIFFER
unsigned char my_mac[6] =	{ 0x14, 0x2d, 0x27, 0xe2, 0x83, 0x8f };
int my_ip[] 		=	{ 192, 168, 0, 14 };
int net_ip[] 		=	{ 192, 168, 0, 0 };
char* interface_name	=	"wlp6s0";

// INFORMACOES DO SNIFFER
int ip_to_send[] 	=	{192, 168, 0, 100};
u_int32_t dhcp_conv_id	=	0;

// INFORMACOES DA MAQUINA REQUISITANTE
int requester_ip[]	=	{ 192, 168, 0, 14 };

// Socket
unsigned char buff[1500];
int sock;
struct sockaddr_ll to;
socklen_t len;

void inverteEthernet()
{

	// Troca dhost por shost
	for (int i = 0; i < 6; i++)
	{
		eth->ether_dhost[i] = eth->ether_shost[i];
	}

	memcpy(&eth->ether_shost, &my_mac, sizeof(&eth->ether_shost));
}

void montaPacoteDHCPOffer()
{
	inverteEthernet();
	eth->ether_type = htons(0X800);  // ip.proto == "UDP" && ip.addr == 10.32.143.224

	char IP_src_s[16];
	char IP_dst_s[16];
	char IP_new_s[16];

	ip_to_string(my_ip, IP_src_s);
	ip_to_string(requester_ip, IP_dst_s);
	ip_to_string(ip_to_send, IP_new_s);

	int i = 0;

	struct ip *iph;

	iph = (struct ip *) &buff[14];
	iph->ip_v = 0X4;
	iph->ip_hl = 0X5;
	iph->ip_tos = 0X0;
	iph->ip_len = htons(0x150);
	iph->ip_id = htons(0);
	iph->ip_off = htons(0);
	iph->ip_ttl = 0X80;
	iph->ip_p = 0X11;	
	iph->ip_sum = htons(0); ///
	inet_aton(IP_src_s, &iph->ip_src);
	inet_aton(IP_dst_s, &iph->ip_dst);

	char iphChecksum[20];
	memcpy(iphChecksum, buff+14, 20);
	iph->ip_sum = (in_cksum((unsigned short *) iphChecksum, sizeof(struct ip))); // 0x150 htons(iph->ip_len)));

	struct udphdr *udph;

	udph = (struct udphdr *) &buff[14 + 20];
	udph->source = htons(67);
	udph->dest = htons(68);
	udph->len = htons(316);
	udph->check = htons(0); //
	//request size 308 discover
	//ack size 316 offer

	struct dhcp_packet *dhcph;

	dhcph = (struct dhcp_packet *) &buff[14 + 20 + 8];
	dhcph->op = 0X2;
	dhcph->htype = 0X1;
	dhcph->hlen = 0X6;
	dhcph->hops = 0X0;
	dhcph->xid = dhcp_conv_id;
	dhcph->secs = 0X0; //Seconds elapsed
	dhcph->flags = 0X0000; //Unicast
	inet_aton("0.0.0.0", &dhcph->ciaddr); //
	inet_aton(IP_new_s, &dhcph->yiaddr); //You /////////////////////////////////
	inet_aton(IP_src_s, &dhcph->siaddr); //Me
	inet_aton("0.0.0.0", &dhcph->giaddr); //Relay

	dhcph->chaddr[0] = eth->ether_dhost[0]; //Your MAC
	dhcph->chaddr[1] = eth->ether_dhost[1];
	dhcph->chaddr[2] = eth->ether_dhost[2];
	dhcph->chaddr[3] = eth->ether_dhost[3];
	dhcph->chaddr[4] = eth->ether_dhost[4];
	dhcph->chaddr[5] = eth->ether_dhost[5];

	dhcph->options[0] = 0X63;
	dhcph->options[1] = 0X82;
	dhcph->options[2] = 0X53;
	dhcph->options[3] = 0X63; //Magic Cookie: DHCP

	dhcph->options[4] = 0X35; //Option 53 	DHCP Message
	dhcph->options[5] = 0X01; //Len 1
	dhcph->options[6] = 0X02; //DHCP Offer

	dhcph->options[7] = 0X36; //Option 54   DHCP Server Identif.
	dhcph->options[8] = 0X04; // Len 4
	dhcph->options[9] = (my_ip[0]); // Meu IP
	dhcph->options[10] = (my_ip[1]); // Meu IP
	dhcph->options[11] = (my_ip[2]); // Meu IP
	dhcph->options[12] = (my_ip[3]); // Meu IP
	//inet_aton("10.32.143.224", &dhcph->options[10]); //Meu IP

	dhcph->options[13] = 0X33; //Option 51 IP Lease Time
	dhcph->options[14] = 0X04; //Len 4
	dhcph->options[15] = 0X99; //Time
	dhcph->options[16] = 0X99; //Time
	dhcph->options[17] = 0X99; //Time
	dhcph->options[18] = 0X99; //Time

	dhcph->options[19] = 0X01; //Option 1 Subnet Mask
	dhcph->options[20] = 0X04; //Len 4
	dhcph->options[21] = 0XFF; //  255.255.255.0
	dhcph->options[22] = 0XFF; // ou FF.FF.FF.00
	dhcph->options[23] = 0XFF; //
	dhcph->options[24] = 0X00; //

	dhcph->options[25] = 0X1C; //Option 28 Broadcast
	dhcph->options[26] = 0X04; //Len 4
	dhcph->options[27] = (10); // 10.32.143.255
	dhcph->options[28] = (32); //
	dhcph->options[29] = (143); //
	dhcph->options[30] = (255); //

	dhcph->options[31] = 0X03; //Option 3 Router
	dhcph->options[32] = 0X04; //Len 4
	dhcph->options[33] = (my_ip[0]); // 10.32.143.224 - meu ip
	dhcph->options[34] = (my_ip[1]); //
	dhcph->options[35] = (my_ip[2]); //
	dhcph->options[36] = (my_ip[3]); //

	dhcph->options[37] = 0X0F; //Option 15 Domain Name
	dhcph->options[38] = 0X0C; //Len 12
	dhcph->options[39] = 0X69; //
	dhcph->options[40] = 0X6E; // inf.pucrs.br
	dhcph->options[41] = 0X66; // .
	dhcph->options[42] = 0X2E; // .
	dhcph->options[43] = 0X70; // inf.pucrs.br
	dhcph->options[44] = 0X75; // .
	dhcph->options[45] = 0X63; // .
	dhcph->options[46] = 0X72; // inf.pucrs.br
	dhcph->options[47] = 0X73; // .
	dhcph->options[48] = 0X2E; // .
	dhcph->options[49] = 0X62; // inf.pucrs.br
	dhcph->options[50] = 0X72; // .

	dhcph->options[51] = 0X06; //Option 6 Domain Name Server
	dhcph->options[52] = 0X08; //Len 8
	dhcph->options[53] = 0X0A; //
	dhcph->options[54] = 0X28; //
	dhcph->options[55] = 0X30; //
	dhcph->options[56] = 0X0A; // 10.40.48.10
	dhcph->options[57] = 0X0A; //
	dhcph->options[58] = 0X28; //
	dhcph->options[59] = 0X30; //
	dhcph->options[60] = 0X0B; // 10.40.48.11

	dhcph->options[61] = 0X2C; //Option 44 NetBIOS
	dhcph->options[62] = 0X08; //Len 8
	dhcph->options[63] = 0X0A; //
	dhcph->options[64] = 0X28; //
	dhcph->options[65] = 0X30; //
	dhcph->options[66] = 0X0A; // 10.40.48.10
	dhcph->options[67] = 0X0A; //
	dhcph->options[68] = 0X28; //
	dhcph->options[69] = 0X30; //
	dhcph->options[70] = 0X0B; // 10.40.48.11

	dhcph->options[71] = 0XFF; // Option 255 END

}

int main(int argc,char *argv[])
{
	int sock, sockd, i;
	struct ifreq ifr;
	struct sockaddr_ll to;
	socklen_t len;
	unsigned char addr[6];

	/* Inicializa com 0 os bytes de memoria apontados por ifr. */
	memset(&ifr, 0, sizeof(ifr));

	/* Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. D� um "man" para ver os par�metros.*/
	/* htons: converte um short (2-byte) integer para standard network byte order. */
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	printf("Erro na criacao do socket.\n");
	//exit(1);
	}

	/* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
	to.sll_protocol= htons(ETH_P_ALL);

	strcpy(ifr.ifr_name, interface_name);

	if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Erro na criacao do socket de recepcao.\n");

	to.sll_halen = 6;
	to.sll_ifindex = ifr.ifr_ifindex; /* indice da interface pela qual os pacotes serao enviados */

    /* Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro na criacao do socket.\n");
        	exit(1);
 	}

	to.sll_halen = 6;
	to.sll_ifindex = ifr.ifr_ifindex; /* indice da interface pela qual os pacotes serao enviados */

    	len = sizeof(struct sockaddr_ll);

	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	bool recebendoPacotes = false;
	bool esperandoRequest = false;

	while(1)
	{
		if (!recebendoPacotes)
		{
			printf("\nRecebendo pacotes.\n");
			printf("___________________\n\n");
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
		if(ntohs(eth->ether_type) == ETHERTYPE_IP)
		{
				// Pega o pacote IP e UDP
				ip = (struct ip *) &buff[14];
				udp = (struct udphdr *) &buff[34];

				if (ip->ip_p == 17 && udp->source == htons(68)) //UDP
				{
					dhcp = (struct dhcp_packet *) &buff[42];

					if(dhcp->options[6] == DHCPDISCOVER && !esperandoRequest) //DHCP Discover
					{
						printf("DHCP Discover recebido\n\n");
						
						dhcp_conv_id = dhcp->xid;
						len = sizeof(struct sockaddr_ll);
						montaPacoteDHCPOffer();

					        if(sendto(sock, (char *) buff, sizeof(buff), 0, (struct sockaddr*) &to, len)<0)			
						{
							printf("DHCP Offer enviado.\n");
							esperandoRequest = true;
						}
						else
						{
							printf("DHCP Offer NAO foi enviado por falha.\n");
							recebendoPacotes = false;
						}
					}
					else if(dhcp->options[6] == DHCPREQUEST) //DHCP Request
					{

						printf("DHCP Request recebido\n");

						dhcp_conv_id = dhcp->xid;
						len = sizeof(struct sockaddr_ll);
						montaPacoteDHCPOffer();
						dhcp->options[6] = 0x05; //ACK

						if(sendto(sock, (char *) buff, sizeof(buff), 0, (struct sockaddr*) &to, len)<0)
						{
								printf("DHCP ACK enviado.\n");
						}
						else
						{
								printf("DHCP ACK NAO foi enviado por falha.\n");
						}

						recebendoPacotes = false;
						esperandoRequest = false;
					}
				}
		}
	}
	return 0;
}
