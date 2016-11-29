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
typedef struct option_field {
	uint16_t		dhcp_message_type_id;
	unsigned char 	dhcp_message_type; // 53 0X35
	
	uint16_t		ip_address_lease_time_id;
	uint32_t 		ip_address_lease_time;//51 0X
	
	uint16_t		subnet_mask_id;
	uint32_t 	  	subnet_mask; //01 0X01
	
	uint16_t		broadcast_addr_id;
	uint32_t		broadcast_addr;//28 
	
	uint16_t		router_id;
	uint32_t 		router;//03 0X03

	uint16_t		domain_name_id;
	uint32_t 		domain_name[3]; //15 0X3A
	
	uint16_t		server_identifier_id;
	uint32_t 		server_identifier;//54 0X36
	
	
	uint16_t		domain_name_server_id;
	uint32_t 		domain_name_server[2];//06 
	
	uint16_t		netBIOS_name_service_id;
	uint32_t 		netBIOS_name_service[2]; //44 0X2C size n octects adress

	unsigned char 	end;
} options_field;

typedef struct package_header{
	_ethernet eth;
	_ip ip;
	_udp udp;
	_dhcp dhcp;
} package ;

//unsigned char net_ip[4] = [10,32,143,0];
uint32_t my_ip = 0; // to load in load_ips
uint32_t net_ip = 0x0A208F00; // 10.32.143.0]
uint32_t sub_net = 0;
uint32_t domain_name_server_1 = 0X0A28300A;
uint32_t domain_name_server_2 = 0X0A28300B;
unsigned char next_free_ip = 0xC9; // 201;


unsigned char buff[1500];
int sock;

package * curr_pack = (package *)&buff[0];

void monta_options(option_field *option_pointer, unsigned char type)
{

	option_pointer->dhcp_message_type_id = 		DHCP_MESSAGE_TYPE; // 53
	option_pointer->dhcp_message_type = 		type; // 53

	option_pointer->ip_address_lease_time_id =	IP_ADDRES_LEASE_TIME;//51 -- 120 SEGUNDOS
	option_pointer->ip_address_lease_time= 		LEASE_TIME_DEFAULT;//51 -- 120 SEGUNDOS

	option_pointer->subnet_mask_id =			SUBNET_MASK; //01
	option_pointer->subnet_mask = 				NET_MASK + sub_net; //01

	option_pointer->broadcast_addr_id =			DHCP_OPT_BROADCAST; //58
	option_pointer->broadcast_addr= 			net_ip + (sub_net & 255); //58

	option_pointer->router_id =					ROUTER;//03
	option_pointer->router= 					my_ip;//03

	option_pointer->server_identifier_id =		SERVER_IDENTIFIER;//54
	option_pointer->server_identifier= 			my_ip;//54

	option_pointer->domain_name_id = 			DOMAIN_NAME;
	option_pointer->domain_name[0]= 			0X696E662E;
	option_pointer->domain_name[1]= 			0X70756372;
	option_pointer->domain_name[2]= 			0X732E6272;

	option_pointer->domain_name_server_id =		DOMAIN_NAME_SERVER_ID;//59
	option_pointer->domain_name_server[0]= 		domain_name_server_1;//59
	option_pointer->domain_name_server[1]= 		domain_name_server_2;//59

	option_pointer->netBIOS_name_service_id =	NETBIOS_NAME_SERVICE;
	option_pointer->netBIOS_name_service[0]=	domain_name_server_1;
	option_pointer->netBIOS_name_service[1]=	domain_name_server_2;

	option_pointer->end=						END;

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


void monta_udp(){ }

void monta_dhcp(){ }

void monta_ip(uint32_t ip_source, uint32_t ip_dest)
{ 
	curr_pack->ip.ip_src = convertInt32(ip_source);
	curr_pack->ip.ip_dst = convertInt32(ip_dest);
	curr_pack->ip.ip_sum = 0;
	curr_pack->ip.ip_sum = in_cksum( (unsigned short * ) &curr_pack->ip , sizeof(_ip) );
}

void inverte_eth()
{
	u_int8_t mac[6];
	memcpy(&mac[0],&curr_pack->eth.ether_dhost[0],6);
	memcpy(&curr_pack->eth.ether_dhost[0],&curr_pack->eth.ether_shost[0],6);
	memcpy(&curr_pack->eth.ether_shost[0],&mac[0],6);
	//free(mac);
}
void inverte_udp()
{
	uint16_t port_aux = curr_pack->udp.uh_sport; 
	curr_pack->udp.uh_sport = curr_pack->udp.uh_dport;
	curr_pack->udp.uh_dport = port_aux;
}

void monta_DHCP(unsigned char type)
{
	inverte_eth();
	monta_ip(my_ip, BROADCAST_ADDR);
	inverte_udp();

	curr_pack->dhcp.op = 2; //Op Code
	curr_pack->dhcp.yiaddr = convertInt32(net_ip + (next_free_ip++)); //Your IP Address
	
	memcpy(&curr_pack->dhcp.options[0],0,DHCP_MAX_OPTION_LEN);

	monta_options(( options_field * ) &curr_pack->dhcp.options[0],type);
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

	struct ifreq ifr;

    /* Inicializa com 0 os bytes de memoria apontados por ifr. */
	memset(&ifr, 0, sizeof(ifr));

	/* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
	to.sll_protocol= htons(ETH_P_ALL);
	to.sll_ifindex = 2; /* indice da interface pela qual os pacotes serao enviados */

	memcpy (to.sll_addr, curr_pack->eth.ether_dhost, 6);
	len = sizeof(struct sockaddr_ll);

	monta_pacote();

	if(sendto(sock, (char *) buff, sizeof(buff), 0, (struct sockaddr*) &to, len)<0)
			printf("sendto maquina destino.\n");
}

int main(int argc,char *argv[])
{
	printf("Iniciando o sniffer\n\n");
	GetIPDaRede(my_ip, net_ip);
	EscreveInformacoesIP(&my_ip, &net_ip);

	unsigned char x[200];

    /* Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro na criacao do socket.\n");
        exit(1);
 	}

	bool recebeuDhcpDiscover = false;
	int posicaoNoBuffer = 0;

	while(1)
	{
		int err_no = 0;
		err_no = recv(sock,(char *) &buff, sizeof(buff), 0x0);

		//Le mensagens
		if(!err_no || err_no == -1){
			continue;
		}
			 
		posicaoNoBuffer = 0;
		memcpy(&curr_pack->eth, &buff, sizeof(curr_pack->eth));
		posicaoNoBuffer = sizeof(curr_pack->eth);

		//Verifica o tipo de protocolo no ethernet
		if(ntohs(curr_pack->eth.ether_type) == ETHERTYPE_IP
			&& 	curr_pack->eth.ether_shost[0] == 0xa4
			&&	curr_pack->eth.ether_shost[1] == 0x1f
			&&	curr_pack->eth.ether_shost[2] == 0x72
			&&	curr_pack->eth.ether_shost[3] == 0xf5
			&&	curr_pack->eth.ether_shost[4] == 0x90
			&&	curr_pack->eth.ether_shost[5] == 0x8f
		)
		{
				//carrega ip header
				printf("a) ");
				for (int i = 0; i < 14; i++)
				{
					printf("%x ",(int)buff[posicaoNoBuffer + i]);
				}

				memcpy(&curr_pack->ip, &buff[posicaoNoBuffer], sizeof(curr_pack->ip));

				printf("\nb) ");
				//carrega ip header
				for (int i = 0; i < 14; i++)
				{
					printf("%x ",(int)buff[posicaoNoBuffer + i]);
				}
				posicaoNoBuffer += sizeof(_ip);
				//printf("%i\n",posicaoNoBuffer);

    			memcpy(&curr_pack->udp, &buff[posicaoNoBuffer], sizeof(_udp));
				posicaoNoBuffer += sizeof(_udp);
				//printf("%i\n",posicaoNoBuffer);

				printf("ipv: %x\nlen: %x\n\n",curr_pack->ip.ip_v,curr_pack->ip.ip_hl);
				printf("ip_tos: %x\nlen: %x\n\n",curr_pack->ip.ip_tos,curr_pack->ip.ip_len);
				printf("ip_id: %x\nip_off: %x\n\n",curr_pack->ip.ip_id,curr_pack->ip.ip_off);
				printf("ip_ttl: %x\nip_p: %x\n\n",curr_pack->ip.ip_ttl,curr_pack->ip.ip_p);
				printf("protocol: %x\ndPort: %x\n\n",curr_pack->ip.ip_p,curr_pack->udp.uh_dport);
				if (curr_pack->ip.ip_p == 17 && curr_pack->udp.uh_dport == 67) //UDP
				{
					//carrega ip header
					
					memcpy(&curr_pack->dhcp, &buff[posicaoNoBuffer], sizeof(_dhcp));
					posicaoNoBuffer += sizeof(_dhcp);
					printf("recebeu discover\n");
					int * options = (int *)&(curr_pack->dhcp.options[0]);

					if(*options == DHCPDISCOVER) //DHCP Discover
					{
						monta_DHCP(DHCPOFFER);
						recebeuDhcpDiscover = true;
					}
					else if(*options == DHCPREQUEST)
					{
						monta_DHCP(DHCPACK);
						recebeuDhcpDiscover = true;
					}
				}
		}
		
		//Se DHCP Discovery identificada...
		if (recebeuDhcpDiscover)
		{
			enviaPacote();
		}
	}
	return 0;
}
