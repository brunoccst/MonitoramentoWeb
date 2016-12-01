#include <ifaddrs.h>
#include "../Funcionalidades/Conversor.cpp"

//	Analisa a rede e configura os ponteiros passados por parametro com o IP da maquina atual e o IP da rede em que a maquina esta conectada
void GetIPDaRede(uint32_t &ipDaMaquina, uint32_t &ipDaRede)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;

	getifaddrs (&ifap);
	int i = 0;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) 
	{
		if (ifa->ifa_addr->sa_family==AF_INET) 
		{
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			
			// IP da maquina
			ipDaMaquina = convertToInt32(sa->sin_addr);

			// IP da rede
			ipDaRede = ipDaMaquina & convertToInt32(((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr);
		}
		i++;
	}
}

//	Escreve no console o IP da maquina e da rede
void EscreveInformacoesIP(uint32_t *ipDaMaquina, uint32_t *ipDaRede)
{
	printf("IP da maquina .... %s \n",inet_ntoa(convertInt32(*ipDaMaquina)));
	printf("IP da rede ....... %s \n",inet_ntoa(convertInt32(*ipDaRede)));
}
