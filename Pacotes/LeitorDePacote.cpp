void printEthernet(struct ether_header *eth)
{
	printf("[ETHERNET]\n");
	printf("	MAC Source ......... %x:%x:%x:%x:%x:%x\n",
		eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
		eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	printf("	MAC Dest ........... %x:%x:%x:%x:%x:%x\n",
		eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
		eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	printf("	Type ............... %i\n", eth->ether_type);
}

// Escreve no console todos os pacotes
void printPackage(struct ether_header *eth)
{
	printEthernet(eth);
	//printIp(ip);
	//printUdp(ip);
	//printDhcp(ip);
}
