#include "Helpers.cpp"

void load_ips(uint32_t my_ip*, uint32_t net_ip*, uint32_t NET_MASK)
{

	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;

	getifaddrs (&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) 
	{
		if (ifa->ifa_addr->sa_family==AF_INET) 
		{
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			printf("IP: %s \n",inet_ntoa(sa->sin_addr));
			my_ip = convertToInt32(sa->sin_addr);

			net_ip = my_ip & NET_MASK;
			break;
		}
	}

}

