in_addr convertInt32(u_int32_t toConvert)
{
	return *( struct in_addr * ) &toConvert;
}

u_int32_t convertToInt32(struct in_addr toConvert)
{
	return *( u_int32_t * ) &toConvert;
}

void ip_to_string(int * ip, char * out)
{
    	sprintf(out, "%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
}
