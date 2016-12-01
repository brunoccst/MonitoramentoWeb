in_addr convertInt32(u_int32_t toConvert)
{
	return *( struct in_addr * ) &toConvert;
}

u_int32_t convertToInt32(struct in_addr toConvert)
{
	return *( u_int32_t * ) &toConvert;
}

