#include "sender.h"

//#define rte_pktmbuf_mtod(m, t) ((t)((char *)(m)->buf_addr + (m)->data_off))
//#define RTE_PTR_ADD(ptr, x) ((void *)((uintptr_t)(ptr) + (x)))

#define rte_pktmbuf_mtod(m, t) ((t)((char *)(m)->buf_addr + (m)->data_off))

#define V4_HEADER_LEN 84
#define PAYLOAD_LEN 1300
#define reg_portid 1
#define IP_HDR_LEN 20
#define SEANET_HDR_LEN 44
#define SEADP_HDR_LEN 20

#ifndef SEADP_H

#define SEADP_H 1

#define SIP "192.168.101.16"
#define CHUNK_TLEN 2097152

#endif

int check_link_status(uint16_t nb_ports)
{
	struct rte_eth_link link;
	uint8_t port;

	for (port = 0; port < nb_ports; port++)
	{
		rte_eth_link_get(port, &link);

		if (link.link_status == 0)
		{
			printf("Port: %u Link DOWN\n", port);
			//return -1;
		}

		printf("Port: %u Link UP Speed %u\n", port, link.link_speed);
	}

	return 0;
}

unsigned short checksum(unsigned short *buffer, long size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		cksum += *(unsigned char *)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
	//if size if odd,auto fill 0x00
}

int Port_send_burst(struct mbuf_table *tx_mbuf, unsigned n, uint8_t port, uint16_t queue_id)
{
	struct rte_mbuf **m_table;
	unsigned ret;
	//struct ether_hdr *eth;
	//int i;

	//m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;
	m_table = tx_mbuf->m_table;
	//printf("port is %d\n",port);
	/* eth = rte_pktmbuf_mtod(*m_table, struct ether_hdr *);
	printf("dmac:");
	for (i = 0; i < 6; i++)
	{
		printf("%x", eth->d_addr.addr_bytes[i]);
	}
	printf("\n");
	
	struct ipv4_hdr *ip = (struct ipv4_hdr *)RTE_PTR_ADD(eth, sizeof(struct ipv4_hdr));
	uint16_t ip_total_len = ip->total_length;
	printf("ip total len is %u\n", ip_total_len); */
	port = 1;
	ret = rte_eth_tx_burst(port, queue_id, m_table, (uint16_t)n);
	printf("ret is %d\n", ret);
	//ret = check_link_status(2);
	//port_statistics[port].tx += ret;
	if (unlikely(ret < n))
	{
		//port_statistics[port].dropped += (n - ret);
		do
		{
			printf("there are %d  pkt not send\n", n - ret);
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

int send_packet(struct rte_mbuf *m, struct mbuf_table *tx_mbuf, uint8_t port, uint16_t queue_id)
{
	unsigned len;

	len = tx_mbuf->len;
	tx_mbuf->m_table[len] = m;
	len++;
	//printf("send packet 1: len: %d\n",len);
	//printf("send packet 1: MAX_PKT_BURST: %d\n",MAX_PKT_BURST);
	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST))
	{
		printf("send packet 2\n");
		Port_send_burst(tx_mbuf, MAX_PKT_BURST, port, queue_id);
		len = 0;
	}

	tx_mbuf->len = len;
	return 0;
}

// unsigned char set_cflags(chunk){
// 	return 0;
// }

int chunk_sender(struct chunk_msg_desc *chunk, struct mbuf_table *tx_mbuf, struct app_lcore_params *conf, uint16_t queue_id)
{

	//struct send_param mysend_info;
	struct rte_mbuf *m;
	m = &chunk->mbuf;
	struct rte_mempool *pool = NULL;
	pool = conf->pktmbuf_pool;

	//m = rte_pktmbuf_alloc(pool);
	int ret = -1;
	struct ether_hdr *eth, *eth_send;
	struct ipv4_hdr *ip, *ip_send;
	struct seanet_hdr *seanet, *seanet_send;
	struct seadp_hdr *seadp, *seadp_send;

	unsigned int offset;
	unsigned int data_len;
	unsigned int packet_number, i, pn;

	//LogWrite(DEBUG,"%s \n","Get chunk_msg_desc, begin to proccess!");
	/* pkt head parse */
	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ip = (struct ipv4_hdr *)RTE_PTR_ADD(eth, sizeof(struct ether_hdr));
	seanet = (struct seanet_hdr *)RTE_PTR_ADD(ip, sizeof(struct ipv4_hdr));
	seadp = (struct seadp_hdr *)RTE_PTR_ADD(seanet, sizeof(struct seanet_hdr));

	//mysend_info = chunk->send_info;

	/* swap mac */
	uint8_t d_addr_bytes[6];
	uint8_t s_addr_bytes[6];
	d_addr_bytes[0] = 0x52;
	d_addr_bytes[1] = 0x54;
	d_addr_bytes[2] = 0x00;
	d_addr_bytes[3] = 0x80;
	d_addr_bytes[4] = 0x2d;
	d_addr_bytes[5] = 0xcf;

	s_addr_bytes[0] = 0x90;
	s_addr_bytes[1] = 0xe2;
	s_addr_bytes[2] = 0xba;
	s_addr_bytes[3] = 0x86;
	s_addr_bytes[4] = 0x42;
	s_addr_bytes[5] = 0x3d;
	printf("dmac:");
	for (i = 0; i < 6; i++)
	{
		eth->d_addr.addr_bytes[i] = s_addr_bytes[i];
		printf("%x", eth->d_addr.addr_bytes[i]);
	}
	printf("\ndmac:");
	for (i = 0; i < 6; i++)
	{
		eth->s_addr.addr_bytes[i] = d_addr_bytes[i];
		printf("%x", eth->s_addr.addr_bytes[i]);
	}
	printf("\n");
	eth->ether_type = htons(0x0800);
	/* IP head encapsulate */

	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(V4_HEADER_LEN + PAYLOAD_LEN);
	ip->packet_id = htons(0);
	ip->fragment_offset = htons(0);
	ip->time_to_live = 0xff;
	ip->next_proto_id = 153;
	ip->hdr_checksum = 0;
	rte_memcpy(&ip->dst_addr, &ip->src_addr, 32);
	ip->src_addr = inet_addr(SIP);
	ip->hdr_checksum = 0;

	/* SEANET head encapsulate */
	//seanet=(struct seanet_hdr*)(packet+sizeof(ipv4_hdr));
	seanet->id_next_head_type = 1;
	seanet->id_length = 44;
	seanet->id_seanet_prot_prop = htons(1);
	printf("flag 5\n");
	//LogWrite(DEBUG,"%s \n","Get chunk for EID:");
	//printf("\n");
	/* SEADP head encapsulate */

	//seadp->seadp_src_port = mysend_info.seadp_src_port;
	//eadp->seadp_dst_port = mysend_info.seadp_dst_port;
	seadp->seadp_packet_type = 0x80; //DAT=1
	seadp->seadp_tran_type_res = 0;
	seadp->seadp_packet_offset = htons(0);
	seadp->seadp_chunk_total_len = htonl(chunk->chunk_size);

	/* judge last segment */
	data_len = SIZE_OF_ONE_CHUNK; // data_len = chunk->chunk_size
	offset = 0;
	packet_number = (data_len / PAYLOAD_LEN) + 1;

	//LogWrite(DEBUG,"%s %d \n","total packet number :", packet_number);
	printf("total packet number : %d\n", packet_number);

	pn = 0;

	struct rte_mbuf *my_mbuf[packet_number];
	for (i = 0; i < packet_number; i++)
	{
		my_mbuf[i] = rte_pktmbuf_alloc(pool);
	}
	printf("malloc finish\n");

	//ret = check_link_status(2);


	while (offset < data_len)
	{

		rte_memcpy(my_mbuf[pn], m, sizeof(struct rte_mbuf));
		eth_send = rte_pktmbuf_mtod(my_mbuf[pn], struct ether_hdr *);
		ip_send = (struct ipv4_hdr *)RTE_PTR_ADD(eth_send, sizeof(struct ether_hdr));
		seanet_send = (struct seanet_hdr *)RTE_PTR_ADD(ip_send, sizeof(struct ipv4_hdr));
		seadp_send = (struct seadp_hdr *)RTE_PTR_ADD(seanet_send, sizeof(struct seanet_hdr));

		seadp_send->seadp_packet_type = seadp_send->seadp_packet_type | (0x80);
		seadp_send->seadp_packet_offset = htonl(offset);
		seadp_send->seadp_packet_order = htons(pn);
		

		int len1 = my_mbuf[pn]->pkt_len;
		int len2 = my_mbuf[pn]->data_len;
		printf("len1 is %d . len2 is %d\n", len1, len2);
		//printf("Message: %02x\n", (packet+20+44+20));
		/* write chunk_offset into payload according to */
		if (offset + PAYLOAD_LEN >= data_len)
		{ //LP
			printf("last packet.\n");
			seadp_send->seadp_tran_type_res = htons(0x1000); //LP

			unsigned short payload = data_len - offset;
			my_mbuf[pn]->pkt_len = ETH_HEAD_LEN + IP_HEAD_LEN + ID_HEAD_LEN + SEADP_HEAD_LEN + payload;
			my_mbuf[pn]->data_len = my_mbuf[pn]->pkt_len;
			//LogWrite(DEBUG,"%s %d \n","last segment length :", payload);
			printf("payload(last segment length):%d\n", payload);

			//seadp->tflag=4;

			/* write chunk_offset into payload, len:payload */
			//memset(seadp_send + SEADP_HDR_LEN, 0, payload);
			rte_memcpy((char *)seadp_send + SEADP_HDR_LEN, (chunk->chunk) + offset, payload);

			/* caculate checksum and set ip_len */
			seadp_send->seadp_tran_type_res = seadp->seadp_tran_type_res | 0x08;
			seadp_send->seadp_packet_offset = offset + payload;
			seadp_send->seadp_packet_order = (uint16_t)pn;
			seadp_send->seadp_checksum = checksum((unsigned short *)(seadp), 20 + payload);
			ip_send->total_length = htons(V4_HEADER_LEN + payload);

			ret = 0;
		}

		else
		{
			my_mbuf[pn]->pkt_len = ETH_HEAD_LEN + IP_HEAD_LEN + ID_HEAD_LEN + SEADP_HEAD_LEN + PAYLOAD_LEN;
        	my_mbuf[pn]->data_len = my_mbuf[pn]->pkt_len;

			seadp_send->seadp_checksum = checksum((unsigned short *)(seadp), 20 + PAYLOAD_LEN);

			//memset(seadp_send + SEADP_HDR_LEN, 0, PAYLOAD_LEN);
			rte_memcpy((char *)seadp_send + SEADP_HDR_LEN, (chunk->chunk) + offset, PAYLOAD_LEN);
			/* caculate checksum and set ip_len */
			seadp_send->seadp_checksum = checksum((unsigned short *)(seadp), 20 + PAYLOAD_LEN);
			seadp_send->seadp_packet_offset = offset + PAYLOAD_LEN;
			seadp_send->seadp_packet_order = (uint16_t)pn;
			ip_send->total_length = htons(V4_HEADER_LEN + PAYLOAD_LEN);
		}
		//LogWrite(DEBUG,"%s %d %s %d \n","send offset :", offset, " #_#  packet number :", pn);
		uint8_t port = 0;
		ret = send_packet(my_mbuf[pn], tx_mbuf, port, queue_id);

		offset += PAYLOAD_LEN;
		pn++;
	}

	// for (i = 0; i < packet_number; i++)
	// {
	// 	rte_pktmbuf_free(my_mbuf[i]);
	// }

	if (pn != packet_number)
	{
		ret = -1;
		//LogWrite(DEBUG,"%s %d %s %d \n","packet number not enough, pn = ", pn, "packet number = ", packet_number);
		printf("send number error, pn = %d \n", pn);
	}
	return ret;
}

int send_expired(struct mbuf_table *tx_mbuf, uint8_t port, uint16_t queue_id)
{
	unsigned len;
	len = tx_mbuf->len;
	if(len == 0)
	{
		printf("no packt to send\n");
		return -1;
	}
	printf("send %dexpired packet\n", len);
	Port_send_burst(tx_mbuf, len, port, queue_id);
	tx_mbuf->len = 0;
	return 0;
}
