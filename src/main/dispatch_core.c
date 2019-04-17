#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_log.h>


#include "dispatch_core.h"
#include "util.h"

#define DISPATCH_CORE_LOG(...) printf("[DISPATCH CORE LOG]: " __VA_ARGS__)


int dispatch_loop(__attribute__((unused)) void *arg){

	struct 	   app_lcore_params *conf;
	unsigned   lcore_id, socket_id;
	unsigned   worker_id;
	uint8_t    port_id, queue_id;
	struct     rte_mbuf *pkts_burst[MAX_PKT_BURST];   //32

	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr; 
	struct seanet_hdr *id_hdr;
	struct seadp_hdr *seadp_hdr;

	int i,nb_rx;
	char src_eid[EID_LEN_HEX + 1] ;                  
        char dst_eid[EID_LEN_HEX + 1] ;
        char *ring_name;
        struct rte_ring *ring = NULL;

        char src_eid_short_array[5];
        char dst_eid_short_array[5];

	lcore_id  = rte_lcore_id();
	socket_id = rte_socket_id();

	/* Get core configuration */
	conf = &lcore_conf[lcore_id];

	DISPATCH_CORE_LOG("[LCORE_%u] Started\n", lcore_id);
	DISPATCH_CORE_LOG("dispatch work begin!\n");

	/* The core has no RX queues to listen from */
	if (conf->nb_rx_ports == 0) {
		DISPATCH_CORE_LOG("[LCORE_%u] I have no RX queues to read from. I quit\n", lcore_id);
		return -1;
	}

	for (i = 0; i < conf->nb_rx_ports; i++) {
		port_id = conf->rx_queue[i].port_id;
		queue_id = conf->rx_queue[i].queue_id;
		DISPATCH_CORE_LOG("[LCORE_%u] Listening on (port_id=%u, queue_id=%u)\n",
				lcore_id, port_id, queue_id);
	}

	while(1){

		/* Read packet from RX queues */
	   for (i = 0; i < conf->nb_rx_ports; i++) 
           {
		port_id  = conf->rx_queue[i].port_id;
		queue_id = conf->rx_queue[i].queue_id;

		nb_rx    = rte_eth_rx_burst((uint8_t) port_id, queue_id, pkts_burst, MAX_PKT_BURST);
		if (nb_rx == 0) { continue; }
			
		for (i = 0; i < nb_rx; i++){

		eth_hdr = rte_pktmbuf_mtod(pkts_burst[i], struct ether_hdr *);

		if(eth_hdr->ether_type != ETHER_TYPE_IPv4_BE) {

        	DISPATCH_CORE_LOG("LCORE_%u: Received non-IPv4 packet "
	   			"from port %u. Dropping\n", rte_lcore_id(), port_id);
		
		rte_pktmbuf_free(pkts_burst[i]);
		conf->stats.malformed++;
		continue;
		}

		ipv4_hdr = (struct ipv4_hdr *)RTE_PTR_ADD(eth_hdr, sizeof(struct ether_hdr));
		if(ipv4_hdr->next_proto_id != SEANET_PROT) {

       		DISPATCH_CORE_LOG("LCORE_%u: Received IPv4 packet, protocol is %u, but requiring is %u "
				"from port %u. Dropping\n", 
		 		 	rte_lcore_id(), ipv4_hdr->next_proto_id, SEANET_PROT, port_id);
	
		rte_pktmbuf_free(pkts_burst[i]);
		conf->stats.malformed++;
		continue;
		}

		id_hdr = (struct seanet_hdr *)RTE_PTR_ADD(ipv4_hdr,sizeof(struct ipv4_hdr));
		if(id_hdr->id_next_head_type != SEADP_PROT) {

       	        DISPATCH_CORE_LOG("LCORE_%u: Received SEANET packet, protocol is %u, but requiring is %u "
		   			"from port %u. Dropping\n", 
	  		 	rte_lcore_id(), id_hdr->id_next_head_type, SEADP_PROT, port_id);
		
		rte_pktmbuf_free(pkts_burst[i]);
		conf->stats.malformed++;
		continue;
		}

		char_array_2_hex_string(src_eid, id_hdr->id_src_eid,EID_LEN);
                src_eid[40] = '\0';
                RTE_LOG(DEBUG, USER1, "received SRC EID IS %s\n", src_eid);
	        strncpy(src_eid_short_array,src_eid,4);	
	        src_eid_short_array[4] = '\0';
                DISPATCH_CORE_LOG("src_eid_short_array is %s\n",src_eid_short_array );


		char_array_2_hex_string(dst_eid, id_hdr->id_dst_eid,EID_LEN);
                dst_eid[40] = '\0';
                //DISPATCH_CORE_LOG("received DST EID IS %s\n", dst_eid);
		strncpy(dst_eid_short_array,dst_eid,4);	
	        dst_eid_short_array[4] = '\0';
                DISPATCH_CORE_LOG("dst_eid_short_array is %s\n", dst_eid_short_array);
  
		seadp_hdr = (struct seadp_hdr *)RTE_PTR_ADD(id_hdr,sizeof(struct seanet_hdr));


		if(seadp_hdr->seadp_packet_type == DATA_SIGN){
			conf->stats.data_recv += 1;
			pkts_burst[i]->ol_flags = TYPE_DATA;
			worker_id = (htoi(src_eid_short_array)%NUM_OF_WORKER_CORE)+2;
                        RTE_LOG(DEBUG, EAL, "worker id is %d\n", worker_id);
			ring_name = get_rx_queue_name(worker_id, WORKER_2_DISPATCH_RECV_RING_NAME_FLAG);
			ring = rte_ring_lookup(ring_name);
			if (ring == NULL){
				rte_exit(EXIT_FAILURE,
					" core:socket %u has problem getting recv ring, ring_name:%s, lcore_id:%u \n",
						socket_id, ring_name, rte_lcore_id());
					}
			printf("this packet have finish dispatch work! \n\n");
			if (rte_ring_enqueue(ring, (void *)pkts_burst[i]) < 0){
                                         RTE_LOG(DEBUG, EAL,"Not enough room in the ring to enqueue on socket:%u \n",
						rte_socket_id());
						continue;
					}
		}else if(seadp_hdr->seadp_packet_type == REQ_SIGH){
				pkts_burst[i]->ol_flags = TYPE_REQ;
				worker_id = (htoi(dst_eid_short_array)%NUM_OF_WORKER_CORE)+2;
					ring_name = get_rx_queue_name(worker_id, WORKER_2_DISPATCH_RECV_RING_NAME_FLAG);
					ring = rte_ring_lookup(ring_name);
					if (ring == NULL){
							rte_exit(EXIT_FAILURE,
								" core:socket %u has problem getting recv ring, ring_name:%s, lcore_id:%u \n",
								socket_id, ring_name, rte_lcore_id());
					}
					printf("this packet have finish dispatch work! \n\n");
					if (rte_ring_enqueue(ring, (void *)pkts_burst[i]) < 0){
							printf("Not enough room in the ring to enqueue on socket:%u \n",
								rte_socket_id());
							continue;
					}
				}

			}
		}
	}
	return 0;
}
