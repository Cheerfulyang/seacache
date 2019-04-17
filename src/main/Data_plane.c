
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>


#include "Data_plane.h"
#include "util.h"

#define DATA_PLANE_LOG(...) printf("[DATA PLANE LOG]: " __VA_ARGS__)
#define DATA_PLANE_WARN(...) printf("[DATA PLANE WARN]: " __VA_ARGS__)

void reset_stats(void) {
	uint8_t lcore_id, nb_lcores;
	nb_lcores = get_nb_lcores_available();
	for(lcore_id = 0; lcore_id < nb_lcores; lcore_id++) {
		if(!rte_lcore_is_enabled(lcore_id)) {
			continue;
		}        
	    lcore_conf[lcore_id].stats.int_recv = 0;
            lcore_conf[lcore_id].stats.int_dram_hit = 0;
            lcore_conf[lcore_id].stats.int_ssd_hit  = 0;
            lcore_conf[lcore_id].stats.int_no_hit   = 0;

            lcore_conf[lcore_id].stats.total_number = 0;
            lcore_conf[lcore_id].stats.total_cpu_cycle = 0;

            lcore_conf[lcore_id].stats.nb_chunk_write_to_ssd  = 0;
            lcore_conf[lcore_id].stats.nb_chunk_read_from_ssd = 0;
        
	    lcore_conf[lcore_id].stats.data_recv = 0;
	    lcore_conf[lcore_id].stats.data_sent = 0;
            lcore_conf[lcore_id].stats.nic_pkt_drop = 0;
	    lcore_conf[lcore_id].stats.sw_pkt_drop = 0;
	    lcore_conf[lcore_id].stats.malformed = 0;
	}
}

void print_stats(void) {
    uint8_t lcore_id;
    struct stats global_stats;
    /* Init global stats */
    global_stats.int_recv = 0;
    global_stats.int_dram_hit = 0;
    global_stats.int_ssd_hit  = 0;
    global_stats.int_no_hit   = 0;

    global_stats.total_number    = 0;
    global_stats.total_cpu_cycle = 0;

    global_stats.nb_chunk_write_to_ssd  = 0;
    global_stats.nb_chunk_read_from_ssd = 0;
    
    global_stats.data_recv = 0;
    global_stats.data_sent = 0;
    global_stats.nic_pkt_drop = 0;
    global_stats.sw_pkt_drop = 0;
    global_stats.malformed = 0;
    printf("Statistics:\n");


	for(lcore_id = 0; lcore_id < APP_MAX_LCORES; lcore_id++) {
		if(!rte_lcore_is_enabled(lcore_id)) {
			continue;
		}
		printf(" [LCORE %u]:\n", lcore_id);
		printf("    Interest recv:      %-15u\n", lcore_conf[lcore_id].stats.int_recv);
        
                printf("    CS Dram hits:       %-15u\n", lcore_conf[lcore_id].stats.int_dram_hit);
                printf("    CS SSD  hits:       %-15u\n", lcore_conf[lcore_id].stats.int_ssd_hit);
                printf("    CS NO   hits:       %-15u\n", lcore_conf[lcore_id].stats.int_no_hit);

                printf("    chunk write to SSD:   %-15u\n", lcore_conf[lcore_id].stats.nb_chunk_write_to_ssd);
                printf("    chunk read from SSD:  %-15u\n", lcore_conf[lcore_id].stats.nb_chunk_read_from_ssd);
        
		printf("    Data received:      %-15u\n", lcore_conf[lcore_id].stats.data_recv);
		printf("    Data sent:          %-15u\n", lcore_conf[lcore_id].stats.data_sent);
		printf("    Packet drops (NIC): %-15u\n", lcore_conf[lcore_id].stats.nic_pkt_drop);
		printf("    Packet drops (SW):  %-15u\n", lcore_conf[lcore_id].stats.sw_pkt_drop);
		printf("    Malformed:          %-15u\n", lcore_conf[lcore_id].stats.malformed);
        
		global_stats.int_recv      += lcore_conf[lcore_id].stats.int_recv;

                global_stats.int_dram_hit  += lcore_conf[lcore_id].stats.int_dram_hit;
                global_stats.int_ssd_hit   += lcore_conf[lcore_id].stats.int_ssd_hit;
                global_stats.int_no_hit    += lcore_conf[lcore_id].stats.int_no_hit;

                global_stats.total_number    += lcore_conf[lcore_id].stats.total_number;
                global_stats.total_cpu_cycle += lcore_conf[lcore_id].stats.total_cpu_cycle;

                global_stats.nb_chunk_write_to_ssd  += lcore_conf[lcore_id].stats.nb_chunk_write_to_ssd;
                global_stats.nb_chunk_read_from_ssd += lcore_conf[lcore_id].stats.nb_chunk_read_from_ssd;
        
		global_stats.data_recv     += lcore_conf[lcore_id].stats.data_recv;
		global_stats.data_sent     += lcore_conf[lcore_id].stats.data_sent;
		global_stats.nic_pkt_drop  += lcore_conf[lcore_id].stats.nic_pkt_drop;
		global_stats.sw_pkt_drop   += lcore_conf[lcore_id].stats.sw_pkt_drop;
		global_stats.malformed     += lcore_conf[lcore_id].stats.malformed;
	}
	printf("  [GLOBAL]:\n");
	printf("    Interest recv:      %-15u\n", global_stats.int_recv);
        printf("    CS Dram hits:       %-15u\n", global_stats.int_dram_hit);
        printf("    CS SSD  hits:       %-15u\n", global_stats.int_ssd_hit);
        printf("    CS NO   hits:       %-15u\n", global_stats.int_no_hit);

        printf("    packet number:      %lu\n", global_stats.total_number);
        printf("    cpu    number:      %lu\n", global_stats.total_cpu_cycle);
    if( global_stats.total_number != 0 )
        printf("    Average CPU number: %f\n", (float)global_stats.total_cpu_cycle/(float)global_stats.total_number);

        printf("    Seg write to SSD:   %-15u\n", global_stats.nb_chunk_write_to_ssd);
        printf("    Seg read from SSD:  %-15u\n", global_stats.nb_chunk_read_from_ssd);
    
	printf("    Data received:      %-15u\n", global_stats.data_recv);
	printf("    Data sent:          %-15u\n", global_stats.data_sent);
	printf("    Packet drops (NIC): %-15u\n", global_stats.nic_pkt_drop);
	printf("    Packet drops (SW):  %-15u\n", global_stats.sw_pkt_drop);
	printf("    Malformed:          %-15u\n", global_stats.malformed);
	printf("=== END ===\n");

    fflush( stdout );
    
}




int seanet_packet_process_loop(__attribute__((unused)) void *arg) {
	
    struct app_lcore_params *conf;
    struct app_lcore_params *conf_write; 
    struct app_lcore_params *conf_tx;  
    struct rte_mbuf   *mbuf = NULL ;

    int8_t  ret;
    
    unsigned lcore_id, socket_id;
    struct ether_hdr  *eth_hdr;

    struct seanet_hdr *id_hdr;
    struct seadp_hdr  *seadp_hdr;
    struct ipv4_hdr   *ipv4_hdr;

    char src_eid[EID_LEN_HEX + 1] ;
    char dst_eid[EID_LEN_HEX + 1] ;
    char *payload;
    uint32_t offset, chunk_total_len;
    uint16_t ip_payload_len;
  
    lcore_id  = rte_lcore_id();
    socket_id = rte_lcore_to_socket_id(lcore_id); 

	DATA_PLANE_LOG("[LCORE_%u] the worker core has Started\n", lcore_id);

	/* Get core configuration */
    conf = &lcore_conf[lcore_id];
    conf_write = &lcore_conf[lcore_id+12];

	
	
	while (1) {
		// get a notify message from Dispatch core and process it. 
        // update hash table for write operation 
        // or prepare the data packet to send to user 
       	if(rte_ring_dequeue(conf->recv_ring, (void **)&mbuf) < 0)
        {
             continue;
        }
        if(mbuf->ol_flags ==  TYPE_DATA ) 
        	{
        	 	conf->stats.data_recv += 1;
                DATA_PLANE_LOG("I have received a data packet!\n ");
                eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
                ipv4_hdr = (struct ipv4_hdr *)RTE_PTR_ADD(eth_hdr, sizeof(struct ether_hdr));
                ip_payload_len = rte_be_to_cpu_16(ipv4_hdr->total_length);
                id_hdr = (struct seanet_hdr *)RTE_PTR_ADD(ipv4_hdr,sizeof(struct ipv4_hdr));
		
		        uint16_t  seadp_packet_order;
                //memcpy (src_eid,id_hdr->id_src_eid,EID_LEN);
		        char_array_2_hex_string(src_eid, id_hdr->id_src_eid,EID_LEN);
                src_eid[40] = '\0';
                //DATA_PLANE_LOG("SRC EID IS %s\n", src_eid);
	            seadp_hdr = (struct seadp_hdr *)RTE_PTR_ADD(id_hdr,sizeof(struct seanet_hdr));
        		chunk_total_len = rte_be_to_cpu_32(seadp_hdr->seadp_chunk_total_len);
        		seadp_packet_order = rte_be_to_cpu_16(seadp_hdr->seadp_packet_order);
                DATA_PLANE_LOG("CHUNK_TOTAL_LEN is %d\n",chunk_total_len);
        		DATA_PLANE_LOG("SEADP PACKET ORDER IS %d\n", seadp_packet_order);
        		offset = rte_be_to_cpu_32(seadp_hdr-> seadp_packet_offset);
                payload = (char *)RTE_PTR_ADD(seadp_hdr,sizeof(struct seadp_hdr));
		        DATA_PLANE_LOG("OFFSET IS :%d\n", offset);
                ret = cs_two_insert_with_hash(conf->shm_message_pool,conf_write->recv_ring,offset, ip_payload_len, chunk_total_len,conf->cs_two,payload,src_eid);

                if(ret != 0){
                if(ret == -ENOSPC){
                        DATA_PLANE_WARN("No available hash table entry for this chunk \n");
                }
            }  
            rte_pktmbuf_free(mbuf);

        	}else if(mbuf->ol_flags ==  TYPE_REQ)
        	{
                if (socket_id == 0)
                     { 
                        conf_tx = &lcore_conf[TX_LCORE_FIRST];
                     }else if(socket_id == 1)
                     {
                        conf_tx = &lcore_conf[TX_LCORE_SECOND];   
                     }

                conf->stats.int_recv++;
        	DATA_PLANE_LOG("I have received a request packet!\n ");
                eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
                ipv4_hdr = (struct ipv4_hdr *)RTE_PTR_ADD(eth_hdr, sizeof(struct ether_hdr));
                id_hdr = (struct seanet_hdr *)RTE_PTR_ADD(ipv4_hdr,sizeof(struct ipv4_hdr));

                char_array_2_hex_string(dst_eid, id_hdr->id_dst_eid,EID_LEN);
                dst_eid[40] = '\0';

                ret = cs_two_lookup_with_hash(conf->shm_message_pool,conf_tx->send_ring, conf_write->recv_ring, conf->cs_two , dst_eid);
                
                if(ret == CACHE_NO_HIT){
                    DATA_PLANE_WARN("we don't have this chunk! \n");
                    conf->stats.int_no_hit++;
                    rte_pktmbuf_free(mbuf);
                }else if(ret == CACHE_HIT_ON_FISK )
                {   
                    DATA_PLANE_LOG("LCORE_%u: Content hit in the Fisk! we will put it to TX core from write core!\n", rte_lcore_id());
                    conf->stats.int_ssd_hit++;
                    rte_pktmbuf_free(mbuf);
                }else if(ret == CACHE_HIT_ON_DRAM)
                {   
                    DATA_PLANE_LOG("LCORE_%u: CS hit in the DRAM! we will have put it to TX core!\n", rte_lcore_id());
                    conf->stats.int_dram_hit++;
                    rte_pktmbuf_free(mbuf);
                }

        	}

        }

}
