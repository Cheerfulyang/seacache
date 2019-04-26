/*
Author : zengl
build a hash table to manage the hierarchical content store
on dram and ssd
*/


#ifndef _CS_TWO_H_
#define _CS_TWO_H_

#include "Defaults.h"

 
#define CHUNK_STORE_IN_DRAM	1
#define CHUNK_STORE_IN_FISK	2
#define CHUNK_STORE_IN_BOTH     3

#define NOT_COMPLETE	    0
#define COMPLETE	    1

#define CACHE_NO_HIT        0
#define CACHE_HIT_ON_FISK   1
#define CACHE_HIT_ON_DRAM   2



struct cs_two_htbl_entry {		// Size: 13 bytes   index table
	uint8_t  busy;
	uint8_t  dram_flag;	/**< indicate whether the entire chunk is stored in the DRAM*/
	uint8_t  assemble_flag;
    struct   chunk_assemble_info *chunk_info;
	uint16_t dram_index;				 /**< Index of the entry in the dram queue */
	}  __attribute__((__packed__));


struct cs_two_htbl_bucket {	   // Size: 64 bytes = 1 cache line
	struct  cs_two_htbl_entry  entry[ENTRY_NUM_OF_ONE_BUCKET];
}  __attribute__((__packed__)) __rte_cache_aligned;



struct cs_two {               // Size: 64 bytes = 1 cache line
	struct cs_two_htbl_bucket  *hash_table;
 	uint32_t 				    hash_table_num_buckets;		
 	struct cs_dram_queue       *dram_queue;
    uint32_t                    dram_queue_max_element;
    uint32_t                    dram_queue_head_index;
    uint32_t                    dram_queue_tail_index;
    uint32_t                    dram_queue_size;              
    /**< current item number in dram queue */
  } __attribute__((__packed__)) __rte_cache_aligned ;

typedef struct cs_two  cs_two_t;

struct cs_dram_queue  {          // Size: 64 bytes = 1 cache line
	uint8_t  req_cnt;                       /**< request count of this chunk */
	uint32_t prev_index;                     /**< previous index in dram LRU queue */
	uint32_t next_index;                     /**< next index in dram LRU queue */
	uint32_t bucket;			              /**< bucket in the hash table */
	uint8_t  tab;					          /**< offset in the bucket */
	uint8_t *dram_packet_pool_chunk_addr; 
/**< index in the dram buffer pool, needed to be allocated first */
} __attribute__((__packed__)) __rte_cache_aligned;


struct chunk_assemble_info   //Size 30 bytes 64 bytes = 1 cache line
{
	struct   Bitmap_info *dram_bitmap;          /**< packets stored in the DRAM map*/	
	uint16_t tem_chunk_len;					   /*the num of received packet*/ 
	char     chunk_eid[EID_LEN_HEX+1];		                  /**< chunk eid value */
}__attribute__((__packed__)) __rte_cache_aligned;

struct Bitmap_info{
     uint16_t packet_num_of_one_chunk;	      // the total num packet of a chunk
     uint8_t  bitmap[BITMAP_BYTE_LEN];
};


uint32_t get_bucket_from_char_eid(char *eid);

uint32_t dram_queue_get_insert_index(cs_two_t * cs);

uint32_t 
dram_queue_update_by_visit_index(struct cs_two * cs, uint32_t index); 

struct cs_two * cs_two_create(uint32_t hash_table_num_buckets, uint32_t dram_queue_max_element, 
                              int socket);

int8_t cs_two_insert_with_hash( struct rte_mempool *shm_message_pool, struct rte_ring *shm_ring_queue,
								uint32_t offset, uint16_t ip_payload_len, uint32_t chunk_total_len,
	                            cs_two_t *cs,  char *payload, 
								char *eid);


uint8_t cs_two_lookup_with_hash(struct rte_mempool *shm_message_pool,
                                struct rte_ring *send_ring_to_tx, 
                                struct rte_ring *worker_to_write_ring, 
                                cs_two_t *cs,
																char *eid,
																struct rte_mbuf   *mbuf);                                          


#endif /* _CS_TWO_H_ */
