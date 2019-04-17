/*
Author : zengl
build a hash table to manage the hierarchical content store
on dram and cs
*/

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include "cs_two.h"
#include "util.h"



#define CS_TWO_LOG(...)  printf("[CS_TWO_LOG]: " __VA_ARGS__)

#define CS_TWO_WARN(...) printf("[CS_TWO_WARN]: " __VA_ARGS__)

static uint8_t dram_queue_is_full(cs_two_t * cs)
{

    return cs->dram_queue_size == cs->dram_queue_max_element;
}

static uint8_t dram_queue_is_empty(cs_two_t * cs)
{

    return cs->dram_queue_size == 0;
}

uint32_t get_bucket_from_char_eid(char *eid)
{	
	  uint64_t short_eid;
	  uint32_t bucket;
	  char eid_short_array[17];
	  memcpy(eid_short_array,eid,16);
          eid_short_array[16] = '\0';
	  short_eid = htoi(eid_short_array);
          //printf("the short eid is %lu!\n",short_eid);
          bucket  = (uint32_t)(short_eid % (uint64_t)BUCKET_NUM_OF_HASH_TABLE);
          return bucket;
}


uint32_t dram_queue_get_insert_index(cs_two_t * cs)
{
    uint32_t insertPosIndex = 0;
    uint32_t head, tail;

    head    = cs->dram_queue_head_index;
    tail    = cs->dram_queue_tail_index;
    
    if( dram_queue_is_empty(cs) ) {
        cs->dram_queue[head].prev_index = tail;
        cs->dram_queue[tail].next_index = head;
        insertPosIndex = head;

    } else{

        /* first check whether the dram queue is full, if it is full, we need to evict an element */
        if( dram_queue_is_full(cs) ){
            
            uint32_t to_be_tail = cs->dram_queue[tail].prev_index;
            uint32_t to_be_head = tail;

            cs->dram_queue[to_be_head].prev_index   = to_be_tail;
            cs->dram_queue[to_be_head].next_index   = head;

            cs->dram_queue[head].prev_index         = to_be_head;
            cs->dram_queue[to_be_tail].next_index   = to_be_head;

            cs->dram_queue_head_index               = to_be_head;
            cs->dram_queue_tail_index               = to_be_tail;

            insertPosIndex = tail;

            return insertPosIndex;

        } else{
            cs->dram_queue[cs->dram_queue_size].next_index = head;
            cs->dram_queue[cs->dram_queue_size].prev_index = tail;

            cs->dram_queue[head].prev_index = cs->dram_queue_size;
            cs->dram_queue[tail].next_index = cs->dram_queue_size;

            cs->dram_queue_head_index = cs->dram_queue_size;

            insertPosIndex = cs->dram_queue_head_index;
        }

    }

    /* DRAM queue is not full, so we need to add the size */
    cs->dram_queue_size += 1;

    return insertPosIndex;
}

uint32_t 
dram_queue_update_by_visit_index(struct cs_two * cs, uint32_t index)
{
    uint32_t head   = cs->dram_queue_head_index;
    uint32_t tail   = cs->dram_queue_tail_index;

    if( index > cs->dram_queue_max_element - 1 ){
        CS_TWO_LOG( "This index %u exceeds the size of the dram queue \n", index);
        return 0;
    }

    /* we should move the visited item to the front */
    if( index == head ){

    }else if ( index == tail ){

        uint32_t to_be_head = tail;
        uint32_t to_be_tail = cs->dram_queue[tail].prev_index;

        cs->dram_queue[to_be_head].prev_index = to_be_tail;
        cs->dram_queue[to_be_tail].next_index = to_be_head;

        cs->dram_queue_head_index   = to_be_head;
        cs->dram_queue_tail_index   = to_be_tail;       

    }else {

        uint32_t to_be_head = index;

        cs->dram_queue[ cs->dram_queue[index].prev_index ].next_index = cs->dram_queue[index].next_index;
                                                        
        cs->dram_queue[ cs->dram_queue[index].next_index ].prev_index = cs->dram_queue[index].prev_index;
                                                        
        cs->dram_queue[head].prev_index = to_be_head;
        cs->dram_queue[tail].next_index = to_be_head;
        cs->dram_queue[to_be_head].next_index = head;
        cs->dram_queue[to_be_head].prev_index = tail;

        cs->dram_queue_head_index   = to_be_head;
    }

    return 0;
}

static inline int copy_packet_to_dram_buffer(struct   cs_two *cs,
                                             uint16_t dram_index,
                                             char     *payload,
                                             uint16_t ip_packet_total_length,
                                             uint32_t packet_offset,
                                             struct   Bitmap_info *bitmap_info)
{

    /*get real address for packet*/
    uint8_t *addr_offset = cs->dram_queue[dram_index].dram_packet_pool_chunk_addr + packet_offset;
    uint16_t payload_len = ip_packet_total_length - IP_HEAD_LEN - ID_HEAD_LEN - SEADP_HEAD_LEN;
    
    rte_memcpy(addr_offset, payload, payload_len);
    if(set_bitmap_from_offset(1, packet_offset, bitmap_info) == 0)
    {
            CS_TWO_LOG("the packet has copied to dram\n");
    }else
    {
          CS_TWO_LOG("the packet copied to dram failed!\n"); 
     }
    return 0;
}


static inline
void push_chunk_to_other_core(struct rte_mempool *shm_message_pool,struct rte_ring *shm_ring_queue,
                                        cs_two_t *cs,uint16_t  index,
                                        struct chunk_msg_desc * msg)
{
    if( rte_mempool_get(shm_message_pool, (void **)&msg) < 0 ){
                                    CS_TWO_WARN("Not enough entries in the mempool on message packet pool on socket:%u \n", 
                                    rte_socket_id());
    }else {
        rte_memcpy(msg->chunk,
               cs->dram_queue[index].dram_packet_pool_chunk_addr,
               SIZE_OF_ONE_CHUNK);

        if(msg == NULL){
            // This usually can not happen
            CS_TWO_WARN("chunk desc is invalid when pushing a chunk to fisk core \n"); 
            return;
        }

        uint32_t bucket = cs->dram_queue[index].bucket;
        uint8_t  tab = cs->dram_queue[index].tab;

        //Notice: the hash value should be the one that will be replaced, rather the one that will be inserted.
        rte_memcpy (msg->chunk_eid,cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid, EID_LEN_HEX);
        msg->io_type  = REQUEST_IO_WRITE;
    

        if (rte_ring_enqueue(shm_ring_queue, msg) < 0) {
        
            CS_TWO_WARN("Not enough room in the ring to enqueue on socket:%u \n", 
                     rte_socket_id());
        
            rte_mempool_put(shm_message_pool, msg);
            return;
        }
    }   
}

/**
 * judge if a content represented by crc is in cache or not 
 * 
 * @cs
 *    data structure of h2c
 * @crc
       hash value of the content 
 * @return
 *      0:   this content is in cache
 *     -1:   this content is not in cache     
*/
static inline
int lookup_cache(cs_two_t *cs, uint32_t bucket, char * eid, uint32_t offset) 
{

    uint32_t hash_bucket;
    uint8_t  tab;
    uint8_t  exit_flag = 0;  
    int8_t type;
  
    hash_bucket = bucket;   
    
    while(1)
    {
        if( exit_flag == 1 ){
            break;
        }

        for (tab = 0; tab < ENTRY_NUM_OF_ONE_BUCKET; tab++) 
        {
            
            if (likely(cs->hash_table[bucket].entry[tab].busy == 0)) 
            {
                if( bucket == hash_bucket )
                {
                    continue;
                }
                else
                {
                    // In this case, we iterate a bucket, but this element is null, which indicates
                    // that the element must not exist, otherwise this element must be occupied in the
                    // inserting process  
                    exit_flag = 1;   
                    break;        
                }
            }
            

            if(strcmp(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid,eid)!=0)
            {    
                CS_TWO_LOG(" hash[%u].entry[%u] don't have this eid chunk \n",bucket,tab);
                continue;
            }
        
            if( cs->hash_table[bucket].entry[tab].dram_flag == CHUNK_STORE_IN_FISK )//chunk has stored in fisk，rather in dram
                { return 0;}

            if(cs->hash_table[bucket].entry[tab].dram_flag == CHUNK_STORE_IN_DRAM ) //chunk or packet store in DRAM
            { 
                if(cs->hash_table[bucket].entry[tab].assemble_flag == COMPLETE) //chunk has assembled successfully
                {
                    return 0;
                }else{                                                     //chunk has not assembled successfully
                    type = check_bitmap_from_offset(offset,cs->hash_table[bucket].entry[tab].chunk_info->dram_bitmap);                
                    if( type == -1 ){
                        // mistake situation
                         CS_TWO_LOG("mistake situation, after lookup, this packet of chunk does not exist \n");
                        return -1;
                    }else if(type == 1){
                         CS_TWO_LOG("after lookup , this packet of chunk has existed \n");
                        
                        return 0;
                    }else if(type == 0){
                        CS_TWO_LOG("after lookup , this packet of chunk does not existed \n");
                        return -1;
                    }
                }
            }


        }
        bucket = (bucket + 1)%cs->hash_table_num_buckets;  
    }
    
    return -1;
}


//  70.8W, 1280
struct cs_two * cs_two_create(uint32_t hash_table_num_buckets, uint32_t dram_queue_max_element, 
                              int socket)
{
	struct cs_two *cs;
	void *p;
	uint32_t i,j;
      	
	/* Allocate space for cs structure */
	p = rte_zmalloc_socket("CS_TWO", sizeof(struct cs_two), RTE_CACHE_LINE_SIZE, socket);
	if(p == NULL) {
		return NULL;
	}
    
	cs = (struct cs_two *) p;

	cs->hash_table_num_buckets = hash_table_num_buckets;


	/* Allocate space for the actual hash-table */
	p = rte_zmalloc_socket("CS_TWO_HASH_TABLE", cs->hash_table_num_buckets*sizeof(struct cs_two_htbl_bucket),
			                RTE_CACHE_LINE_SIZE, socket);
	if(p == NULL) {
		return NULL;
	}
	
	cs->hash_table = (struct cs_two_htbl_bucket *) p;
    cs->dram_queue_max_element = dram_queue_max_element;

    /* Allocate space for hash table per entry */
    for (i = 0; i < cs->hash_table_num_buckets; i++)
    {
        for (j = 0; j < ENTRY_NUM_OF_ONE_BUCKET; j++)
        {
            p = rte_zmalloc_socket("ENTRY_CHUNK_INFO",sizeof(struct chunk_assemble_info),RTE_CACHE_LINE_SIZE,socket);
              if(p == NULL) {
                  printf("struct chunk_assemble_info malloc fail!\n");
                  return NULL;
               }
            cs->hash_table[i].entry[j].chunk_info = (struct chunk_assemble_info * )p;
            p = rte_zmalloc_socket("BITMAP_INFO",sizeof(struct Bitmap_info),RTE_CACHE_LINE_SIZE,socket);
            if(p == NULL) {
                 printf("struct bitmap_info malloc fail!\n");
                 return NULL;
                }
            cs->hash_table[i].entry[j].chunk_info->dram_bitmap = (struct Bitmap_info *)p;

        }
    }

    /* Allocate space for dram queue */
    p = rte_zmalloc_socket("CS_DRAM_QUEUE", cs->dram_queue_max_element*sizeof(struct cs_dram_queue), 
                            RTE_CACHE_LINE_SIZE, socket);
	if(p == NULL) {
		return NULL;
	}

    cs->dram_queue = (struct cs_dram_queue *)p;
    cs->dram_queue_head_index = 0;
    cs->dram_queue_tail_index = 0;
    cs->dram_queue_size       = 0;

  

	/* Allocate 2MB memory for each chunk in dram queue */
    //1280
	for(i = 0; i < cs->dram_queue_max_element; i++){
		p = rte_zmalloc_socket("QUE_PER_CHUNK_ADDR", SIZE_OF_ONE_CHUNK, 
			                   RTE_CACHE_LINE_SIZE, socket);
		cs->dram_queue[i].dram_packet_pool_chunk_addr = (uint8_t *)p;
	}

    
	return cs;
}




static inline
int8_t __cs_two_insert_with_hash( struct rte_mempool *shm_message_pool, struct rte_ring *shm_ring_queue,
								  uint32_t offset, uint16_t ip_payload_len, 
				      uint32_t chunk_total_len,
	                              cs_two_t *cs, char *payload, 
								  char *eid)
{
    
    struct chunk_msg_desc * msg = NULL;     /**< used to send a message to SSD IO core when dram queue is full */

    uint32_t bucket;
    uint8_t  tab;
    //uint32_t pool_index, j;
    //uint8_t  *packet;                     /**< point to real network packet */ 
     uint32_t i;
    uint32_t dram_queue_insert_index=0;
    uint32_t dram_queue_insert_index_tem;/**< store the index value that will be inserted on the dram queue */
	uint32_t dram_queue_index_from_entry; /**< store the dram queue index from an existed hash table entry */ 
	               	
    uint32_t bucket_of_replaced_chunk, tab_of_replaced_chunk; /**< tmp variable to record chunk that will be replaced */
 	
    //uint64_t begin_rtc, end_rtc; 
    //float    us_value;
    
    bucket = get_bucket_from_char_eid(eid); /**< Get index of corresponding bucket */
    printf("the bucket calcuatd by eid is %d\n", bucket);
    if( lookup_cache(cs, bucket, eid,offset) == 0 ){
        printf("this content has detected in hash table\n");
        return 0;
    }    
   
	
    while( 1 )
    {
    	// Iterate all buckets till find one free and insert 
    	for (tab = 0; tab < ENTRY_NUM_OF_ONE_BUCKET; tab++) 
        {
    		if (likely(cs->hash_table[bucket].entry[tab].busy == 0)) 
            {
                // If the dram queue is full, one of the segments will be replaced based on LRU strategy.
    			if( dram_queue_is_full(cs) )
                {   
                    CS_TWO_LOG("the dram queue is full! we need delete a index in dram queue,and insert new one!\n");
                    dram_queue_insert_index_tem      = dram_queue_get_insert_index(cs);

                    //the dram lru queue is full, if the last index has assemblede succssfully,
                    //we delete it and pull new content into this index.
                    //otherwise, we take content into a loop, we lookup the (index-n)'s index,
                    //if (index-n)'s index.assemble_flag == COMPLETE
                    //we insert new content into (index-n)'s index
                    
                    for(i=0; i<dram_queue_insert_index_tem ;i++)
                    {
                        bucket_of_replaced_chunk = cs->dram_queue[dram_queue_insert_index_tem-i].bucket;
                        tab_of_replaced_chunk    = cs->dram_queue[dram_queue_insert_index_tem-i].tab;
                        if(cs->hash_table[bucket_of_replaced_chunk].entry[tab_of_replaced_chunk].assemble_flag == COMPLETE)
                        {
                            if(cs->hash_table[bucket_of_replaced_chunk].entry[tab_of_replaced_chunk].dram_flag==CHUNK_STORE_IN_BOTH)
                            {
                               CS_TWO_LOG("the content in dram_queue[%u] had stored in fisk,we can delete it's index from dram queue,"
                                           "for put the new one in! but it still sore in fisk\n", dram_queue_insert_index_tem-i);
                               dram_queue_insert_index =  dram_queue_insert_index_tem-i;                                             
                               cs->hash_table[bucket_of_replaced_chunk].entry[tab_of_replaced_chunk].dram_flag    = CHUNK_STORE_IN_FISK;
                               cs->hash_table[bucket_of_replaced_chunk].entry[tab_of_replaced_chunk].dram_index   = 0;
                               
                            }else if(cs->hash_table[bucket_of_replaced_chunk].entry[tab_of_replaced_chunk].dram_flag==CHUNK_STORE_IN_FISK||
                                     cs->hash_table[bucket_of_replaced_chunk].entry[tab_of_replaced_chunk].dram_flag==CHUNK_STORE_IN_DRAM)
                                {
                                    continue;
                                }
                        }

                    }

                    // CS_TWO_LOG("busy:%u, ssd_flag:%u, hash_value:%u, packet buffer:%u, replaced dram index:%u, ssd_index:%u \n",
                    //             cs->hash_table[bucketID_of_replaced_segment].entry[tabID_of_replaced_segment].busy,
                    //             cs->hash_table[bucketID_of_replaced_segment].entry[tabID_of_replaced_segment].ssd_flag, 
                    //             cs->hash_table[bucketID_of_replaced_segment].entry[tabID_of_replaced_segment].segment_hash_value,
                    //             cs->hash_table[bucketID_of_replaced_segment].entry[tabID_of_replaced_segment].dram_bitmap, 
                    //             dram_queue_insert_index,
                    //             cs->hash_table[bucketID_of_replaced_segment].entry[tabID_of_replaced_segment].ssd_index);

                    // if( bitmap_of_replaced_segment == 0 ){
                    //     for(i=0; i<CHUNK_NUM_OF_ONE_SEGMENT; i++){
                    //         recycled_packet_pool_index = cs->dram_queue[dram_queue_insert_index].dram_packet_pool_chunk_index_list[i];
                    //         CS_TWO_LOG("active status:%u \n", cs->dram_packet_pool[recycled_packet_pool_index].active);
                    //     }
                    // }
                    
    				// Clear corresponding entry in hash table  				
                    	
    			}else
                {
    				dram_queue_insert_index = dram_queue_get_insert_index(cs);
    			}    
                


                if(likely(copy_packet_to_dram_buffer(cs, dram_queue_insert_index, payload, ip_payload_len,
                                                     offset, cs->hash_table[bucket].entry[tab].chunk_info->dram_bitmap)) == 0 )
                {



              
                    // Associate this segment with this entry in hash table
                    cs->hash_table[bucket].entry[tab].busy               = 1;
                    cs->hash_table[bucket].entry[tab].dram_flag          = 0;
                    cs->hash_table[bucket].entry[tab].assemble_flag      = NOT_COMPLETE; 
                    cs->hash_table[bucket].entry[tab].dram_index         = dram_queue_insert_index;

                    cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len = 1;
                    cs->hash_table[bucket].entry[tab].chunk_info->dram_bitmap->packet_num_of_one_chunk = cal_packet_num_of_chunk(chunk_total_len); 
                    //tem_chunk_len means that the recent received packet num of chunk 
                    strcpy(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid,eid);          
                   
                    // Associate this chunk with the dram queue. Packet pool index will be associated afterwards.
                    cs->dram_queue[dram_queue_insert_index].req_cnt = 1;
                    cs->dram_queue[dram_queue_insert_index].bucket  = bucket;
                    cs->dram_queue[dram_queue_insert_index].tab     = tab;


                    CS_TWO_LOG("First Packet of the chunk , DRAM Index %u \n",dram_queue_insert_index);

                }
                else
                {
                    // This code can not be reached if we set the packet buffer number of packet pool carefully.
                    CS_TWO_WARN("Insert first chunk, no available dram packet buffer \n");                
                    rte_exit(EXIT_FAILURE, 
                            "lcore_id:%u, insert first chunk, no available dram packet buffer for this chunk! \n", 
                            rte_lcore_id());
                    // return 0;
                }
    			return 0;
    		}else // This hash table entry is occupied, meaning that at least one  packet of the chunk has been received.
            {
                CS_TWO_LOG("This hash table entry is occupied, meaning that at least one  packet of the chunk has been received.\n");
                CS_TWO_LOG("total packet of one chunk num: %u\n", cs->hash_table[bucket].entry[tab].chunk_info->dram_bitmap->packet_num_of_one_chunk);
                CS_TWO_LOG("tem len: %u\n", cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len);
		// The hash value of this chunk should be equal to the one recorded in the dram segment queue.
    			if(likely(strcmp(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid,eid)==0)){
                        
                        if(unlikely(cs->hash_table[bucket].entry[tab].assemble_flag == COMPLETE))
                        {
			  CS_TWO_LOG("we have assembled this chunk, and store it in the system!\n");
                          return 0;
                        }
		         else if(likely(cs->hash_table[bucket].entry[tab].assemble_flag == NOT_COMPLETE)){
                    dram_queue_index_from_entry = cs->hash_table[bucket].entry[tab].dram_index;
                    // CS_TWO_LOG("Insert other chunk %u on dram index %u \n", chunk_id_value, dram_queue_index_from_entry);

        			if( likely(copy_packet_to_dram_buffer(cs, dram_queue_index_from_entry, payload,ip_payload_len,
                                                          offset, cs->hash_table[bucket].entry[tab].chunk_info->dram_bitmap)) == 0 )
                    {
                         CS_TWO_LOG("push a packet of Chunk into DRAM, DRAM Index %u,\n\n", dram_queue_index_from_entry);


                         cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len ++;
                         if(cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len == 
                            cs->hash_table[bucket].entry[tab].chunk_info->dram_bitmap->packet_num_of_one_chunk)
                         {
			    CS_TWO_LOG("this is a chunk total len: %u\n", chunk_total_len); 
			    CS_TWO_LOG("this is a tem len: %u\n", cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len);
                            CS_TWO_LOG("the chunk has been assembled,we push it to the write core!\n");
                            cs->hash_table[bucket].entry[tab].assemble_flag = COMPLETE;
                            cs->hash_table[bucket].entry[tab].dram_flag = CHUNK_STORE_IN_DRAM;
                            push_chunk_to_other_core(shm_message_pool,shm_ring_queue,cs,dram_queue_index_from_entry,msg);                                                               
                                        
                         } 

                    }else
                    {
                        // This code can not be reached if we set the packet buffer number of packet pool carefully.
                        CS_TWO_WARN("Insert packeting,but no available dram packet buffer for him, lcore_id:%u \n",rte_lcore_id());
                        rte_exit(EXIT_FAILURE, "Insert packeting,but no available dram packet buffer for him, lcore_id:%u \n", 
                                               rte_lcore_id());
                        // return 0;
                    }  
                    return 0;
                    }
    			}
				else
				{
                    // This hash table entry is occupied and the hash value of this chunk is not equal to
                    // the existed one in this entry. In this case, we need to iterate the bucket continue.
                    printf("hash[%u].entry[%u]_eid isn't equal to received eid,we lookup for next entry!\n",bucket,tab);                 
                    continue;
                } 
    		}
    	}
        // No available entry in current bucket, linear probing to solve collision
        bucket = (bucket + 1)%cs->hash_table_num_buckets;        
    }    
    
	return -ENOSPC;
}

int8_t cs_two_insert_with_hash( struct rte_mempool *shm_message_pool, struct rte_ring *shm_ring_queue,
                                uint32_t offset,uint16_t ip_payload_len, uint32_t chunk_total_len,
                                cs_two_t *cs, char *payload, 
                                char *eid)
{
    return __cs_two_insert_with_hash(shm_message_pool, shm_ring_queue, offset, ip_payload_len, chunk_total_len,cs, payload, eid);
}

static inline
uint8_t __cs_two_lookup_with_hash(struct rte_mempool *shm_message_pool,
                                  struct rte_ring *send_ring_to_tx, 
                                  struct rte_ring *worker_to_write_ring, 
                                  cs_two_t *cs, char *eid) 
{
    // if( rte_lcore_id() != 1 ){
    //     return NULL;
    // }


    uint32_t bucket,  hash_bucket;
    uint8_t  tab;
    uint32_t dram_queue_index;          /**< used to record index on dram queue  */
    uint8_t  exit_flag = 0;


    struct chunk_msg_desc * a_chunk_msg_desc_to_tx  = NULL; /**< used to send chunk to the tx core when the request hit in the DRAM */ 
    struct chunk_msg_desc * a_chunk_msg_desc_to_write  = NULL; /**< or used to send a a request msg to write core when the chunk is stored on fisk. */    

    bucket = get_bucket_from_char_eid(eid); /**< Get index of corresponding bucket */
    printf("the bucket calcuatd by eid is %d\n", bucket);
    hash_bucket = bucket;   
   
    unsigned lcore_id;


    lcore_id = rte_lcore_id();

    while(1)
    {
        if( exit_flag == 1 ){
            break;
        }

        for (tab = 0; tab < ENTRY_NUM_OF_ONE_BUCKET; tab++) 
        {
            
            if (likely(cs->hash_table[bucket].entry[tab].busy == 0)) 
            {
                if( bucket == hash_bucket )
                {
                    continue;
                }
                else
                {
                    // In this case, we iterate a bucket, but this element is null, which indicates
                    // that the element must not exist, otherwise this element must be occupied in the
                    // inserting process. This can not guarantee that this element does not exist as 
                    // cache replacement occurs 
                    exit_flag = 1;   
                    break;        
                }   
            }
            
            if(strcmp(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid,eid) !=0)
            {
                continue;
            }

           
            printf("the dram_flag is %d!\n",cs->hash_table[bucket].entry[tab].dram_flag);
            // When this chunk is stored on fisk, which means its had been assembled ,we send a msg to write core.
            // and notify write core send chunk to tx core. then we don't need a feedback msg.
            if( cs->hash_table[bucket].entry[tab].dram_flag == CHUNK_STORE_IN_FISK )
            {

                if (cs->hash_table[bucket].entry[tab].assemble_flag == NOT_COMPLETE) 
                {
                     CS_TWO_LOG("error situation, the chunk should have been stored in fisk with assembled state,but it's not!");
                     return CACHE_NO_HIT;   
                }

                /* chunk is stored in fisk */            
                if( rte_mempool_get(shm_message_pool, (void **)&a_chunk_msg_desc_to_tx) < 0 ){
                     CS_TWO_WARN("Not enough entries in the schedule mempool on message packet pool on socket:%u \n", 
                                  rte_socket_id());
                }

                /* Put this message on the ring, so that write IO core can receive it */
                if( a_chunk_msg_desc_to_tx != NULL )
                {
                    a_chunk_msg_desc_to_write->io_type   =  REQUEST_IO_READ;
                    strcpy(a_chunk_msg_desc_to_write->chunk_eid,eid);
                                              
                    if (rte_ring_enqueue(worker_to_write_ring, a_chunk_msg_desc_to_write) < 0) {
                            
                        CS_TWO_WARN("Not enough room in the ring to enqueue on socket:%u \n", 
                                     rte_socket_id());
                            
                        rte_mempool_put(shm_message_pool, a_chunk_msg_desc_to_tx);
                    }else{

                        CS_TWO_LOG("chunk is stored in fisk and a request is sent to write core! \n");
                            
                    }
                        // This can lead to false positive if the hash value of the requested chunk equals to the value recorded
                    return CACHE_HIT_ON_FISK;                          
                }
            }  // chunk is stored in DRAM
            else if(cs->hash_table[bucket].entry[tab].dram_flag == CHUNK_STORE_IN_BOTH)
            {

                CS_TWO_LOG("[lcore:%d]chunk is stored both in DRAM and fisk, we put it to tx core from DRAM priority!\n",lcore_id);

            }else if(cs->hash_table[bucket].entry[tab].dram_flag == CHUNK_STORE_IN_DRAM){
                 
                CS_TWO_LOG("[lcore:%d]we have this eid, we first check whether its assembled! from DRAM\n",lcore_id);
                if(cs->hash_table[bucket].entry[tab].assemble_flag == NOT_COMPLETE)
                {   
                    CS_TWO_LOG("[lcore:%d]chunk has not assembled successfully!request can not hit\n",lcore_id);
                    return CACHE_NO_HIT; 
                }else if(cs->hash_table[bucket].entry[tab].assemble_flag == COMPLETE)
                {

                    CS_TWO_LOG("[lcore:%d]chunk stored in DRAM, we put it to tx core!\n",lcore_id);
                }
            }

                dram_queue_index  = cs->hash_table[bucket].entry[tab].dram_index;
                
                // When the first chunk of a segment gets a cache hit, it indicates that this segment has been requested again
                cs->dram_queue[dram_queue_index].req_cnt += 1;  
                // This chunks will be moved to the head of the dram queue first based on LRU strategy. 
                dram_queue_update_by_visit_index(cs, dram_queue_index); 
                CS_TWO_LOG("update the dram queue because of this chunk request!\n"); 
                
                if( rte_mempool_get(shm_message_pool, (void **)&a_chunk_msg_desc_to_tx) < 0 ){
                     CS_TWO_WARN("Not enough entries in the schedule mempool on message packet pool on socket:%u \n", 
                                  rte_socket_id());
                }

                /* Put this message on the ring, so that tx  core can receive it */
                if( a_chunk_msg_desc_to_tx != NULL )
                {
                a_chunk_msg_desc_to_tx->io_type =  NOTIFY_IO_READ_FINISH;
                strcpy(a_chunk_msg_desc_to_tx->chunk_eid, cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid);
                rte_memcpy(a_chunk_msg_desc_to_tx->chunk, cs->dram_queue[dram_queue_index].dram_packet_pool_chunk_addr, SIZE_OF_ONE_CHUNK);          
                }
                push_chunk_to_other_core(shm_message_pool,send_ring_to_tx,cs,dram_queue_index,a_chunk_msg_desc_to_tx);
                
                CS_TWO_LOG("[lcore:%d]we have pushed the chunk to tx core!\n",lcore_id);

                //发包需要的结构体还没写                 
                return  CACHE_HIT_ON_DRAM;
        }

        bucket = (bucket + 1)%cs->hash_table_num_buckets;  
    }
    
    //We have iterated the designated bucket, but still can not find a matched item.
        CS_TWO_WARN("We have iterated the designated bucket, but still can not find a matched item chunk. \n");
    return CACHE_NO_HIT;
}



uint8_t cs_two_lookup_with_hash(struct rte_mempool *shm_message_pool,
                                struct rte_ring *send_ring_to_tx, 
                                struct rte_ring *worker_to_write_ring, 
                                cs_two_t *cs, char *eid)                                          
{
    return __cs_two_lookup_with_hash(shm_message_pool,send_ring_to_tx, worker_to_write_ring,
                                    cs,eid);
}
