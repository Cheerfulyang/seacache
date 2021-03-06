/*
 * zicco_zeng 
 * 2019/1/15
 *
 */

#ifndef _DEFAULTS_H_
#define _DEFAULTS_H_

#include <inttypes.h>
#include <rte_mbuf.h>
/**
 * @file
 *
 * Default configuration parameters
 *
 * This file contains the default configuration parameters of the H2C
 * router. These parameters can be overridden in the config.h file.
 */



/**************** General machine capabilities ****************/

#define MASTER_LCORE  0
#define DISPATCH_LCORE  1
#define TX_LCORE_FIRST 12
#define TX_LCORE_SECOND 13


/**
* Core dedicated to implement SSD_HDD fisk IO operation. Note that, this configure is reasonable
   when we assume that there are 24 cores. We use 8 write cores
*/
#define NUM_OF_WORKER_CORE  8
#define NUM_OF_WRITE_CORE   8



/* the configure of the core*/

#define APP_MAX_LCORES 24
#define APP_MAX_SOCKETS 2


/**
 * Max number of Ethernet ports available on the system
 */
#define APP_MAX_ETH_PORTS 10

#define NB_PORT_OF_H2C    2

/**************** NIC capabilities and configuration ****************/

/*
 *  * RX and TX Prefetch, Host, and Write-back threshold values should be
 *   * carefully set for optimal performance. Consult the network
 *    * controller's datasheet and supporting DPDK documentation for guidance
 *     * on how these parameters should be set.
 *      */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 0 /**< Default values of RX write-back threshold reg. */

/*
 *  * These default values are optimized for use with the Intel(R) 82599 10 GbE
 *   * Controller and the DPDK ixgbe PMD. Consider using other values for other
 *    * network controllers and/or network drivers.
 *     */
#define TX_PTHRESH 32 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

/**
 * Per-core cache size of packet mempool
 */
#define MEMPOOL_CACHE_SIZE  256
/**
 * Size of an mbuf (i.e. the data structure that containing a packet received
 * from the NIC)
 *
 * Note: Headroom is a free space at the beginning of the packet buffer that is
 * reserved to prepend data to a packet being processed. DPDK headroom value is
 * 128 bytes. We do not need any headroom because we do not need to prepend
 * data. To remove it we need to compile DPDK with setting
 * CONFIG_RTE_PKTMBUF_HEADROOM=0
 */
#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
/**
 * Number of packet buffers per NUMA socket
 */
#define NB_MBUF   32768

/******************* dispatch configuration **********************/

/* Big-endian EtherType fields */
#define ETHER_TYPE_IPv4_BE 0x0008 /**< IPv4 Protocol. */
#define DATA_SIGN 128 //10000000
#define REQ_SIGH  64 //01000000
#define TYPE_DATA	0
#define TYPE_REQ 	1
#define SEANET_PROT 0x99
#define SEADP_PROT  1




/******************* Data plane configuration **********************/

#define SIZE_OF_ONE_CHUNK (2*1024*1024)

/**
 * Max size of burst transmitted to be sent to a TX port in a batch
 */
#define MAX_PKT_BURST 32

/* CS_TWO */
#define ENTRY_NUM_OF_ONE_BUCKET	        4
#define DRAM_LRU_QUEUE_SIZE_PER_CORE	1000

#define EXTEND_FACTOR_OF_HASH_TABLE	4
#define SSD_HDD_CACHE_SIZE	2.7*1024*1024*1024*1024 //original == 5T

#define DISK_CACHE_CHUNK_CAPABILITY	SSD_HDD_CACHE_SIZE/SIZE_OF_ONE_CHUNK //  5T/2M=250W //2.7T/2M = 141.5W error

#define WRITE_CORE_MANAGE_CHUNK_NUM	DISK_CACHE_CHUNK_CAPABILITY/NUM_OF_WRITE_CORE //250W/8=312.5K //141.5W/8=17.7W
#define BUCKET_NUM_OF_HASH_TABLE	(WRITE_CORE_MANAGE_CHUNK_NUM)* EXTEND_FACTOR_OF_HASH_TABLE  
                                        //(312.5K)*4=1250K //17.7*4=70.8W
#define EID_LEN_HEX 40
#define EID_LEN    20
/**
 * Transmission buffer drain period, in microseconds
 *
 * If not enough packets have been received to make a match of MAX_PKT_BURST
 * to forward and BURST_TX_DRAIN_US microseconds have passed since a packet
 * has been received, forward it anyway.
 */
#define BURST_TX_DRAIN_US 100

/* Big-endian EtherType fields */
#define ETHER_TYPE_IPv4_BE 0x0008 /**< IPv4 Protocol. */
#define ETHER_TYPE_IPv6_BE 0xDD86 /**< IPv6 Protocol. */

#define SEANET_DEFAULT_PROTOCOL 0x0099 /**< SEANET Protocol. */

/******************* assemble data structure ***************************/
#define ETH_HEAD_LEN    14
#define IP_HEAD_LEN 	20
#define ID_HEAD_LEN	    44
#define SEADP_HEAD_LEN 	20

/******************* write core structure ***************************/

#define FILESYSTEM_PATH_NAME "/data"
#define REQUEST_IO_WRITE	1
#define REQUEST_IO_READ	        2
#define NOTIFY_IO_WRITE_FINISH	3
#define NOTIFY_IO_READ_FINISH	4
#define NOTIFY_IO_WRITE_FAIL  	5
#define NOTIFY_IO_READ_FAIL 	6

 #define REQUEST_REGISTER	7
 #define REQUEST_CANCEL		8


/**
 * Create ring and memory pool to transfer message between pkt fwd core and SSD IO core
 * This value still needs to be considerd further.
 */

#define RING_DISPATCH_2_WORKER_SIZE          4096 
#define RING_CHUNK_NOTIFY_SHEDULE_SIZE       1024
#define RING_PACKET_IN_SIZE                  2048

#define SCHEDULE_MEMPOOL_SIZE          4096 // orignal 4096     
#define SCHEDULE_MEMPOOL_CACHE_SIZE    512

#define BITMAP_WORD                    8
#define BITMAP_BYTE_LEN   207



struct chunk_msg_desc {
	uint8_t 	io_type;
	char 		chunk_eid[41];
	char 		chunk[SIZE_OF_ONE_CHUNK];
	uint32_t	chunk_size;
	struct rte_mbuf mbuf;
};

struct notify_desc{
        uint8_t  io_type;  
        char    chunk_eid[41];
};



/* 
 ** Including two kinds of elements, i.e., segment_desc and notify_desc
 ** We should allocate the size of the maximum value of these two structures
 */
#define SCHEDULE_MEMPOOL_ELEMENT_SIZE  ( 0 + sizeof(struct chunk_msg_desc)>sizeof(struct notify_desc)?sizeof(struct chunk_msg_desc):sizeof(struct notify_desc) )
//#define SCHEDULE_MEMPOOL_ELEMENT_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

 

#endif /* _DEFAULTS_H_ */


