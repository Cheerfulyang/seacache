/*
Author: YH Li
Build a dedicated lcore to implement file system IO operation
*/

#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_common.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include<sys/time.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include "sender.h"

#include "tx_action.h"

#define TX_LOG(...) printf("[TX_IOG]: " __VA_ARGS__)
#define TX_WARN(...) printf("[TX_WARN]: " __VA_ARGS__)

/*
*暂定的消息结构体（chunk_msg_desc_from_worker\chunk_msg_desc_from_writer可以用相同的结构体）

struct chunk_msg_desc {
    uint8_t     io_type;
    char        chunk_eid[20];
    char        chunk[SIZE_OF_ONE_CHUNK];
    uint32_t    chunk_size;
    struct send_param send_info;
}

struct send_param{
    unsigned    portid;
    uint32_t    dst_addr;
    char        id_src_eid[20];                 
    char        id_dst_eid[20];
    uint16_t    seadp_src_port;
    uint16_t    seadp_dst_port;
    uint8_t     seadp_cache_type;
}
*/

int tx_process_loop(__attribute__((unused)) void *arg)
{
    //self
    struct chunk_msg_desc *a_chunk_msg_desc_from_worker = NULL; /**< used to send a message to writer core when dram queue is full. */
    struct chunk_msg_desc *a_chunk_msg_desc_from_writer = NULL; /**< used to send a message to tx core from writer core. */

    struct rte_mempool *pool = NULL;

    unsigned lcore_id;
    unsigned  socket_id;
    uint16_t queue_id;

    struct app_lcore_params *conf;
    struct mbuf_table *tx_mbuf;
    
    
    //tx_mubf->m_table;

    //int writen_num = 0;

    //store temp info for a_notify_desc
    //char chunk_temp[SIZE_OF_ONE_CHUNK] = {0};

    struct rte_ring *recv_ring_from_worker;
    struct rte_ring *recv_ring_from_writer;

    // NUMA node0 CPU(s):     0,2,4,6,8,10,12,14,16,18,20,22
    // NUMA node1 CPU(s):     1,3,5,7,9,11,13,15,17,19,21,23

    lcore_id = rte_lcore_id();
    socket_id = rte_lcore_to_socket_id(lcore_id); //use to get ring and mempool with tx core

    conf = &lcore_conf[lcore_id];
    recv_ring_from_writer = conf->recv_ring;
    recv_ring_from_worker = conf->send_ring;
    pool = conf->shm_message_pool;
    queue_id = conf->tx_queue_id[0];//the same core has the same queue_id

    //tx_mbuf = (struct mbuf_table *)malloc(sizeof(struct mbuf_table ));
    tx_mbuf = (struct mbuf_table *)rte_zmalloc_socket("MBUF_TABLE",
                    sizeof(struct mbuf_table ),RTE_CACHE_LINE_SIZE,socket_id);
    tx_mbuf->len = 0;
    /*看TODO对应要完成的功能
    *
    * a_chunk_msg_desc_from_worker\a_chunk_msg_desc_from_writer是对应的结构体，可以填充所需要的字段
    * 将之送入chunk发送函数进行下一步操作
    * 
    */
   /* 超时发送设置 */
    struct timeval tv;
    struct timeval last_tv;
    gettimeofday(&tv,NULL);
    gettimeofday(&last_tv,NULL);
    printf("Setup time: tv_sec=%ld, tv_usec=%ld\n", tv.tv_sec, tv.tv_usec);
    int portid = 1;

    while (1)
    {
        gettimeofday(&tv,NULL);
        if((tv.tv_usec - last_tv.tv_usec) > 1000)
        {
            if(tx_mbuf->len!=0){
                send_expired(tx_mbuf, portid, queue_id);
                memcpy(&last_tv,&tv,sizeof(struct timeval));
            }
            last_tv.tv_usec = tv.tv_usec;
        }
        //get message from recv_ring
        if (rte_ring_dequeue(recv_ring_from_worker, (void **)&a_chunk_msg_desc_from_worker) == 0)
        {
            TX_LOG("receive an message from worker core\n");
            TX_LOG("io_type is %d\n", a_chunk_msg_desc_from_worker->io_type);
            TX_LOG("eid is %s\n", a_chunk_msg_desc_from_worker->chunk_eid);
            TX_LOG("chunk size is %u\n", a_chunk_msg_desc_from_worker->chunk_size);
            TX_LOG("quid 0 is %u\n",conf->tx_queue_id[0]);
            TX_LOG("quid 1 is %u\n",conf->tx_queue_id[1]);
            if (a_chunk_msg_desc_from_worker->io_type == REQUEST_IO_READ)
            {
                //TODO:send chunk operation
                if (chunk_sender(a_chunk_msg_desc_from_worker, tx_mbuf, conf, queue_id) != 0)
                {
                    //LogWrite(INFO,"%s \n","chunk_send fail");
                    TX_LOG("chunk send fail\n");
                }
                else
                {
                    TX_LOG("chunk send finish\n");
                }
            }
            else if (a_chunk_msg_desc_from_worker->io_type == REQUEST_REGISTER)
            {
                //TODO:register operation
            }
            else if (a_chunk_msg_desc_from_worker->io_type == REQUEST_CANCEL)
            {
                //TODO:cancel operation
            }
            else
            {
                TX_LOG("message with an unknown msg type: %d from worker core\n", a_chunk_msg_desc_from_worker->io_type);
            }
            //after the chunk_dssc is used,it should be released
            rte_mempool_put(pool, a_chunk_msg_desc_from_worker);
        }
        else if (rte_ring_dequeue(recv_ring_from_writer, (void **)&a_chunk_msg_desc_from_writer) == 0)
        {
            TX_LOG("receive an message from writer core\n");
            if (a_chunk_msg_desc_from_writer->io_type == REQUEST_IO_READ)
            {
                //TODO:send chunk operation
            }
            else
            {
                TX_LOG("message with an unknown msg type: %d from writer core\n", a_chunk_msg_desc_from_writer->io_type);
            }
            //after the chunk_dssc is used,it should be released
            rte_mempool_put(pool, a_chunk_msg_desc_from_writer);
        }
        else
        {
            continue;
        }
    }
}
