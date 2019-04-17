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



//#include "init.h"
#include "writer_core.h"

#define WRITE_LOG(...) printf("[WRITE_IOG]: " __VA_ARGS__)
#define WRITE_WARN(...) printf("[WRITE_WARN]: " __VA_ARGS__)

/*function operation:
	output the path of a chunk should be put in,
	its like "/data/f1_i/f2_j" while 0<=i,j<128
*/
static
int lookup_path(char *chunk_eid, char *eid_path)
{
    char res1[10], res2[10] = {0};
    unsigned int num_front_four_bytes, num_last_four_bytes = 0;
    char a[4], b[4] = {0};
    if (chunk_eid == NULL)
    {
        printf("receive an unknown eid\n");
        return -1;
    }

    strncpy(a, chunk_eid, 4);
    strncpy(b, chunk_eid + EID_LEN_HEX - 4, 4);
    sscanf(a, "%x", &num_front_four_bytes);
    sscanf(b, "%x", &num_last_four_bytes);
    printf("eid前4Byte是：%d\n", num_front_four_bytes);
    printf("eid后4Byte是：%d\n", num_last_four_bytes);
    sprintf(res1, "%d", num_front_four_bytes % PRIMARY_FOLDER_NUM);
    sprintf(res2, "%d", num_last_four_bytes % SECONDARY_FOLDER_NUM);
    strcpy(eid_path, FILESYSTEM_PATH_NAME); //strcpy function will cover old information
    strcat(eid_path, "/f1_");
    strcat(eid_path, res1);
    strcat(eid_path, "/f2_");
    strcat(eid_path, res2);
    strcat(eid_path, "/");
    strcat(eid_path, chunk_eid);
    return 0;
}

 
static
int is_file_exist(const char *file_path)
{
    if (file_path == NULL)
        return -1;
    if (access(file_path, F_OK) == 0)
        return 0;
    return -1;
}

int fs_io_loop(__attribute__((unused)) void *arg)
{
    //self
    struct chunk_msg_desc *a_chunk_msg_desc = NULL;                /**< used to send a message to writer core when dram queue is full. */
    struct chunk_msg_desc *a_chunk_msg_desc_to_tx = NULL;          /**< used to send a message to tx core from writer core. */
    struct notify_desc *a_notify_desc = NULL;                  /**< Notify pkt lcore that IO write request is finished */
    char *fs_path_for_eid = (char *)malloc(sizeof(char) * 60); /**<used to storage a path corrosponding to a chunk eid */
    FILE *fp = NULL;
    struct rte_mempool *pool = NULL;

    unsigned lcore_id, socket_id;

    struct app_lcore_params *conf; 
    struct app_lcore_params *conf_tx = NULL;
                                                         
    int writen_num = 0;

    //store temp info for a_notify_desc
    char chunk_temp[SIZE_OF_ONE_CHUNK] = {0};
    char msg_type_temp = 0;
    //char chunk_temp[] how to store chunk?
    struct rte_ring *recv_ring_from_worker;
    struct rte_ring *send_ring_to_worker;
    struct rte_ring *send_ring_to_tx;

    // NUMA node0 CPU(s):     0,2,4,6,8,10,12,14,16,18,20,22
    // NUMA node1 CPU(s):     1,3,5,7,9,11,13,15,17,19,21,23

    lcore_id = rte_lcore_id();
    socket_id = rte_lcore_to_socket_id(lcore_id); //use to get ring and mempool with tx core

    
    if (socket_id == 0)
    { 
        conf_tx = &lcore_conf[TX_LCORE_FIRST];
    }else if(socket_id == 1)
    {
        conf_tx = &lcore_conf[TX_LCORE_SECOND];   
    }

   conf = &lcore_conf[lcore_id];
   send_ring_to_tx = conf_tx->send_ring;
   recv_ring_from_worker = conf->recv_ring;
   send_ring_to_worker = conf->send_ring;
   pool = conf->shm_message_pool;
 

    while (1)
    {
        //get message from recv_ring
        if (rte_ring_dequeue(recv_ring_from_worker, (void **)&a_chunk_msg_desc) < 0)
        {
            continue;
        }
        else
        { 
            WRITE_LOG("receive and message from worker core\n");
            // Enter different processing flow according to io type
            if (a_chunk_msg_desc->io_type == REQUEST_IO_WRITE)
            {
                if (lookup_path(a_chunk_msg_desc->chunk_eid, fs_path_for_eid) == 0)
                {
		    fp = fopen(fs_path_for_eid, "w+");                                  //if file already exists, it will be updated
                    writen_num = fwrite(a_chunk_msg_desc->chunk, SIZE_OF_ONE_CHUNK, 1, fp); 
                    fclose(fp);

                    //TODO: construct write finish notify
                    if (writen_num == 0)
                    {
                        msg_type_temp = NOTIFY_IO_WRITE_FAIL; //write operation failed
                    }
                    else
                    {  
                        WRITE_LOG("finish writting chunk into filesystem\n");
                        msg_type_temp = NOTIFY_IO_WRITE_FINISH;

                        //apply space for notify from mempool
                        while (1) //if no space for notify, it will be stuck here
                        {
                            if (rte_mempool_get(pool, (void **)&a_notify_desc) < 0)
                            {
                                WRITE_WARN("Not enough entries in the mempool on message packet pool on socket:%u \n",
                                         rte_socket_id());
                            }
                            else
                            {
                                break;
                            }
                        }
                        //construct a chunk_msg_desc (send to worker core)
                        a_notify_desc->io_type = msg_type_temp;
                        rte_memcpy(a_notify_desc->chunk_eid, a_chunk_msg_desc->chunk_eid, EID_LEN);

                        //TODO:consider when to put notify into send_ring
                        if (rte_ring_enqueue(send_ring_to_worker, a_notify_desc) < 0)
                        {
                            WRITE_WARN("Not enough room in the ring to enqueue on socket:%u \n",
                                     rte_socket_id());
                            rte_mempool_put(pool, a_notify_desc);
                        }
                    }
                }
                else //consider using a special folder to place these strange chunks
                {   
                    WRITE_WARN("Receive an unknown request with wrong chunk eid!\n");
                    //TODO: construct write failed notify
                    msg_type_temp = NOTIFY_IO_WRITE_FAIL;
                }
            }
            else if (a_chunk_msg_desc->io_type == REQUEST_IO_READ)
            {
                if (lookup_path(a_chunk_msg_desc->chunk_eid, fs_path_for_eid) == 0)
                {
                    //examine whether the chunk file exists
                    if (is_file_exist(fs_path_for_eid) < 0)
                    {
                        //TODO: construct read failed notify
                        msg_type_temp = NOTIFY_IO_READ_FAIL;
                    }
                    else
                    {

                        fp = fopen(fs_path_for_eid, "r");
                        fread(chunk_temp, SIZE_OF_ONE_CHUNK, 1, fp);
                        fclose(fp);
                        //TODO: construct read finish notify
                        while (1) //if no space for notify, it will be stuck here
                        {
                            if (rte_mempool_get(pool, (void **)&a_chunk_msg_desc_to_tx) < 0)
                            {
                                WRITE_WARN("Not enough entries in the mempool on message packet pool on socket:%u \n",
                                         rte_socket_id());
                            }
                            else
                            {
                                break;
                            }
                        }
                        //construct a chunk_msg_desc_to_tx
                        a_chunk_msg_desc_to_tx->io_type = NOTIFY_IO_READ_FINISH;
                        rte_memcpy(a_chunk_msg_desc_to_tx->chunk_eid, a_chunk_msg_desc->chunk_eid, EID_LEN);
                        rte_memcpy(a_chunk_msg_desc_to_tx->chunk, chunk_temp, SIZE_OF_ONE_CHUNK);

                        if (rte_ring_enqueue(send_ring_to_tx, a_chunk_msg_desc_to_tx) < 0)
                        {
                            WRITE_WARN("Not enough room in the ring to enqueue on socket:%u \n",
                                     rte_socket_id());
                            rte_mempool_put(pool, a_chunk_msg_desc_to_tx);
                            msg_type_temp = NOTIFY_IO_READ_FAIL;
                        }
                        msg_type_temp = NOTIFY_IO_READ_FINISH;
                    }
                }
                else
                {
                    WRITE_WARN("Receive an unknown request with wrong chunk eid!\n");
                    //TODO: construct read failed notify
                    msg_type_temp = NOTIFY_IO_READ_FAIL;
                }
            }
            else
            {
                WRITE_WARN("Receive an unknown request with type:%u \n", a_chunk_msg_desc->io_type);
                //consider whether to construct a notify
            }

            //after the chunk_dssc is used,it should be released
            rte_mempool_put(pool, a_chunk_msg_desc);
        }
    }
    return 0;
}
