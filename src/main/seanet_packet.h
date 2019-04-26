#ifndef _SEANET_PACKET_PRASE_H_
#define _SEANET_PACKET_PRASE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>






struct seanet_hdr{
    uint8_t id_next_head_type ;
    uint8_t id_length ;
    uint16_t id_seanet_prot_prop;
    char id_src_eid[20] ;                  
    char id_dst_eid[20] ;
};

struct seadp_hdr{ 
    uint16_t seadp_src_port ;
    uint16_t seadp_dst_port ;
    uint8_t seadp_packet_type ;
    uint8_t seadp_cache_type ;
    uint16_t seadp_tran_type_res ;//unsigned short tflag:4,reserve:12;
    uint32_t seadp_chunk_total_len ;
    uint32_t seadp_packet_offset ;
    uint16_t seadp_packet_order ;
    uint16_t seadp_checksum ;
};




#endif /* _SEANET_PACKET_PRASE_H_ */
