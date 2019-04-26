#ifndef _DISPATCH_CORE_H_
#define _DISPATCH_CORE_H_

/**
 *  * @file
 *   *
 *     */

#include <stdint.h>
#include <rte_ip.h>
#include "init.h"
#include "Defaults.h"
#include "seanet_packet.h"

extern struct app_global_config app_conf;
extern struct app_lcore_params lcore_conf[APP_MAX_LCORES];

int dispatch_loop(__attribute__((unused)) void *arg);




#endif /* _DISPATCH_CORE_H_ */

