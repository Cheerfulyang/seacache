# Config
#SHELL = /bin/sh

# RTE_SDK points to the directory where DPDK is built
ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# Binary name
APP = seanet_cache_system_v2.8


# Folders containing source files (relative path)
SRC_MAIN_DIR = src/main
#
#all source are stored in SRCS-y
SRCS-y := $(SRC_MAIN_DIR)/main.c
SRCS-y += $(SRC_MAIN_DIR)/util.c
SRCS-y += $(SRC_MAIN_DIR)/init.c
SRCS-y += $(SRC_MAIN_DIR)/Data_plane.c 
SRCS-y += $(SRC_MAIN_DIR)/dispatch_core.c 
SRCS-y += $(SRC_MAIN_DIR)/writer_core.c 
SRCS-y += $(SRC_MAIN_DIR)/cs_two.c 
SRCS-y += $(SRC_MAIN_DIR)/tx_action.c 
SRCS-y += $(SRC_MAIN_DIR)/sender.c 

# Here for the -I option (which locates headers) I need absolute path
CFLAGS += -O3 -I$(SRCDIR)/$(SRC_MAIN_DIR) 
CFLAGS += $(WERROR_FLAGS)


include $(RTE_SDK)/mk/rte.extapp.mk

