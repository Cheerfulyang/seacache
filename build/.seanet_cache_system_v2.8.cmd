cmd_seanet_cache_system_v2.8 = gcc -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2,RTE_CPUFLAG_AES,RTE_CPUFLAG_PCLMULQDQ,RTE_CPUFLAG_AVX,RTE_CPUFLAG_RDRAND,RTE_CPUFLAG_FSGSBASE,RTE_CPUFLAG_F16C  -I/home/myshare/seanet_cache_system_v3.2_zicco/build/include -I/home/dsp/dpdk-2.0.0/x86_64-native-linuxapp-gcc/include -include /home/dsp/dpdk-2.0.0/x86_64-native-linuxapp-gcc/include/rte_config.h -O3 -I/home/myshare/seanet_cache_system_v3.2_zicco/src/main  -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings  -Wl,-Map=seanet_cache_system_v2.8.map,--cref -o seanet_cache_system_v2.8 src/main/main.o src/main/util.o src/main/init.o src/main/Data_plane.o src/main/dispatch_core.o src/main/writer_core.o src/main/cs_two.o src/main/tx_action.o src/main/sender.o -Wl,--no-as-needed -Wl,-export-dynamic -L/home/myshare/seanet_cache_system_v3.2_zicco/build/lib -L/home/dsp/dpdk-2.0.0/x86_64-native-linuxapp-gcc/lib  -L/home/dsp/dpdk-2.0.0/x86_64-native-linuxapp-gcc/lib -Wl,--whole-archive -Wl,-lintel_dpdk -Wl,--start-group -Wl,-lrt -Wl,-lm -Wl,-ldl -Wl,--end-group -Wl,--no-whole-archive 
