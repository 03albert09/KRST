idf_component_register(SRCS "block.c" "consensus.c" "block_store.c" "chain.c" "chain_task.c" "chain_net.c"
                            "ledger.c" "miner.c" "evil_block.c"
                    INCLUDE_DIRS "include"
                    REQUIRES krst_common p2p_core
                    PRIV_REQUIRES mbedtls esp_partition esp_timer)
