# Firmware z testami jednostkowymi. Budowany osobno od wlasciwego wezla.
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "../components" "../../krst_common")

# Zwykla zmienna, a nie CACHE: wartosc z cache nie zmienilaby sie w istniejacym katalogu build.
set(TEST_COMPONENTS "p2p_core chain_core")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(node_test)
