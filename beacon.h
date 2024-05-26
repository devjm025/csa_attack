#include <iostream>
#include <cstdio>
#include <pcap.h>
#include "mac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <arpa/inet.h>

#pragma pack(push, 1)

// Radiotap 헤더 구조체
struct dot11_radiotap_header {
    uint8_t it_version;     // Radiotap 버전
    uint8_t it_pad;         // 패딩 (항상 0)
    uint16_t it_len;        // 전체 헤더 길이
    uint32_t it_present;    // 사용된 필드를 나타내는 비트 마스크
};

// IEEE 802.11 MAC 헤더 구조체
struct dot11_beacon_frame_header {
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    uint8_t receiver[6];
    uint8_t transmitter[6];
    uint8_t bssid[6];
    uint16_t sequence_control;
};


// SSID 정보를 파싱하기 위한 구조체
struct ssid_parameter {
    uint8_t element_id;
    uint8_t length;
    char ssid[32]; // 최대 SSID 길이가 32
};
#pragma pack(pop)
