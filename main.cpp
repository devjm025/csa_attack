#include "beacon.h"

using namespace std;

bool unicast{false};

Mac ap_mac;
Mac station_mac = Mac("ff:ff:ff:ff:ff:ff");

void usage() {

    printf("syntax : csa-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void packet_handler(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ieee80211_header *wifi_header;
    struct beacon_frame *beacon;
    struct ssid_parameter *ssid;

    // 먼저 MAC 헤더의 위치를 찾습니다.
    wifi_header = (struct ieee80211_header*) packet;

    // 비콘 프레임인지 확인합니다.
    if ((wifi_header->type & 0xfc) == 0x80) { // 관리 프레임 중 비콘 프레임 타입 체크
        // 비콘 프레임 정보를 가져옵니다.
        beacon = (struct beacon_frame*)(packet + sizeof(struct ieee80211_header));

        // SSID 정보를 가져옵니다.
        ssid = (struct ssid_parameter*)(packet + sizeof(struct ieee80211_header) + sizeof(struct beacon_frame));

        printf("SSID: %.*s\n", ssid->length, ssid->ssid); // SSID 길이만큼 출력
        printf("Beacon Interval: %d\n", beacon->beacon_interval);
        printf("Capability Info: %d\n", beacon->capability_info);
    }
}

int main(int argc, char* argv[])
{
    if(argc < 3){
        usage();
        return -1;
    }

    ap_mac = Mac(argv[2]);
    printf("AP is : %s\n",  argv[2]);

    if (argc >= 4){
        unicast = true;
        station_mac = Mac(argv[3]);
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 디바이스를 열고 패킷 캡처를 시작합니다.
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n",argv[1], errbuf);
        return 2;
    }

    // 패킷 캡처 루프
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) {
            // 타임아웃 발생
            continue;
        }
        packet_handler(header, packet);
    }

    if (res == -1) {
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(handle));
    }

    // 캡처를 종료하고 리소스를 정리합니다.
    pcap_close(handle);
    return 0;

}

