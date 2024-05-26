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
    struct dot11_radiotap_header* rt_hdr;
    struct ssid_parameter *ssid;

    // 먼저 MAC 헤더의 위치를 찾습니다.
    rt_hdr = (struct dot11_radiotap_header*) packet;

    uint16_t len = htons(rt_hdr->it_len);
    std::memset(rt_hdr, 0x00, len);
    rt_hdr->it_len = htons(len);

    struct dot11_beacon_frame_header *bf_hdr = (struct dot11_beacon_frame_header*)(packet + len);

    if(bf_hdr->type != 0x80) return;

    Mac transmitter;
    transmitter = Mac(bf_hdr->transmitter);


    if(transmitter != ap_mac) return;
    std::cout << "transmitter_mac 주소: " << static_cast<std::string>(transmitter) << std::endl;

    // SSID 정보를 가져옵니다.
    ssid = (struct ssid_parameter*)(bf_hdr + sizeof(struct dot11_beacon_frame_header));
    printf("element id : %d", ssid->element_id);
    printf("length : %d", ssid->length);


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

