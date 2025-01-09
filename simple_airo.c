#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <endian.h>

#define MAX_BSSIDS 256
#define CHANNEL_HOP_INTERVAL 1

typedef struct {
    char bssid[18];
    int pwr;
    int beacons;
    char enc[8];
    char essid[33];
} NetworkInfo;

NetworkInfo networks[MAX_BSSIDS];
int network_count = 0;

void parse_radiotap(const u_char *packet, int *pwr) {
    uint16_t radiotap_len = le16toh(*(uint16_t *)(packet + 2));

    if (radiotap_len >= 14) {
        *pwr = (int8_t)packet[14]; // Radiotap Header에서 RSSI 읽기
    } else {
        *pwr = -128; // 기본값
    }
}

void parse_encryption(const u_char *tags, int tag_len, char *enc) {
    int offset = 0;

    while (offset < tag_len) {
        u_char tag_id = tags[offset];
        u_char tag_len = tags[offset + 1];

        // RSN (WPA2)
        if (tag_id == 0x30) {
            strcpy(enc, "WPA2");
            return;
        }
        // WPA (Vendor-specific, OUI-based)
        else if (tag_id == 0xDD && tag_len >= 4) {
            const u_char *oui = tags + offset + 2;
            if (oui[0] == 0x00 && oui[1] == 0x50 && oui[2] == 0xF2 && oui[3] == 0x01) {
                strcpy(enc, "WPA");
                return;
            }
        }

        offset += 2 + tag_len; // 다음 태그로 이동
    }

    // 암호화 없음
    strcpy(enc, "Open");
}

void parse_beacon_frame(const u_char *packet, int pwr) {
    uint16_t radiotap_len = le16toh(*(uint16_t *)(packet + 2));
    const u_char *frame = packet + radiotap_len;

    const u_char *bssid_ptr = frame + 16;
    char bssid[18];
    snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid_ptr[0], bssid_ptr[1], bssid_ptr[2],
             bssid_ptr[3], bssid_ptr[4], bssid_ptr[5]);

    const u_char *tags = frame + 36;
    int tag_len = le16toh(*(uint16_t *)(frame + 34)); // 태그 전체 길이 계산
    char essid[33] = "<hidden>";
    if (tags[0] == 0 && tags[1] <= 32) {
        int ssid_len = tags[1];
        if (ssid_len > 0) {
            memcpy(essid, tags + 2, ssid_len);
            essid[ssid_len] = '\0';
        }
    }

    char enc[8];
    parse_encryption(tags, tag_len, enc);

    int found = 0;
    for (int i = 0; i < network_count; i++) {
        if (strcmp(networks[i].bssid, bssid) == 0) {
            networks[i].beacons++;
            networks[i].pwr = pwr;
            if (strcmp(essid, "<hidden>") != 0) {
                strcpy(networks[i].essid, essid);
            }
            found = 1;
            break;
        }
    }

    if (!found && network_count < MAX_BSSIDS) {
        strcpy(networks[network_count].bssid, bssid);
        networks[network_count].pwr = pwr;
        networks[network_count].beacons = 1;
        strcpy(networks[network_count].enc, enc);
        strcpy(networks[network_count].essid, essid);
        network_count++;
    }
}

void hop_channel(const char *interface) {
    static int current_channel = 1;
    char command[64];
    snprintf(command, sizeof(command), "iwconfig %s channel %d", interface, current_channel);
    system(command);
    current_channel = (current_channel % 13) + 1;
}

void print_networks() {
    printf("\nBSSID               PWR  Beacons  ENC   ESSID\n");
    printf("------------------------------------------------------\n");
    for (int i = 0; i < network_count; i++) {
        printf("%s  %4d  %7d  %-5s  %s\n",
               networks[i].bssid,
               networks[i].pwr,
               networks[i].beacons,
               networks[i].enc,
               networks[i].essid);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: airodump <interface>\n");
        return 1;
    }

    char *interface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    printf("SimpleAirodump - Listening on %s...\n", interface);

    while (1) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        if (!packet) continue;

        int pwr = 0;
        parse_radiotap(packet, &pwr);

        if ((packet[0] & 0x0C) == 0x00) { // 관리 프레임 (Beacon)
            parse_beacon_frame(packet, pwr);
        }

        print_networks();
        hop_channel(interface);

        sleep(CHANNEL_HOP_INTERVAL);
    }

    pcap_close(handle);
    return 0;
}
