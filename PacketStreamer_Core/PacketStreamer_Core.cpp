#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <Windows.h>
#include <pcap.h>

#ifdef PACKETSTREAMER_EXPORTS
#define PACKETSTREAMER_API __declspec(dllexport)
#else
#define PACKETSTREAMER_API __declspec(dllimport)
#endif

// ✅ NEW: متغیر برای کنترل توقف کپچر
volatile bool g_stopCapture = false;

// ---------- ساختارهای هدر شبکه ----------
#pragma pack(push, 1)
struct EtherHeader {
    uint8_t  dest[6];
    uint8_t  src[6];
    uint16_t type;
};

struct IpHeader {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};
// ✅ NEW: هدر TCP (حداقل ۲۰ بایت)
struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

// ✅ NEW: هدر UDP (۸ بایت)
struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

// ---------- ساختار کارت شبکه ----------
struct NetworkInterface {
    char name[256];
    char description[512];
};

// ✅ NEW: ساختار اطلاعات پکت برای ارسال به C#
// ✅ UPDATED: ساختار اطلاعات پکت با فیلدهای جدید
struct PacketInfo {
    char src_ip[16];
    char dst_ip[16];
    char protocol[10];
    uint16_t length;
    uint16_t src_port;      // ✅ NEW
    uint16_t dst_port;      // ✅ NEW
    uint32_t timestamp_sec; // ✅ NEW
    uint32_t timestamp_usec;// ✅ NEW
    char payload_preview[50]; // ✅ NEW: ۱۶ بایت اول داده به صورت هگز

    // ✅ NEW: داده کامل پکت (تا 2000 بایت)
    uint8_t raw_data[2000];
    uint16_t raw_data_length;
};
// ✅ NEW: ساختار اطلاعات فایل/دامنه شناسایی شده
struct FileInfo {
    char file_type[10];    // "HTTP", "DNS", "TLS"
    char name[256];        // نام فایل یا دامنه
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
};

// ✅ NEW: Callback برای فایل‌ها
typedef void(__cdecl* FileCallback)(const FileInfo* file);

// ✅ NEW: تعریف نوع Callback function
typedef void(__cdecl* PacketCallback)(const PacketInfo* packet);

// ---------- توابع کمکی ----------
void IpToString(uint32_t ip, char* buffer) {
    uint8_t* bytes = (uint8_t*)&ip;
    sprintf_s(buffer, 16, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void ProtocolName(uint8_t proto, char* buffer) {
    switch (proto) {
    case 1:   strcpy_s(buffer, 10, "ICMP"); break;
    case 2:   strcpy_s(buffer, 10, "IGMP"); break;
    case 6:   strcpy_s(buffer, 10, "TCP"); break;
    case 17:  strcpy_s(buffer, 10, "UDP"); break;
    case 47:  strcpy_s(buffer, 10, "GRE"); break;
    case 50:  strcpy_s(buffer, 10, "ESP"); break;
    case 51:  strcpy_s(buffer, 10, "AH"); break;
    case 58:  strcpy_s(buffer, 10, "ICMPv6"); break;
    case 89:  strcpy_s(buffer, 10, "OSPF"); break;
    case 132: strcpy_s(buffer, 10, "SCTP"); break;
    default:  sprintf_s(buffer, 10, "Other"); break;
    }
}

// ✅ NEW: پارس HTTP برای استخراج URL و Host
bool ParseHttpPacket(const uint8_t* payload, int payloadLen, char* url, char* host) {
    if (payloadLen < 10) return false;

    // بررسی اینکه HTTP است
    if (memcmp(payload, "GET ", 4) != 0 &&
        memcmp(payload, "POST ", 5) != 0 &&
        memcmp(payload, "HEAD ", 5) != 0) {
        return false;
    }

    // پیدا کردن URL (بین "GET " و " HTTP")
    const char* start = (const char*)payload;
    while (*start == ' ') start++;

    const char* end = strstr(start, " HTTP/");
    if (!end) return false;

    int urlLen = (int)(end - start);
    if (urlLen > 200) urlLen = 200;
    strncpy_s(url, 256, start, urlLen);

    // پیدا کردن Host header
    const char* hostHeader = strstr((const char*)payload, "Host: ");
    if (hostHeader) {
        hostHeader += 6; // رد کردن "Host: "
        const char* hostEnd = strstr(hostHeader, "\r\n");
        if (hostEnd) {
            int hostLen = (int)(hostEnd - hostHeader);
            if (hostLen > 100) hostLen = 100;
            strncpy_s(host, 128, hostHeader, hostLen);
        }
    }

    return true;
}

// ✅ NEW: پارس DNS برای استخراج نام دامنه
bool ParseDnsPacket(const uint8_t* payload, int payloadLen, char* domain) {
    if (payloadLen < 12) return false;

    // DNS header: 12 bytes
    // بعد از header، سوالات شروع می‌شوند
    int offset = 12;

    // خواندن نام دامنه (فرمت DNS: length-prefixed labels)
    char temp[256] = { 0 };
    int tempPos = 0;

    while (offset < payloadLen) {
        uint8_t labelLen = payload[offset++];

        if (labelLen == 0) break; // پایان نام

        // Pointer (compression) - رد کردن
        if ((labelLen & 0xC0) == 0xC0) {
            offset++; // فقط یک بایت دیگر
            break;
        }

        if (offset + labelLen > payloadLen) break;

        if (tempPos > 0 && tempPos < 250) {
            temp[tempPos++] = '.';
        }

        for (int i = 0; i < labelLen && tempPos < 250; i++) {
            temp[tempPos++] = (char)payload[offset++];
        }
    }

    if (tempPos > 0) {
        strncpy_s(domain, 256, temp, _TRUNCATE);
        return true;
    }

    return false;
}

// ✅ NEW: پارس TLS Client Hello برای استخراج SNI
bool ParseTlsSni(const uint8_t* payload, int payloadLen, char* sni) {
    if (payloadLen < 43) return false;

    // بررسی TLS handshake (Content Type = 0x16 = Handshake)
    if (payload[0] != 0x16) return false;

    // Handshake Type = 0x01 (Client Hello)
    int offset = 5; // بعد از TLS record header
    if (payload[offset] != 0x01) return false;

    // پرش به Session ID
    offset += 38; // 1 (type) + 3 (length) + 2 (version) + 32 (random)
    if (offset >= payloadLen) return false;

    uint8_t sessionIdLen = payload[offset++];
    offset += sessionIdLen;
    if (offset + 2 >= payloadLen) return false;

    // Cipher Suites
    uint16_t cipherLen = (payload[offset] << 8) | payload[offset + 1];
    offset += 2 + cipherLen;
    if (offset + 1 >= payloadLen) return false;

    // Compression Methods
    uint8_t compLen = payload[offset++];
    offset += compLen;
    if (offset + 2 >= payloadLen) return false;

    // Extensions
    uint16_t extLen = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    int extEnd = offset + extLen;

    // جستجو برای SNI extension (type = 0x0000)
    while (offset + 4 < extEnd && offset + 4 < payloadLen) {
        uint16_t extType = (payload[offset] << 8) | payload[offset + 1];
        uint16_t extDataLen = (payload[offset + 2] << 8) | payload[offset + 3];
        offset += 4;

        if (extType == 0x0000) { // SNI
            if (offset + 5 >= payloadLen) return false;

            // Server Name List Length (2 bytes)
            // Server Name Type (1 byte) = 0 (host_name)
            // Server Name Length (2 bytes)
            uint16_t nameLen = (payload[offset + 3] << 8) | payload[offset + 4];
            offset += 5;

            if (offset + nameLen > payloadLen) return false;

            if (nameLen > 200) nameLen = 200;
            strncpy_s(sni, 256, (const char*)(payload + offset), nameLen);
            return true;
        }

        offset += extDataLen;
    }

    return false;
}

// ---------- توابع Export شده ----------
extern "C" PACKETSTREAMER_API int InitializeWinsock() {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData);
}

extern "C" PACKETSTREAMER_API void CleanupWinsock() {
    WSACleanup();
}

extern "C" PACKETSTREAMER_API int GetNetworkInterfaces(NetworkInterface* interfaces, int maxCount) {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return -1;
    }

    int count = 0;
    for (pcap_if_t* d = alldevs; d != nullptr && count < maxCount; d = d->next, count++) {
        strncpy_s(interfaces[count].name, sizeof(interfaces[count].name), d->name, _TRUNCATE);
        if (d->description) {
            strncpy_s(interfaces[count].description, sizeof(interfaces[count].description), d->description, _TRUNCATE);
        }
        else {
            strncpy_s(interfaces[count].description, sizeof(interfaces[count].description), "No description", _TRUNCATE);
        }
    }

    pcap_freealldevs(alldevs);
    return count;
}

// ✅ NEW: تابع برای توقف کپچر
extern "C" PACKETSTREAMER_API void StopCapture() {
    g_stopCapture = true;
}

// ✅ UPDATED: تابع StartCapture با Callback
// ✅ SIMPLIFIED: فقط packet callback (بدون file callback)
extern "C" PACKETSTREAMER_API void StartCapture(const char* deviceName, PacketCallback callback) {
    char errbuf[PCAP_ERRBUF_SIZE];

    g_stopCapture = false;

    pcap_t* handle = pcap_open_live(deviceName, 65535, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "[ERROR] Could not open device: " << errbuf << "\n";
        return;
    }

    struct pcap_pkthdr* header;
    const uint8_t* packetData;

    while (!g_stopCapture && pcap_next_ex(handle, &header, &packetData) >= 0) {
        if (header->caplen < 34) continue;

        const EtherHeader* eth = (const EtherHeader*)packetData;
        uint16_t ethType = ntohs(eth->type);
        if (ethType != 0x0800) continue;

        const IpHeader* ip = (const IpHeader*)(packetData + 14);
        uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;

        PacketInfo packetInfo;
        IpToString(ip->src_ip, packetInfo.src_ip);
        IpToString(ip->dst_ip, packetInfo.dst_ip);
        ProtocolName(ip->protocol, packetInfo.protocol);
        packetInfo.length = ntohs(ip->total_len);
        packetInfo.timestamp_sec = (uint32_t)header->ts.tv_sec;
        packetInfo.timestamp_usec = (uint32_t)header->ts.tv_usec;
        packetInfo.src_port = 0;
        packetInfo.dst_port = 0;

        const uint8_t* transportLayer = packetData + 14 + ihl;

        if (ip->protocol == 6 && header->caplen >= 14 + ihl + 20) {
            const TcpHeader* tcp = (const TcpHeader*)transportLayer;
            packetInfo.src_port = ntohs(tcp->src_port);
            packetInfo.dst_port = ntohs(tcp->dst_port);
        }
        else if (ip->protocol == 17 && header->caplen >= 14 + ihl + 8) {
            const UdpHeader* udp = (const UdpHeader*)transportLayer;
            packetInfo.src_port = ntohs(udp->src_port);
            packetInfo.dst_port = ntohs(udp->dst_port);
        }

        uint16_t copyLen = (header->caplen > 2000) ? 2000 : header->caplen;
        memcpy(packetInfo.raw_data, packetData, copyLen);
        packetInfo.raw_data_length = copyLen;

        uint8_t transportHeaderLen = 0;
        if (ip->protocol == 6) transportHeaderLen = 20;
        else if (ip->protocol == 17) transportHeaderLen = 8;
        uint16_t payloadStart = 14 + ihl + transportHeaderLen;
        uint16_t previewLen = (header->caplen > payloadStart + 16) ? 16 : (header->caplen - payloadStart);
        char hexPreview[50] = { 0 };
        for (int i = 0; i < previewLen; i++) {
            sprintf_s(hexPreview + (i * 3), 4, "%02X ", packetData[payloadStart + i]);
        }
        strncpy_s(packetInfo.payload_preview, sizeof(packetInfo.payload_preview), hexPreview, _TRUNCATE);

        if (callback) {
            callback(&packetInfo);
        }
    }

    pcap_close(handle);
}