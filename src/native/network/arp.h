#pragma once

#include <string>
#include <vector>
#include <memory>

// Windows and Npcap includes
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <pcap.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

// Ethernet header structure
struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

// ARP packet structure
struct ArpPacket {
    uint16_t hardware_type;     // Hardware type (1 for Ethernet)
    uint16_t protocol_type;     // Protocol type (0x0800 for IPv4)
    uint8_t hardware_len;       // Hardware address length (6 for MAC)
    uint8_t protocol_len;       // Protocol address length (4 for IPv4)
    uint16_t operation;         // Operation (1 for request, 2 for reply)
    uint8_t sender_mac[6];      // Sender hardware address
    uint8_t sender_ip[4];       // Sender protocol address
    uint8_t target_mac[6];      // Target hardware address
    uint8_t target_ip[4];       // Target protocol address
};

// Complete Ethernet + ARP frame
struct ArpFrame {
    EthernetHeader eth;
    ArpPacket arp;
};

// Network adapter information
struct NetworkAdapter {
    std::string name;           // Windows adapter name (GUID)
    std::string pcap_name;      // Npcap device name (\Device\NPF_{GUID})
    std::string description;
    std::string friendly_name;
    std::string mac_address;
    std::string ip_address;
    std::string subnet_mask;
    std::string gateway;
    bool is_active;
    bool is_wireless;
};

// Network topology information
struct NetworkInfo {
    std::string local_ip;
    std::string subnet_mask;
    std::string gateway_ip;
    std::string gateway_mac;
    std::string interface_name;
    std::string interface_mac;
    uint32_t subnet_cidr;
    bool is_valid;
};

// ARP Manager class for handling ARP operations
class ArpManager {
private:
#ifdef _WIN32
    pcap_t* pcap_handle;
#else
    void* pcap_handle; // stub for non-Windows
#endif
    NetworkInfo network_info;
    bool is_initialized;
    
    // Performance optimization: pre-allocated buffers
    std::vector<uint8_t> arp_buffer;
    ArpFrame* arp_frame;
    
public:
    ArpManager();
    ~ArpManager();
    
    // Initialization and cleanup
    bool initialize(const std::string& adapter_name);
    void cleanup();
    
    // Network adapter enumeration
    std::vector<NetworkAdapter> enumerateAdapters();
    
    // Network topology discovery
    NetworkInfo discoverNetworkTopology(const std::string& adapter_name);
    NetworkInfo discoverNetworkTopologyAlternative();
    NetworkInfo getNetworkInfo() const { return network_info; }
    
    // ARP packet operations
    bool sendArpRequest(const std::string& target_ip);
    bool sendArpReply(const std::string& sender_ip, const std::string& target_ip, 
                     const std::string& sender_mac, const std::string& target_mac);
    
    // ARP poisoning operations (Phase 2)
    bool startArpPoisoning(const std::string& target_ip, const std::string& target_mac);
    bool stopArpPoisoning(const std::string& target_ip);
    bool poisonArpCache(const std::string& victim_ip, const std::string& victim_mac, 
                       const std::string& spoof_ip, const std::string& our_mac);
    
    // Gateway discovery
    std::string discoverGatewayMac(const std::string& gateway_ip);
    bool refreshGatewayMac(); // Refresh gateway MAC if not found during init
    
    // Adapter name mapping (Phase 2)
    std::string mapAdapterNameToPcap(const std::string& windows_adapter_name);
    std::vector<std::string> enumeratePcapDevices();
    
    // Utility functions
    static std::string macToString(const uint8_t* mac);
    static bool stringToMac(const std::string& mac_str, uint8_t* mac);
    static bool stringToIp(const std::string& ip_str, uint8_t* ip);
    static std::string ipToString(const uint8_t* ip);
    
    // Performance monitoring
    struct PerformanceStats {
        uint64_t packets_sent;
        uint64_t packets_received;
        uint64_t send_errors;
        uint64_t receive_errors;
        double avg_send_time_ms;
        double avg_receive_time_ms;
    };
    
    PerformanceStats getPerformanceStats() const;
    void resetPerformanceStats();
    
    // Error handling
    std::string getLastError() const { return last_error; }
    
private:
    PerformanceStats perf_stats;
    std::string last_error;
    
    // ARP poisoning state (Phase 2)
    struct PoisoningTarget {
        std::string ip;
        std::string mac;
        bool is_active;
    };
    std::vector<PoisoningTarget> poisoning_targets;
    bool poisoning_active;
    
    // Internal helper methods
    void setError(const std::string& error);
    bool validateAdapter(const std::string& adapter_name);
    void initializeBuffers();
    void updatePerformanceStats(bool is_send, double time_ms, bool success);
};

// Global ARP manager instance
extern std::unique_ptr<ArpManager> g_arp_manager;

// C++ function declarations for N-API exports
std::vector<NetworkAdapter> GetNetworkAdapters();
bool InitializeArpManager(const std::string& adapter_name);
void CleanupArpManager();
NetworkInfo GetNetworkTopology();
bool SendArpRequest(const std::string& target_ip);
ArpManager::PerformanceStats GetArpPerformanceStats();

// Phase 2 exports
bool StartArpPoisoning(const std::string& target_ip, const std::string& target_mac);
bool StopArpPoisoning(const std::string& target_ip);
std::vector<std::string> EnumeratePcapDevices();