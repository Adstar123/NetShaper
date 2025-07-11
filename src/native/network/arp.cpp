#include "arp.h"
#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <codecvt>
#include <locale>

// Helper function to convert wide string to string
static std::string WideStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Helper function to convert PWCHAR to string
static std::string PWCHARToString(PWCHAR pwchar) {
    if (!pwchar) return std::string();
    return WideStringToString(std::wstring(pwchar));
}

// Global ARP manager instance
std::unique_ptr<ArpManager> g_arp_manager;

// ARP Manager Implementation
ArpManager::ArpManager() : pcap_handle(nullptr), is_initialized(false) {
    initializeBuffers();
    resetPerformanceStats();
}

ArpManager::~ArpManager() {
    cleanup();
}

bool ArpManager::initialize(const std::string& adapter_name) {
    if (is_initialized) {
        cleanup();
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Validate adapter name
    if (!validateAdapter(adapter_name)) {
        setError("Invalid adapter name: " + adapter_name);
        return false;
    }
    
    // Open adapter for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(adapter_name.c_str(), 65536, 1, 1000, errbuf);
    
    if (pcap_handle == nullptr) {
        // Log the error - this is expected for Phase 1 since adapter names from enumeration 
        // are Windows display names, not pcap device names
        printf("ARP Manager: Failed to open pcap adapter '%s': %s\n", adapter_name.c_str(), errbuf);
        printf("ARP Manager: This is expected in Phase 1 - pcap requires device names like \\Device\\NPF_{GUID}\n");
        pcap_handle = nullptr; // Set to null to indicate no pcap
        // Continue with initialization - Phase 2 will implement proper adapter name mapping
    }
    
    // Set non-blocking mode for performance (only if pcap is available)
    if (pcap_handle && pcap_setnonblock(pcap_handle, 1, errbuf) == -1) {
        printf("ARP Manager: Failed to set non-blocking mode: %s (continuing for Phase 1 testing)\n", errbuf);
        // Continue anyway for Phase 1 testing
    }
    
    // Discover network topology
    network_info = discoverNetworkTopology(adapter_name);
    if (!network_info.is_valid) {
        printf("ARP Manager: Network topology discovery failed for '%s', trying alternative method\n", adapter_name.c_str());
        // Try alternative topology discovery using Windows IP Helper API
        network_info = discoverNetworkTopologyAlternative();
        if (!network_info.is_valid) {
            setError("Failed to discover network topology using any method");
            cleanup();
            return false;
        }
    }
    
    is_initialized = true;
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Log initialization performance
    char debug_msg[256];
    sprintf_s(debug_msg, sizeof(debug_msg), "ARP Manager initialized in %lld microseconds\n", duration.count());
    OutputDebugStringA(debug_msg);
    
    return true;
}

void ArpManager::cleanup() {
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
    }
    is_initialized = false;
}

std::vector<NetworkAdapter> ArpManager::enumerateAdapters() {
    std::vector<NetworkAdapter> adapters;
    
    // Get all network adapters using GetAdaptersAddresses
    ULONG bufferSize = 0;
    DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferSize);
    
    if (result == ERROR_BUFFER_OVERFLOW) {
        auto buffer = std::make_unique<char[]>(bufferSize);
        PIP_ADAPTER_ADDRESSES adapterAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
        
        result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapterAddresses, &bufferSize);
        
        if (result == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES adapter = adapterAddresses; adapter != nullptr; adapter = adapter->Next) {
                // Skip loopback adapters only - include all others regardless of status
                if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
                    continue;
                }
                
                NetworkAdapter netAdapter;
                netAdapter.name = adapter->AdapterName;
                netAdapter.description = PWCHARToString(adapter->Description);
                netAdapter.friendly_name = PWCHARToString(adapter->FriendlyName);
                netAdapter.is_active = (adapter->OperStatus == IfOperStatusUp);
                netAdapter.is_wireless = (adapter->IfType == IF_TYPE_IEEE80211);
                
                // Get MAC address
                if (adapter->PhysicalAddressLength == 6) {
                    netAdapter.mac_address = macToString(adapter->PhysicalAddress);
                } else {
                    netAdapter.mac_address = "00:00:00:00:00:00"; // Default for adapters without MAC
                }
                
                // Get IP address
                for (PIP_ADAPTER_UNICAST_ADDRESS unicastAddress = adapter->FirstUnicastAddress;
                     unicastAddress != nullptr; unicastAddress = unicastAddress->Next) {
                    
                    if (unicastAddress->Address.lpSockaddr->sa_family == AF_INET) {
                        sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(unicastAddress->Address.lpSockaddr);
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ip_str, INET_ADDRSTRLEN);
                        netAdapter.ip_address = std::string(ip_str);
                        
                        // Calculate subnet mask from prefix length
                        uint32_t mask = 0xFFFFFFFF << (32 - unicastAddress->OnLinkPrefixLength);
                        mask = htonl(mask);
                        struct in_addr mask_addr;
                        mask_addr.s_addr = mask;
                        char mask_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &mask_addr, mask_str, INET_ADDRSTRLEN);
                        netAdapter.subnet_mask = std::string(mask_str);
                        break;
                    }
                }
                
                // Get gateway
                for (PIP_ADAPTER_GATEWAY_ADDRESS gatewayAddress = adapter->FirstGatewayAddress;
                     gatewayAddress != nullptr; gatewayAddress = gatewayAddress->Next) {
                    
                    if (gatewayAddress->Address.lpSockaddr->sa_family == AF_INET) {
                        sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(gatewayAddress->Address.lpSockaddr);
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ip_str, INET_ADDRSTRLEN);
                        netAdapter.gateway = std::string(ip_str);
                        break;
                    }
                }
                
                adapters.push_back(netAdapter);
            }
        }
    }
    
    return adapters;
}

NetworkInfo ArpManager::discoverNetworkTopology(const std::string& adapter_name) {
    NetworkInfo info = {};
    
    // Get adapter information
    auto adapters = enumerateAdapters();
    auto it = std::find_if(adapters.begin(), adapters.end(), 
        [&adapter_name](const NetworkAdapter& adapter) {
            return adapter.name == adapter_name;
        });
    
    if (it == adapters.end()) {
        setError("Adapter not found: " + adapter_name);
        return info;
    }
    
    const NetworkAdapter& adapter = *it;
    
    // Fill network info
    info.local_ip = adapter.ip_address;
    info.subnet_mask = adapter.subnet_mask;
    info.gateway_ip = adapter.gateway;
    info.interface_name = adapter.name;
    info.interface_mac = adapter.mac_address;
    
    // Calculate CIDR
    struct in_addr mask_addr;
    inet_pton(AF_INET, adapter.subnet_mask.c_str(), &mask_addr);
    uint32_t mask = mask_addr.s_addr;
    info.subnet_cidr = 0;
    while (mask & 0x80000000) {
        info.subnet_cidr++;
        mask <<= 1;
    }
    
    // Discover gateway MAC address
    info.gateway_mac = discoverGatewayMac(adapter.gateway);
    
    info.is_valid = !info.gateway_mac.empty();
    
    return info;
}

bool ArpManager::sendArpRequest(const std::string& target_ip) {
    if (!is_initialized) {
        setError("ARP Manager not initialized");
        return false;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Parse target IP
    uint8_t target_ip_bytes[4];
    if (!stringToIp(target_ip, target_ip_bytes)) {
        setError("Invalid target IP address: " + target_ip);
        return false;
    }
    
    // Parse local IP and MAC
    uint8_t local_ip_bytes[4];
    uint8_t local_mac_bytes[6];
    if (!stringToIp(network_info.local_ip, local_ip_bytes) ||
        !stringToMac(network_info.interface_mac, local_mac_bytes)) {
        setError("Invalid local network configuration");
        return false;
    }
    
    // Prepare ARP request frame
    ArpFrame* frame = reinterpret_cast<ArpFrame*>(arp_buffer.data());
    memset(frame, 0, sizeof(ArpFrame));
    
    // Ethernet header
    memset(frame->eth.dest_mac, 0xFF, 6); // Broadcast MAC
    memcpy(frame->eth.src_mac, local_mac_bytes, 6);
    frame->eth.ethertype = htons(0x0806); // ARP
    
    // ARP packet
    frame->arp.hardware_type = htons(1);    // Ethernet
    frame->arp.protocol_type = htons(0x0800); // IPv4
    frame->arp.hardware_len = 6;
    frame->arp.protocol_len = 4;
    frame->arp.operation = htons(1);        // Request
    memcpy(frame->arp.sender_mac, local_mac_bytes, 6);
    memcpy(frame->arp.sender_ip, local_ip_bytes, 4);
    memset(frame->arp.target_mac, 0, 6);    // Unknown
    memcpy(frame->arp.target_ip, target_ip_bytes, 4);
    
    // Send packet
    int result = pcap_sendpacket(pcap_handle, arp_buffer.data(), sizeof(ArpFrame));
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    bool success = (result == 0);
    updatePerformanceStats(true, duration.count() / 1000.0, success);
    
    if (!success) {
        setError("Failed to send ARP request: " + std::string(pcap_geterr(pcap_handle)));
    }
    
    return success;
}

bool ArpManager::sendArpReply(const std::string& sender_ip, const std::string& target_ip, 
                             const std::string& sender_mac, const std::string& target_mac) {
    if (!is_initialized) {
        setError("ARP Manager not initialized");
        return false;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Parse parameters
    uint8_t sender_ip_bytes[4], target_ip_bytes[4];
    uint8_t sender_mac_bytes[6], target_mac_bytes[6];
    
    if (!stringToIp(sender_ip, sender_ip_bytes) ||
        !stringToIp(target_ip, target_ip_bytes) ||
        !stringToMac(sender_mac, sender_mac_bytes) ||
        !stringToMac(target_mac, target_mac_bytes)) {
        setError("Invalid parameters for ARP reply");
        return false;
    }
    
    // Prepare ARP reply frame
    ArpFrame* frame = reinterpret_cast<ArpFrame*>(arp_buffer.data());
    memset(frame, 0, sizeof(ArpFrame));
    
    // Ethernet header
    memcpy(frame->eth.dest_mac, target_mac_bytes, 6);
    memcpy(frame->eth.src_mac, sender_mac_bytes, 6);
    frame->eth.ethertype = htons(0x0806); // ARP
    
    // ARP packet
    frame->arp.hardware_type = htons(1);    // Ethernet
    frame->arp.protocol_type = htons(0x0800); // IPv4
    frame->arp.hardware_len = 6;
    frame->arp.protocol_len = 4;
    frame->arp.operation = htons(2);        // Reply
    memcpy(frame->arp.sender_mac, sender_mac_bytes, 6);
    memcpy(frame->arp.sender_ip, sender_ip_bytes, 4);
    memcpy(frame->arp.target_mac, target_mac_bytes, 6);
    memcpy(frame->arp.target_ip, target_ip_bytes, 4);
    
    // Send packet
    int result = pcap_sendpacket(pcap_handle, arp_buffer.data(), sizeof(ArpFrame));
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    bool success = (result == 0);
    updatePerformanceStats(true, duration.count() / 1000.0, success);
    
    if (!success) {
        setError("Failed to send ARP reply: " + std::string(pcap_geterr(pcap_handle)));
    }
    
    return success;
}

std::string ArpManager::discoverGatewayMac(const std::string& gateway_ip) {
    // Try to find gateway MAC in ARP table first
    ULONG bufferSize = 0;
    DWORD result = GetIpNetTable(nullptr, &bufferSize, FALSE);
    
    if (result == ERROR_INSUFFICIENT_BUFFER) {
        auto buffer = std::make_unique<char[]>(bufferSize);
        PMIB_IPNETTABLE pIpNetTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.get());
        
        result = GetIpNetTable(pIpNetTable, &bufferSize, FALSE);
        
        if (result == NO_ERROR) {
            struct in_addr gateway_addr;
            inet_pton(AF_INET, gateway_ip.c_str(), &gateway_addr);
            
            for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
                if (pIpNetTable->table[i].dwAddr == gateway_addr.s_addr) {
                    return macToString(pIpNetTable->table[i].bPhysAddr);
                }
            }
        }
    }
    
    // If not found in ARP table, send ARP request
    if (sendArpRequest(gateway_ip)) {
        // Wait briefly for response and check ARP table again
        Sleep(100);
        return discoverGatewayMac(gateway_ip);
    }
    
    return "";
}

// Utility functions
std::string ArpManager::macToString(const uint8_t* mac) {
    std::stringstream ss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return ss.str();
}

bool ArpManager::stringToMac(const std::string& mac_str, uint8_t* mac) {
    if (mac_str.length() != 17) return false;
    
    for (int i = 0; i < 6; ++i) {
        std::string byte_str = mac_str.substr(i * 3, 2);
        try {
            mac[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
        } catch (...) {
            return false;
        }
    }
    return true;
}

bool ArpManager::stringToIp(const std::string& ip_str, uint8_t* ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        return false;
    }
    
    memcpy(ip, &addr, 4);
    return true;
}

std::string ArpManager::ipToString(const uint8_t* ip) {
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." + 
           std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}

ArpManager::PerformanceStats ArpManager::getPerformanceStats() const {
    return perf_stats;
}

void ArpManager::resetPerformanceStats() {
    memset(&perf_stats, 0, sizeof(perf_stats));
}

// Alternative network topology discovery using Windows IP Helper API
NetworkInfo ArpManager::discoverNetworkTopologyAlternative() {
    NetworkInfo info;
    info.is_valid = false;
    
    // Get all adapter addresses to find active adapter with gateway
    ULONG bufferSize = 0;
    DWORD result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, 
                                       nullptr, nullptr, &bufferSize);
    
    if (result == ERROR_BUFFER_OVERFLOW) {
        auto buffer = std::make_unique<char[]>(bufferSize);
        PIP_ADAPTER_ADDRESSES adapterAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
        
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
                                     nullptr, adapterAddresses, &bufferSize);
        
        if (result == NO_ERROR) {
            // Find the first active adapter with a gateway
            for (PIP_ADAPTER_ADDRESSES adapter = adapterAddresses; adapter; adapter = adapter->Next) {
                if (adapter->OperStatus == IfOperStatusUp && 
                    adapter->FirstUnicastAddress && 
                    adapter->FirstGatewayAddress) {
                    
                    // Get local IP
                    auto unicast = adapter->FirstUnicastAddress;
                    if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                        auto sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ip_str, INET_ADDRSTRLEN);
                        info.local_ip = std::string(ip_str);
                        
                        // Calculate subnet info from prefix
                        UINT8 prefixLength = unicast->OnLinkPrefixLength;
                        info.subnet_cidr = prefixLength;
                        
                        // Calculate subnet mask
                        uint32_t mask = 0xFFFFFFFF << (32 - prefixLength);
                        struct in_addr mask_addr;
                        mask_addr.s_addr = htonl(mask);
                        char mask_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &mask_addr, mask_str, INET_ADDRSTRLEN);
                        info.subnet_mask = std::string(mask_str);
                    }
                    
                    // Get gateway IP
                    auto gateway = adapter->FirstGatewayAddress;
                    if (gateway->Address.lpSockaddr->sa_family == AF_INET) {
                        auto gateway_sockaddr = reinterpret_cast<sockaddr_in*>(gateway->Address.lpSockaddr);
                        char gateway_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &gateway_sockaddr->sin_addr, gateway_str, INET_ADDRSTRLEN);
                        info.gateway_ip = std::string(gateway_str);
                    }
                    
                    // Get interface MAC address
                    if (adapter->PhysicalAddressLength == 6) {
                        char mac_str[18];
                        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                                adapter->PhysicalAddress[0], adapter->PhysicalAddress[1],
                                adapter->PhysicalAddress[2], adapter->PhysicalAddress[3],
                                adapter->PhysicalAddress[4], adapter->PhysicalAddress[5]);
                        info.interface_mac = std::string(mac_str);
                    } else {
                        // Set default MAC if not available
                        info.interface_mac = "00:00:00:00:00:00";
                    }
                    
                    // For gateway MAC, we'll need to discover it via ARP (set to zero for now)
                    info.gateway_mac = "00:00:00:00:00:00";
                    
                    info.is_valid = true;
                    printf("ARP Manager: Alternative topology discovery successful - IP: %s, Gateway: %s, Subnet: %s/%d\n",
                           info.local_ip.c_str(), info.gateway_ip.c_str(), info.subnet_mask.c_str(), info.subnet_cidr);
                    break;
                }
            }
        }
    }
    
    if (!info.is_valid) {
        printf("ARP Manager: Alternative topology discovery failed\n");
    }
    
    return info;
}

void ArpManager::setError(const std::string& error) {
    last_error = error;
    OutputDebugStringA(("ARP Manager Error: " + error + "\n").c_str());
}

bool ArpManager::validateAdapter(const std::string& adapter_name) {
    auto adapters = enumerateAdapters();
    return std::find_if(adapters.begin(), adapters.end(), 
        [&adapter_name](const NetworkAdapter& adapter) {
            return adapter.name == adapter_name;
        }) != adapters.end();
}

void ArpManager::initializeBuffers() {
    arp_buffer.resize(sizeof(ArpFrame));
    arp_frame = reinterpret_cast<ArpFrame*>(arp_buffer.data());
}

void ArpManager::updatePerformanceStats(bool is_send, double time_ms, bool success) {
    if (is_send) {
        perf_stats.packets_sent++;
        if (!success) perf_stats.send_errors++;
        perf_stats.avg_send_time_ms = (perf_stats.avg_send_time_ms + time_ms) / 2.0;
    } else {
        perf_stats.packets_received++;
        if (!success) perf_stats.receive_errors++;
        perf_stats.avg_receive_time_ms = (perf_stats.avg_receive_time_ms + time_ms) / 2.0;
    }
}

// C++ function implementations for N-API exports
std::vector<NetworkAdapter> GetNetworkAdapters() {
    if (!g_arp_manager) {
        g_arp_manager = std::make_unique<ArpManager>();
    }
    return g_arp_manager->enumerateAdapters();
}

bool InitializeArpManager(const std::string& adapter_name) {
    if (!g_arp_manager) {
        g_arp_manager = std::make_unique<ArpManager>();
    }
    return g_arp_manager->initialize(adapter_name);
}

void CleanupArpManager() {
    if (g_arp_manager) {
        g_arp_manager->cleanup();
    }
}

NetworkInfo GetNetworkTopology() {
    if (!g_arp_manager) {
        return NetworkInfo{};
    }
    return g_arp_manager->discoverNetworkTopology("");
}

bool SendArpRequest(const std::string& target_ip) {
    if (!g_arp_manager) {
        return false;
    }
    return g_arp_manager->sendArpRequest(target_ip);
}

ArpManager::PerformanceStats GetArpPerformanceStats() {
    if (!g_arp_manager) {
        return ArpManager::PerformanceStats{};
    }
    return g_arp_manager->getPerformanceStats();
}