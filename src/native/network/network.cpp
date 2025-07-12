#include <napi.h>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "arp.h"

// Windows-specific includes for network operations
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iostream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
// Linux-specific includes
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <cstdio>
#endif

// Structure to hold device information
struct DeviceInfo {
    std::string ip;
    std::string mac;
    std::string name;
    std::string vendor;
    bool isOnline;
    uint64_t lastSeen;
};

// Structure to hold traffic control settings for a device
struct TrafficControl {
    std::string deviceMac;
    double downloadLimit; // Mbps
    double uploadLimit;   // Mbps
    bool isBlocked;
    bool isActive;
};

// Global storage for discovered devices and traffic controls
static std::map<std::string, DeviceInfo> discoveredDevices;
static std::map<std::string, TrafficControl> activeControls;
static std::atomic<bool> scanningActive{false};

// Helper function to convert MAC address bytes to string
#ifdef _WIN32
std::string MacToString(const BYTE* mac) {
#else
std::string MacToString(const unsigned char* mac) {
#endif
    std::stringstream ss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return ss.str();
}

// Helper function to get device name using FAST DNS lookup with timeout
std::string GetDeviceName(const std::string& ip) {
#ifdef _WIN32
    char debug_msg[256]; // Single declaration for the entire function
    // Use Windows console output instead of std::cout
    sprintf_s(debug_msg, sizeof(debug_msg), "Fast DNS: Trying to resolve name for IP: %s\n", ip.c_str());
    OutputDebugStringA(debug_msg);
#endif
    printf("DEBUG: Fast DNS: Trying to resolve name for IP: %s\n", ip.c_str());
    fflush(stdout);
    
#ifdef _WIN32
    // Initialize Winsock if not already done
    static bool wsaInitialized = false;
    if (!wsaInitialized) {
        WSADATA wsaData;
        int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (wsaResult == 0) {
            wsaInitialized = true;
            OutputDebugStringA("Winsock initialized successfully\n");
            printf("DEBUG: Winsock initialized successfully\n");
        } else {
            sprintf_s(debug_msg, sizeof(debug_msg), "Winsock initialization failed: %d\n", wsaResult);
            OutputDebugStringA(debug_msg);
            printf("DEBUG: Winsock initialization failed: %d\n", wsaResult);
        }
        fflush(stdout);
    }
#endif
    
    // Method 1: FAST reverse DNS lookup (getnameinfo) - only try once with no flags
    char hostname[NI_MAXHOST];
    memset(hostname, 0, sizeof(hostname));
    
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) == 1) {
        // Only try the fastest method with no flags
        int result = getnameinfo((struct sockaddr*)&sa, sizeof(sa), 
                                hostname, sizeof(hostname), 
                                NULL, 0, 0);
        
        if (result == 0 && strlen(hostname) > 0) {
            std::string name = hostname;
#ifdef _WIN32
            sprintf_s(debug_msg, sizeof(debug_msg), "Fast DNS: Success for %s: %s\n", ip.c_str(), name.c_str());
            OutputDebugStringA(debug_msg);
#endif
            printf("DEBUG: Fast DNS: Success for %s: %s\n", ip.c_str(), name.c_str());
            fflush(stdout);
            
            // Only remove domain suffix if it's actually a hostname, not an IP
            if (name != ip && name.find_first_not_of("0123456789.") != std::string::npos) {
                // This is a real hostname, remove domain suffix
                size_t dotPos = name.find('.');
                if (dotPos != std::string::npos) {
                    name = name.substr(0, dotPos);
                }
            }
            
            // Return if it's a meaningful name (not just IP)
            if (name != ip && name.length() > 0) {
#ifdef _WIN32
                sprintf_s(debug_msg, sizeof(debug_msg), "Fast DNS: Returning device name: %s for IP: %s\n", name.c_str(), ip.c_str());
                OutputDebugStringA(debug_msg);
#endif
                printf("DEBUG: Fast DNS: Returning device name: %s for IP: %s\n", name.c_str(), ip.c_str());
                fflush(stdout);
                return name;
            }
        } else {
#ifdef _WIN32
            sprintf_s(debug_msg, sizeof(debug_msg), "Fast DNS: Failed for %s (error: %d)\n", ip.c_str(), result);
            OutputDebugStringA(debug_msg);
#endif
            printf("DEBUG: Fast DNS: Failed for %s (error: %d)\n", ip.c_str(), result);
            fflush(stdout);
        }
    }
    
#ifdef _WIN32
    sprintf_s(debug_msg, sizeof(debug_msg), "Fast DNS: No name found for %s\n", ip.c_str());
    OutputDebugStringA(debug_msg);
#endif
    printf("DEBUG: Fast DNS: No name found for %s\n", ip.c_str());
    fflush(stdout);
    return ""; // Return empty string if no name found
}

// Function to scan network devices using ARP table (fast scan without DNS)
Napi::Array ScanDevicesFast(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Array result = Napi::Array::New(env);
    
#ifdef _WIN32
    // Clear previous scan results
    discoveredDevices.clear();
    
    // Get ARP table
    ULONG bufferSize = 0;
    DWORD ret = GetIpNetTable(NULL, &bufferSize, FALSE);
    
    if (ret == ERROR_INSUFFICIENT_BUFFER) {
        PMIB_IPNETTABLE pIpNetTable = (PMIB_IPNETTABLE)malloc(bufferSize);
        
        if (pIpNetTable != NULL) {
            ret = GetIpNetTable(pIpNetTable, &bufferSize, FALSE);
            
            if (ret == NO_ERROR) {
                DWORD deviceIndex = 0;
                std::set<std::string> seenMacs; // Track unique MACs to prevent duplicates
                
                for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
                    MIB_IPNETROW& entry = pIpNetTable->table[i];
                    
                    // Skip invalid entries
                    if (entry.dwType == MIB_IPNET_TYPE_INVALID) continue;
                    
                    // Convert IP address first to check if we should skip it
                    struct in_addr addr;
                    addr.s_addr = entry.dwAddr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
                    std::string ip = std::string(ip_str);
                    
                    // Skip multicast addresses (224.x.x.x - 239.x.x.x)
                    size_t pos1 = ip.find('.');
                    if (pos1 != std::string::npos) {
                        int firstOctet = std::stoi(ip.substr(0, pos1));
                        if (firstOctet >= 224 && firstOctet <= 239) continue;
                    }
                    
                    // Skip broadcast addresses
                    if (ip.find(".255") != std::string::npos || ip == "255.255.255.255") continue;
                    
                    // Skip localhost
                    if (ip.find("127.") == 0) continue;
                    
                    // Convert MAC address
                    std::string mac = MacToString(entry.bPhysAddr);
                    
                    // Skip duplicates
                    if (seenMacs.count(mac) > 0) continue;
                    seenMacs.insert(mac);
                    
                    // Use IP as device name initially (fast scan)
                    std::string deviceName = ip;
                    
                    // Create device info
                    DeviceInfo device;
                    device.ip = ip;
                    device.mac = mac;
                    device.name = deviceName;
                    device.vendor = "Unknown";
                    device.isOnline = (entry.dwType == MIB_IPNET_TYPE_DYNAMIC || entry.dwType == MIB_IPNET_TYPE_STATIC);
                    device.lastSeen = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count();
                    
                    // Store in global map
                    discoveredDevices[mac] = device;
                    
                    // Create JavaScript object for this device
                    Napi::Object deviceObj = Napi::Object::New(env);
                    deviceObj.Set("ip", Napi::String::New(env, ip));
                    deviceObj.Set("mac", Napi::String::New(env, mac));
                    deviceObj.Set("name", Napi::String::New(env, deviceName));
                    deviceObj.Set("vendor", Napi::String::New(env, device.vendor));
                    deviceObj.Set("isOnline", Napi::Boolean::New(env, device.isOnline));
                    deviceObj.Set("lastSeen", Napi::Number::New(env, device.lastSeen));
                    
                    result.Set(deviceIndex++, deviceObj);
                }
            }
            
            free(pIpNetTable);
        }
    }
#else
    // Linux stub - return empty array
    printf("ScanDevicesFast: Not implemented on Linux\n");
#endif
    
    return result;
}

// Function to scan network devices with DNS resolution (slower but with names)
Napi::Array ScanDevices(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Array result = Napi::Array::New(env);
    
#ifdef _WIN32
    // Clear previous scan results
    discoveredDevices.clear();
    
    // Get ARP table
    ULONG bufferSize = 0;
    DWORD ret = GetIpNetTable(NULL, &bufferSize, FALSE);
    
    if (ret == ERROR_INSUFFICIENT_BUFFER) {
        PMIB_IPNETTABLE pIpNetTable = (PMIB_IPNETTABLE)malloc(bufferSize);
        
        if (pIpNetTable != NULL) {
            ret = GetIpNetTable(pIpNetTable, &bufferSize, FALSE);
            
            if (ret == NO_ERROR) {
                DWORD deviceIndex = 0;
                std::set<std::string> seenMacs; // Track unique MACs to prevent duplicates
                
                for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
                    MIB_IPNETROW& entry = pIpNetTable->table[i];
                    
                    // Skip invalid entries
                    if (entry.dwType == MIB_IPNET_TYPE_INVALID) continue;
                    
                    // Convert IP address first to check if we should skip it
                    struct in_addr addr;
                    addr.s_addr = entry.dwAddr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
                    std::string ip = std::string(ip_str);
                    
                    // Skip multicast addresses (224.x.x.x - 239.x.x.x)
                    size_t pos1 = ip.find('.');
                    if (pos1 != std::string::npos) {
                        int firstOctet = std::stoi(ip.substr(0, pos1));
                        if (firstOctet >= 224 && firstOctet <= 239) continue;
                    }
                    
                    // Skip broadcast addresses
                    if (ip.find(".255") != std::string::npos || ip == "255.255.255.255") continue;
                    
                    // Skip localhost
                    if (ip.find("127.") == 0) continue;
                    
                    // Convert MAC address
                    std::string mac = MacToString(entry.bPhysAddr);
                    
                    // Skip duplicates
                    if (seenMacs.count(mac) > 0) continue;
                    seenMacs.insert(mac);
                    
                    // Get device name with DNS lookup
                    std::string deviceName = GetDeviceName(ip);
                    if (deviceName.empty()) {
                        deviceName = ip; // Fallback to IP if no name found
                    }
                    
                    // Create device info
                    DeviceInfo device;
                    device.ip = ip;
                    device.mac = mac;
                    device.name = deviceName;
                    device.vendor = "Unknown";
                    device.isOnline = (entry.dwType == MIB_IPNET_TYPE_DYNAMIC || entry.dwType == MIB_IPNET_TYPE_STATIC);
                    device.lastSeen = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count();
                    
                    // Store in global map
                    discoveredDevices[mac] = device;
                    
                    // Create JavaScript object for this device
                    Napi::Object deviceObj = Napi::Object::New(env);
                    deviceObj.Set("ip", Napi::String::New(env, ip));
                    deviceObj.Set("mac", Napi::String::New(env, mac));
                    deviceObj.Set("name", Napi::String::New(env, deviceName));
                    deviceObj.Set("vendor", Napi::String::New(env, device.vendor));
                    deviceObj.Set("isOnline", Napi::Boolean::New(env, device.isOnline));
                    deviceObj.Set("lastSeen", Napi::Number::New(env, device.lastSeen));
                    
                    result.Set(deviceIndex++, deviceObj);
                }
            }
            
            free(pIpNetTable);
        }
    }
#else
    // Linux stub - return empty array
    printf("ScanDevices: Not implemented on Linux\n");
#endif
    
    return result;
}

// Function to set bandwidth limits for a device
Napi::Boolean SetBandwidthLimit(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 3 || !info[0].IsString() || !info[1].IsNumber() || !info[2].IsNumber()) {
        Napi::TypeError::New(env, "Expected (string, number, number)").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    std::string mac = info[0].As<Napi::String>().Utf8Value();
    double downloadLimit = info[1].As<Napi::Number>().DoubleValue();
    double uploadLimit = info[2].As<Napi::Number>().DoubleValue();
    
    // Validate limits (0-1000 Mbps)
    if (downloadLimit < 0 || downloadLimit > 1000 || uploadLimit < 0 || uploadLimit > 1000) {
        Napi::TypeError::New(env, "Bandwidth limits must be between 0 and 1000 Mbps").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    // Create or update traffic control entry
    TrafficControl control;
    control.deviceMac = mac;
    control.downloadLimit = downloadLimit;
    control.uploadLimit = uploadLimit;
    control.isBlocked = false;
    control.isActive = true;
    
    activeControls[mac] = control;
    
    // TODO: Implement actual packet filtering using WinDivert
    // For now, we just store the settings
    
    return Napi::Boolean::New(env, true);
}

// Function to block/unblock a device
Napi::Boolean SetDeviceBlocked(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsBoolean()) {
        Napi::TypeError::New(env, "Expected (string, boolean)").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    std::string mac = info[0].As<Napi::String>().Utf8Value();
    bool blocked = info[1].As<Napi::Boolean>().Value();
    
    // Create or update traffic control entry
    if (activeControls.find(mac) == activeControls.end()) {
        TrafficControl control;
        control.deviceMac = mac;
        control.downloadLimit = 0;
        control.uploadLimit = 0;
        control.isBlocked = blocked;
        control.isActive = blocked;
        activeControls[mac] = control;
    } else {
        activeControls[mac].isBlocked = blocked;
        activeControls[mac].isActive = blocked || 
            (activeControls[mac].downloadLimit > 0 || activeControls[mac].uploadLimit > 0);
    }
    
    // TODO: Implement actual packet blocking using WinDivert
    // For now, we just store the settings
    
    return Napi::Boolean::New(env, true);
}

// Function to remove all traffic controls for a device
Napi::Boolean RemoveTrafficControl(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected (string)").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    std::string mac = info[0].As<Napi::String>().Utf8Value();
    
    // Remove from active controls
    activeControls.erase(mac);
    
    // TODO: Remove actual packet filtering rules using WinDivert
    
    return Napi::Boolean::New(env, true);
}

// Function to get current traffic control settings
Napi::Array GetActiveControls(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Array result = Napi::Array::New(env);
    
    uint32_t index = 0;
    for (const auto& pair : activeControls) {
        const TrafficControl& control = pair.second;
        
        Napi::Object controlObj = Napi::Object::New(env);
        controlObj.Set("mac", Napi::String::New(env, control.deviceMac));
        controlObj.Set("downloadLimit", Napi::Number::New(env, control.downloadLimit));
        controlObj.Set("uploadLimit", Napi::Number::New(env, control.uploadLimit));
        controlObj.Set("isBlocked", Napi::Boolean::New(env, control.isBlocked));
        controlObj.Set("isActive", Napi::Boolean::New(env, control.isActive));
        
        result.Set(index++, controlObj);
    }
    
    return result;
}

// Function to resolve DNS name for a single IP address
Napi::String ResolveSingleDeviceName(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected (string)").ThrowAsJavaScriptException();
        return Napi::String::New(env, "");
    }
    
    std::string ip = info[0].As<Napi::String>().Utf8Value();
    
    // Get device name with DNS lookup
    std::string resolvedName = GetDeviceName(ip);
    if (resolvedName.empty()) {
        resolvedName = ip; // Fallback to IP if no name found
    }
    
    return Napi::String::New(env, resolvedName);
}

// Function to get detailed device information
Napi::Object GetDeviceDetails(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected (string)").ThrowAsJavaScriptException();
        return Napi::Object::New(env);
    }
    
    std::string mac = info[0].As<Napi::String>().Utf8Value();
    
    auto it = discoveredDevices.find(mac);
    if (it == discoveredDevices.end()) {
        return Napi::Object::New(env); // Return empty object if device not found
    }
    
    const DeviceInfo& device = it->second;
    
    Napi::Object result = Napi::Object::New(env);
    result.Set("ip", Napi::String::New(env, device.ip));
    result.Set("mac", Napi::String::New(env, device.mac));
    result.Set("name", Napi::String::New(env, device.name));
    result.Set("vendor", Napi::String::New(env, device.vendor));
    result.Set("isOnline", Napi::Boolean::New(env, device.isOnline));
    result.Set("lastSeen", Napi::Number::New(env, device.lastSeen));
    
    // Add traffic control info if available
    auto controlIt = activeControls.find(mac);
    if (controlIt != activeControls.end()) {
        const TrafficControl& control = controlIt->second;
        result.Set("downloadLimit", Napi::Number::New(env, control.downloadLimit));
        result.Set("uploadLimit", Napi::Number::New(env, control.uploadLimit));
        result.Set("isBlocked", Napi::Boolean::New(env, control.isBlocked));
        result.Set("hasTrafficControl", Napi::Boolean::New(env, control.isActive));
    } else {
        result.Set("downloadLimit", Napi::Number::New(env, 0));
        result.Set("uploadLimit", Napi::Number::New(env, 0));
        result.Set("isBlocked", Napi::Boolean::New(env, false));
        result.Set("hasTrafficControl", Napi::Boolean::New(env, false));
    }
    
    return result;
}

// N-API wrapper functions for ARP functionality
Napi::Array EnumerateNetworkAdapters(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Array result = Napi::Array::New(env);
    
    try {
        auto adapters = GetNetworkAdapters();
        
        for (size_t i = 0; i < adapters.size(); ++i) {
            const auto& adapter = adapters[i];
            
            Napi::Object adapterObj = Napi::Object::New(env);
            adapterObj.Set("name", Napi::String::New(env, adapter.name));
            adapterObj.Set("description", Napi::String::New(env, adapter.description));
            adapterObj.Set("friendlyName", Napi::String::New(env, adapter.friendly_name));
            adapterObj.Set("macAddress", Napi::String::New(env, adapter.mac_address));
            adapterObj.Set("ipAddress", Napi::String::New(env, adapter.ip_address));
            adapterObj.Set("subnetMask", Napi::String::New(env, adapter.subnet_mask));
            adapterObj.Set("gateway", Napi::String::New(env, adapter.gateway));
            adapterObj.Set("isActive", Napi::Boolean::New(env, adapter.is_active));
            adapterObj.Set("isWireless", Napi::Boolean::New(env, adapter.is_wireless));
            adapterObj.Set("pcapName", Napi::String::New(env, adapter.pcap_name));
            
            result.Set(i, adapterObj);
        }
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
    }
    
    return result;
}

Napi::Boolean InitializeArp(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected adapter name as string").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    std::string adapterName = info[0].As<Napi::String>().Utf8Value();
    
    try {
        bool result = InitializeArpManager(adapterName);
        return Napi::Boolean::New(env, result);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
}

Napi::Object GetNetworkTopologyInfo(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);
    
    try {
        NetworkInfo topology = GetNetworkTopology();
        
        result.Set("localIp", Napi::String::New(env, topology.local_ip));
        result.Set("subnetMask", Napi::String::New(env, topology.subnet_mask));
        result.Set("gatewayIp", Napi::String::New(env, topology.gateway_ip));
        result.Set("gatewayMac", Napi::String::New(env, topology.gateway_mac));
        result.Set("interfaceName", Napi::String::New(env, topology.interface_name));
        result.Set("interfaceMac", Napi::String::New(env, topology.interface_mac));
        result.Set("subnetCidr", Napi::Number::New(env, topology.subnet_cidr));
        result.Set("isValid", Napi::Boolean::New(env, topology.is_valid));
        
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
    }
    
    return result;
}

Napi::Boolean SendArpRequestWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected target IP as string").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    std::string targetIp = info[0].As<Napi::String>().Utf8Value();
    
    try {
        bool result = SendArpRequest(targetIp);
        return Napi::Boolean::New(env, result);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
}

Napi::Object GetArpPerformanceStatsWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);
    
    try {
        auto stats = GetArpPerformanceStats();
        
        result.Set("packetsSent", Napi::Number::New(env, static_cast<double>(stats.packets_sent)));
        result.Set("packetsReceived", Napi::Number::New(env, static_cast<double>(stats.packets_received)));
        result.Set("sendErrors", Napi::Number::New(env, static_cast<double>(stats.send_errors)));
        result.Set("receiveErrors", Napi::Number::New(env, static_cast<double>(stats.receive_errors)));
        result.Set("avgSendTimeMs", Napi::Number::New(env, stats.avg_send_time_ms));
        result.Set("avgReceiveTimeMs", Napi::Number::New(env, stats.avg_receive_time_ms));
        
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
    }
    
    return result;
}

Napi::Value CleanupArpWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        CleanupArpManager();
        return env.Undefined();
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Undefined();
    }
}

// Phase 2: ARP poisoning N-API wrapper functions
Napi::Boolean StartArpPoisoningWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Expected (target_ip: string, target_mac: string)").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    std::string targetIp = info[0].As<Napi::String>().Utf8Value();
    std::string targetMac = info[1].As<Napi::String>().Utf8Value();
    
    try {
        bool result = StartArpPoisoning(targetIp, targetMac);
        return Napi::Boolean::New(env, result);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
}

Napi::Boolean StopArpPoisoningWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected target IP as string").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    std::string targetIp = info[0].As<Napi::String>().Utf8Value();
    
    try {
        bool result = StopArpPoisoning(targetIp);
        return Napi::Boolean::New(env, result);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
}

Napi::Array EnumeratePcapDevicesWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Array result = Napi::Array::New(env);
    
    try {
        auto devices = EnumeratePcapDevices();
        
        for (size_t i = 0; i < devices.size(); ++i) {
            result.Set(i, Napi::String::New(env, devices[i]));
        }
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
    }
    
    return result;
}

// Initialize the module and export functions
Napi::Object Initialize(Napi::Env env, Napi::Object exports) {
    // Initialize Winsock
    #ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    #endif
    
    // Export network scanning functions
    exports.Set("scanDevices", Napi::Function::New(env, ScanDevices));
    exports.Set("scanDevicesFast", Napi::Function::New(env, ScanDevicesFast));
    exports.Set("getDeviceDetails", Napi::Function::New(env, GetDeviceDetails));
    exports.Set("resolveSingleDeviceName", Napi::Function::New(env, ResolveSingleDeviceName));
    
    // Export traffic control functions
    exports.Set("setBandwidthLimit", Napi::Function::New(env, SetBandwidthLimit));
    exports.Set("setDeviceBlocked", Napi::Function::New(env, SetDeviceBlocked));
    exports.Set("removeTrafficControl", Napi::Function::New(env, RemoveTrafficControl));
    exports.Set("getActiveControls", Napi::Function::New(env, GetActiveControls));
    
    // Export ARP functionality
    exports.Set("enumerateNetworkAdapters", Napi::Function::New(env, EnumerateNetworkAdapters));
    exports.Set("initializeArp", Napi::Function::New(env, InitializeArp));
    exports.Set("getNetworkTopology", Napi::Function::New(env, GetNetworkTopologyInfo));
    exports.Set("sendArpRequest", Napi::Function::New(env, SendArpRequestWrapper));
    exports.Set("getArpPerformanceStats", Napi::Function::New(env, GetArpPerformanceStatsWrapper));
    exports.Set("cleanupArp", Napi::Function::New(env, CleanupArpWrapper));
    
    // Export Phase 2: ARP poisoning functionality
    exports.Set("startArpPoisoning", Napi::Function::New(env, StartArpPoisoningWrapper));
    exports.Set("stopArpPoisoning", Napi::Function::New(env, StopArpPoisoningWrapper));
    exports.Set("enumeratePcapDevices", Napi::Function::New(env, EnumeratePcapDevicesWrapper));
    
    return exports;
}

NODE_API_MODULE(network, Initialize)