const path = require('path');

// Test configuration
const TEST_CONFIG = {
    ENABLE_PCAP_TESTS: true,
    ENABLE_ARP_POISONING_TESTS: true,
    ENABLE_ADAPTER_MAPPING_TESTS: true,
    ARP_POISONING_DURATION_MS: 5000,  // 5 seconds for safety
    TEST_TARGET_IP: '192.168.1.1',    // Default gateway - safe target
    VERBOSE_LOGGING: true
};

// Performance thresholds for Phase 2
const PERFORMANCE_THRESHOLDS = {
    ADAPTER_MAPPING_MAX_MS: 2000,      // Max time for adapter mapping
    ARP_POISONING_START_MAX_MS: 100,   // Max time to start poisoning
    ARP_POISONING_STOP_MAX_MS: 100,    // Max time to stop poisoning
    PCAP_ENUMERATION_MAX_MS: 1000      // Max time to enumerate pcap devices
};

console.log('🚀 Starting NetShaper Phase 2 Test Suite');
console.log('============================================================');
console.log('Phase 2: ARP Poisoning Engine - Enhanced Network Control');
console.log('');

// Test counter
let testsRun = 0;
let testsPassed = 0;
let testsFailed = 0;

function logTest(testName, status, timeMs = null, details = null) {
    testsRun++;
    const emoji = status === 'PASS' ? '✅' : status === 'FAIL' ? '❌' : '⚠️';
    const timeStr = timeMs !== null ? ` (${timeMs.toFixed(2)}ms)` : '';
    
    console.log(`${emoji} ${testName}${timeStr}`);
    
    if (details) {
        console.log(`   ${details}`);
    }
    
    if (status === 'PASS') {
        testsPassed++;
    } else if (status === 'FAIL') {
        testsFailed++;
    }
}

function testPerformance(actualMs, thresholdMs, operation) {
    if (actualMs <= thresholdMs) {
        return { pass: true, message: `${operation} completed in ${actualMs.toFixed(2)}ms (threshold: ${thresholdMs}ms)` };
    } else {
        return { pass: false, message: `${operation} took ${actualMs.toFixed(2)}ms, exceeds threshold of ${thresholdMs}ms` };
    }
}

// Main test execution
async function runPhase2Tests() {
    console.log('🔄 Loading network module...');
    
    // Load the native module
    let network;
    try {
        const modulePath = path.join(__dirname, '../../build/Release/network.node');
        network = require(modulePath);
        console.log(`✅ Network module loaded from: ${modulePath}`);
    } catch (error) {
        console.log(`❌ Failed to load network module: ${error.message}`);
        console.log('');
        console.log('📋 Prerequisites Check:');
        console.log('   • Ensure the native module is built: cd src/native/network && npx node-gyp rebuild');
        console.log('   • Ensure running on Windows with Administrator privileges');
        console.log('   • Ensure Npcap is installed');
        console.log('');
        process.exit(1);
    }
    
    // Phase 2 Test 1: Pcap Device Enumeration
    if (TEST_CONFIG.ENABLE_PCAP_TESTS) {
        console.log('');
        console.log('📡 Testing Pcap Device Enumeration...');
        
        try {
            const startTime = Date.now();
            const pcapDevices = network.enumeratePcapDevices();
            const endTime = Date.now();
            const duration = endTime - startTime;
            
            if (Array.isArray(pcapDevices) && pcapDevices.length > 0) {
                const perfResult = testPerformance(duration, PERFORMANCE_THRESHOLDS.PCAP_ENUMERATION_MAX_MS, 'Pcap enumeration');
                logTest('Pcap device enumeration test', perfResult.pass ? 'PASS' : 'FAIL', duration, perfResult.message);
                
                console.log(`📊 Found ${pcapDevices.length} pcap devices:`);
                pcapDevices.forEach((device, index) => {
                    console.log(`   ${index + 1}. ${device}`);
                });
            } else {
                logTest('Pcap device enumeration test', 'FAIL', duration, 'No pcap devices found - check Npcap installation');
            }
        } catch (error) {
            logTest('Pcap device enumeration test', 'FAIL', null, `Error: ${error.message}`);
        }
    }
    
    // Phase 2 Test 2: Enhanced Network Adapter Enumeration with Pcap Mapping
    if (TEST_CONFIG.ENABLE_ADAPTER_MAPPING_TESTS) {
        console.log('');
        console.log('📡 Testing Enhanced Network Adapter Enumeration...');
        
        try {
            const startTime = Date.now();
            const adapters = network.enumerateNetworkAdapters();
            const endTime = Date.now();
            const duration = endTime - startTime;
            
            if (Array.isArray(adapters) && adapters.length > 0) {
                const perfResult = testPerformance(duration, PERFORMANCE_THRESHOLDS.ADAPTER_MAPPING_MAX_MS, 'Adapter enumeration with mapping');
                logTest('Enhanced adapter enumeration test', perfResult.pass ? 'PASS' : 'FAIL', duration, perfResult.message);
                
                console.log(`📊 Found ${adapters.length} network adapters with pcap mapping:`);
                adapters.forEach((adapter, index) => {
                    const status = adapter.isActive ? 'Active' : 'Inactive';
                    const pcapStatus = adapter.pcapName ? '🔗 Mapped' : '❌ No mapping';
                    console.log(`   📋 ${adapter.friendlyName || adapter.description}`);
                    console.log(`      IP: ${adapter.ipAddress || 'N/A'} | MAC: ${adapter.macAddress} | ${status}`);
                    console.log(`      Windows Name: ${adapter.name}`);
                    console.log(`      Pcap Name: ${adapter.pcapName || 'Not mapped'} | ${pcapStatus}`);
                    console.log('');
                });
                
                // Check that at least one adapter has pcap mapping
                const mappedAdapters = adapters.filter(a => a.pcapName && a.pcapName.length > 0);
                if (mappedAdapters.length > 0) {
                    logTest('Adapter pcap mapping test', 'PASS', null, `${mappedAdapters.length}/${adapters.length} adapters successfully mapped to pcap devices`);
                } else {
                    logTest('Adapter pcap mapping test', 'FAIL', null, 'No adapters could be mapped to pcap devices - check Npcap installation');
                }
            } else {
                logTest('Enhanced adapter enumeration test', 'FAIL', duration, 'No network adapters found');
            }
        } catch (error) {
            logTest('Enhanced adapter enumeration test', 'FAIL', null, `Error: ${error.message}`);
        }
    }
    
    // Phase 2 Test 3: ARP Manager Initialization with Pcap
    console.log('');
    console.log('🔧 Testing ARP Manager Initialization with Pcap Support...');
    
    let selectedAdapter = null;
    try {
        // Get adapters and select an active one with pcap mapping
        const adapters = network.enumerateNetworkAdapters();
        selectedAdapter = adapters.find(a => a.isActive && a.pcapName && a.ipAddress);
        
        if (!selectedAdapter) {
            logTest('ARP initialization test', 'SKIP', null, 'No suitable adapter found (need active adapter with pcap mapping)');
        } else {
            console.log(`🎯 Using adapter: ${selectedAdapter.friendlyName} (${selectedAdapter.name})`);
            console.log(`   Pcap device: ${selectedAdapter.pcapName}`);
            
            const startTime = Date.now();
            const initResult = network.initializeArp(selectedAdapter.name);
            const endTime = Date.now();
            const duration = endTime - startTime;
            
            if (initResult) {
                const perfResult = testPerformance(duration, PERFORMANCE_THRESHOLDS.ADAPTER_MAPPING_MAX_MS, 'ARP initialization');
                logTest('ARP initialization test', perfResult.pass ? 'PASS' : 'FAIL', duration, perfResult.message);
                
                // Get network topology to verify initialization
                const topology = network.getNetworkTopology();
                if (topology && topology.isValid) {
                    console.log('📊 Network Topology (Phase 2):');
                    console.log(`   Local IP: ${topology.localIp}/${topology.subnetCidr}`);
                    console.log(`   Gateway: ${topology.gatewayIp} (${topology.gatewayMac || 'MAC TBD'})`);
                    console.log(`   Interface: ${topology.interfaceName}`);
                    console.log(`   Interface MAC: ${topology.interfaceMac}`);
                    
                    logTest('Network topology discovery test', 'PASS', null, 'Network topology successfully discovered');
                } else {
                    logTest('Network topology discovery test', 'FAIL', null, 'Failed to discover network topology');
                }
            } else {
                logTest('ARP initialization test', 'FAIL', duration, 'ARP initialization returned false');
            }
        }
    } catch (error) {
        logTest('ARP initialization test', 'FAIL', null, `Error: ${error.message}`);
    }
    
    // Phase 2 Test 4: ARP Poisoning Functionality (Controlled Test)
    if (TEST_CONFIG.ENABLE_ARP_POISONING_TESTS && selectedAdapter) {
        console.log('');
        console.log('🧪 Testing ARP Poisoning Functionality (Controlled Test)...');
        console.log('⚠️  This test will perform CONTROLLED ARP poisoning for testing purposes');
        console.log('⚠️  Target: Gateway (safe test target)');
        console.log('⚠️  Duration: 5 seconds maximum');
        
        try {
            const topology = network.getNetworkTopology();
            if (!topology || !topology.isValid || !topology.gatewayIp) {
                logTest('ARP poisoning test', 'SKIP', null, 'No valid network topology available');
            } else {
                const targetIp = topology.gatewayIp;
                const targetMac = topology.gatewayMac || '00:00:00:00:00:00'; // Default if not discovered
                
                console.log(`🎯 Test target: ${targetIp} (${targetMac})`);
                
                // Test starting ARP poisoning
                const startTime = Date.now();
                const startResult = network.startArpPoisoning(targetIp, targetMac);
                const startEndTime = Date.now();
                const startDuration = startEndTime - startTime;
                
                if (startResult) {
                    const startPerfResult = testPerformance(startDuration, PERFORMANCE_THRESHOLDS.ARP_POISONING_START_MAX_MS, 'ARP poisoning start');
                    logTest('ARP poisoning start test', startPerfResult.pass ? 'PASS' : 'FAIL', startDuration, startPerfResult.message);
                    
                    // Wait briefly to let poisoning take effect
                    console.log('⏳ Running ARP poisoning for 3 seconds...');
                    await new Promise(resolve => setTimeout(resolve, 3000));
                    
                    // Test stopping ARP poisoning
                    const stopTime = Date.now();
                    const stopResult = network.stopArpPoisoning(targetIp);
                    const stopEndTime = Date.now();
                    const stopDuration = stopEndTime - stopTime;
                    
                    if (stopResult) {
                        const stopPerfResult = testPerformance(stopDuration, PERFORMANCE_THRESHOLDS.ARP_POISONING_STOP_MAX_MS, 'ARP poisoning stop');
                        logTest('ARP poisoning stop test', stopPerfResult.pass ? 'PASS' : 'FAIL', stopDuration, stopPerfResult.message);
                        
                        console.log('✅ ARP poisoning test completed safely');
                    } else {
                        logTest('ARP poisoning stop test', 'FAIL', stopDuration, 'Failed to stop ARP poisoning');
                    }
                } else {
                    logTest('ARP poisoning start test', 'FAIL', startDuration, 'Failed to start ARP poisoning');
                }
            }
        } catch (error) {
            logTest('ARP poisoning test', 'FAIL', null, `Error: ${error.message}`);
        }
    }
    
    // Phase 2 Test 5: Performance Statistics
    console.log('');
    console.log('📈 Testing ARP Performance Statistics...');
    
    try {
        const stats = network.getArpPerformanceStats();
        
        if (stats && typeof stats === 'object') {
            console.log('📊 ARP Performance Statistics:');
            console.log(`   Packets Sent: ${stats.packetsSent}`);
            console.log(`   Packets Received: ${stats.packetsReceived}`);
            console.log(`   Send Errors: ${stats.sendErrors}`);
            console.log(`   Receive Errors: ${stats.receiveErrors}`);
            console.log(`   Avg Send Time: ${stats.avgSendTimeMs?.toFixed(2)}ms`);
            console.log(`   Avg Receive Time: ${stats.avgReceiveTimeMs?.toFixed(2)}ms`);
            
            logTest('Performance statistics test', 'PASS', null, `Statistics retrieved successfully`);
        } else {
            logTest('Performance statistics test', 'FAIL', null, 'Invalid statistics object returned');
        }
    } catch (error) {
        logTest('Performance statistics test', 'FAIL', null, `Error: ${error.message}`);
    }
    
    // Phase 2 Test 6: Cleanup and Safety
    console.log('');
    console.log('🧹 Testing Cleanup Functionality...');
    
    try {
        network.cleanupArp();
        logTest('Cleanup functionality test', 'PASS', null, 'Cleanup completed successfully');
        
        // Test multiple cleanup calls for safety
        network.cleanupArp();
        network.cleanupArp();
        logTest('Multiple cleanup calls test', 'PASS', null, 'Multiple cleanup calls handled safely');
    } catch (error) {
        logTest('Cleanup functionality test', 'FAIL', null, `Error: ${error.message}`);
    }
    
    // Test Results Summary
    console.log('');
    console.log('🎉 Phase 2 test suite completed!');
    console.log('');
    console.log('📊 Test Results Summary');
    console.log('========================================');
    console.log(`✅ Passed: ${testsPassed}`);
    console.log(`❌ Failed: ${testsFailed}`);
    console.log(`📊 Total: ${testsRun}`);
    console.log('');
    
    if (testsFailed === 0) {
        console.log('🎉 All tests passed! Phase 2 ARP poisoning engine is ready for integration.');
        console.log('');
        console.log('🚀 Phase 2 Status: COMPLETE ✅');
        console.log('   ✅ Adapter name mapping functional');
        console.log('   ✅ Pcap device enumeration working');
        console.log('   ✅ ARP poisoning engine operational');
        console.log('   ✅ Performance monitoring active');
        console.log('   ✅ Cleanup and safety mechanisms working');
        console.log('');
        console.log('📋 Ready for Phase 3: Traffic Control Implementation');
    } else {
        console.log(`⚠️  ${testsFailed} test(s) failed. Please review the issues above.`);
        console.log('');
        console.log('🔧 Common Issues:');
        console.log('   • Ensure Npcap is properly installed');
        console.log('   • Ensure running as Administrator on Windows');
        console.log('   • Ensure no other network tools are interfering');
        console.log('   • Check Windows Firewall settings');
    }
    
    console.log('');
    console.log('⚠️  Important: This is an educational project for resume purposes only.');
    console.log('⚠️  Use responsibly and only on networks you own or have permission to test.');
}

// Run the tests
runPhase2Tests().catch(error => {
    console.error('💥 Test suite crashed:', error);
    process.exit(1);
});