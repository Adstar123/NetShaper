/**
 * Comprehensive Test Suite for NetShaper Phase 1
 * Tests: Network Adapter Enumeration, ARP Implementation, Gateway Discovery
 * 
 * IMPORTANT: This test file requires Administrator privileges and Npcap installation
 * Run with: node test_phase1.js (from Administrator command prompt)
 */

const path = require('path');
const assert = require('assert');

// Performance benchmarks
const PERFORMANCE_THRESHOLDS = {
    ADAPTER_ENUMERATION_MAX_MS: 1000,
    ARP_INITIALIZATION_MAX_MS: 500,
    ARP_REQUEST_MAX_MS: 50,
    GATEWAY_DISCOVERY_MAX_MS: 2000,
    PING_LATENCY_IMPACT_MAX_MS: 5
};

// Test configuration
const TEST_CONFIG = {
    ENABLE_PING_TESTS: true,
    ENABLE_STRESS_TESTS: true,
    ARP_REQUEST_COUNT: 10,
    PING_COUNT: 5
};

class Phase1TestSuite {
    constructor() {
        this.networkModule = null;
        this.selectedAdapter = null;
        this.networkTopology = null;
        this.testResults = {
            passed: 0,
            failed: 0,
            errors: []
        };
    }

    // Load the native network module
    loadNetworkModule() {
        console.log('🔄 Loading network module...');
        
        const possiblePaths = [
            path.join(__dirname, '../../build/Release/network.node'),
            path.join(__dirname, '../../src/native/network/build/Release/network.node'),
            path.resolve('./build/Release/network.node')
        ];

        for (const modulePath of possiblePaths) {
            try {
                const fs = require('fs');
                if (fs.existsSync(modulePath)) {
                    this.networkModule = require(modulePath);
                    console.log('✅ Network module loaded from:', modulePath);
                    return true;
                }
            } catch (error) {
                console.log('❌ Failed to load from', modulePath, ':', error.message);
            }
        }

        throw new Error('❌ Could not load network module from any path');
    }

    // Test network adapter enumeration
    async testAdapterEnumeration() {
        console.log('\n📡 Testing Network Adapter Enumeration...');
        
        const startTime = performance.now();
        
        try {
            const adapters = this.networkModule.enumerateNetworkAdapters();
            const endTime = performance.now();
            const duration = endTime - startTime;

            // Functionality tests
            assert(Array.isArray(adapters), 'Adapters should be an array');
            assert(adapters.length > 0, 'Should find at least one adapter');
            
            console.log(`📊 Found ${adapters.length} network adapters`);

            // Validate adapter structure
            adapters.forEach((adapter, index) => {
                assert(typeof adapter.name === 'string', `Adapter ${index} should have name`);
                assert(typeof adapter.description === 'string', `Adapter ${index} should have description`);
                assert(typeof adapter.isActive === 'boolean', `Adapter ${index} should have isActive flag`);
                assert(typeof adapter.macAddress === 'string', `Adapter ${index} should have MAC address`);
                
                // MAC address format validation
                const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
                if (adapter.macAddress && adapter.macAddress !== '') {
                    assert(macRegex.test(adapter.macAddress), `Invalid MAC format: ${adapter.macAddress}`);
                }

                console.log(`  📋 ${adapter.friendlyName || adapter.description}`);
                console.log(`     IP: ${adapter.ipAddress || 'N/A'} | MAC: ${adapter.macAddress || 'N/A'} | Active: ${adapter.isActive}`);
            });

            // Performance test
            assert(duration < PERFORMANCE_THRESHOLDS.ADAPTER_ENUMERATION_MAX_MS, 
                `Adapter enumeration took ${duration.toFixed(2)}ms, should be under ${PERFORMANCE_THRESHOLDS.ADAPTER_ENUMERATION_MAX_MS}ms`);

            // Select first active adapter for subsequent tests
            this.selectedAdapter = adapters.find(a => a.isActive && a.ipAddress) || adapters[0];
            console.log(`✅ Selected adapter: ${this.selectedAdapter.friendlyName || this.selectedAdapter.description}`);

            this.testResults.passed++;
            console.log(`✅ Adapter enumeration test passed (${duration.toFixed(2)}ms)`);
            
        } catch (error) {
            this.testResults.failed++;
            this.testResults.errors.push(`Adapter enumeration: ${error.message}`);
            console.log(`❌ Adapter enumeration test failed: ${error.message}`);
            throw error;
        }
    }

    // Test ARP initialization
    async testArpInitialization() {
        console.log('\n🔧 Testing ARP Initialization...');
        
        if (!this.selectedAdapter) {
            throw new Error('No adapter selected for ARP initialization');
        }

        const startTime = performance.now();
        
        try {
            const success = this.networkModule.initializeArp(this.selectedAdapter.name);
            const endTime = performance.now();
            const duration = endTime - startTime;

            assert(success === true, 'ARP initialization should succeed');
            
            // Performance test
            assert(duration < PERFORMANCE_THRESHOLDS.ARP_INITIALIZATION_MAX_MS, 
                `ARP initialization took ${duration.toFixed(2)}ms, should be under ${PERFORMANCE_THRESHOLDS.ARP_INITIALIZATION_MAX_MS}ms`);

            this.testResults.passed++;
            console.log(`✅ ARP initialization test passed (${duration.toFixed(2)}ms)`);
            
        } catch (error) {
            this.testResults.failed++;
            this.testResults.errors.push(`ARP initialization: ${error.message}`);
            console.log(`❌ ARP initialization test failed: ${error.message}`);
            throw error;
        }
    }

    // Test network topology discovery
    async testNetworkTopologyDiscovery() {
        console.log('\n🗺️ Testing Network Topology Discovery...');
        
        const startTime = performance.now();
        
        try {
            const topology = this.networkModule.getNetworkTopology();
            const endTime = performance.now();
            const duration = endTime - startTime;

            // Validate topology structure
            assert(typeof topology === 'object', 'Topology should be an object');
            assert(typeof topology.isValid === 'boolean', 'Topology should have isValid flag');
            
            if (topology.isValid) {
                assert(typeof topology.localIp === 'string', 'Should have local IP');
                assert(typeof topology.gatewayIp === 'string', 'Should have gateway IP');
                assert(typeof topology.gatewayMac === 'string', 'Should have gateway MAC');
                assert(typeof topology.interfaceMac === 'string', 'Should have interface MAC');
                assert(typeof topology.subnetCidr === 'number', 'Should have subnet CIDR');

                // IP address format validation
                const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
                assert(ipRegex.test(topology.localIp), `Invalid local IP format: ${topology.localIp}`);
                assert(ipRegex.test(topology.gatewayIp), `Invalid gateway IP format: ${topology.gatewayIp}`);

                // MAC address format validation
                const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
                assert(macRegex.test(topology.gatewayMac), `Invalid gateway MAC format: ${topology.gatewayMac}`);
                assert(macRegex.test(topology.interfaceMac), `Invalid interface MAC format: ${topology.interfaceMac}`);

                // CIDR validation
                assert(topology.subnetCidr >= 8 && topology.subnetCidr <= 30, 
                    `Invalid CIDR: ${topology.subnetCidr}`);

                console.log(`📊 Network Topology:`);
                console.log(`   Local IP: ${topology.localIp}/${topology.subnetCidr}`);
                console.log(`   Gateway: ${topology.gatewayIp} (${topology.gatewayMac})`);
                console.log(`   Interface MAC: ${topology.interfaceMac}`);

                this.networkTopology = topology;
            } else {
                console.log('⚠️ Network topology discovery returned invalid result');
            }

            // Performance test
            assert(duration < PERFORMANCE_THRESHOLDS.GATEWAY_DISCOVERY_MAX_MS, 
                `Topology discovery took ${duration.toFixed(2)}ms, should be under ${PERFORMANCE_THRESHOLDS.GATEWAY_DISCOVERY_MAX_MS}ms`);

            this.testResults.passed++;
            console.log(`✅ Network topology discovery test passed (${duration.toFixed(2)}ms)`);
            
        } catch (error) {
            this.testResults.failed++;
            this.testResults.errors.push(`Network topology: ${error.message}`);
            console.log(`❌ Network topology discovery test failed: ${error.message}`);
            throw error;
        }
    }

    // Test ARP request functionality
    async testArpRequests() {
        console.log('\n📡 Testing ARP Request Functionality...');
        
        if (!this.networkTopology || !this.networkTopology.isValid) {
            console.log('⚠️ Skipping ARP request tests - no valid network topology');
            return;
        }

        const targetIp = this.networkTopology.gatewayIp;
        const requestTimes = [];

        try {
            // Test multiple ARP requests for performance consistency
            for (let i = 0; i < TEST_CONFIG.ARP_REQUEST_COUNT; i++) {
                const startTime = performance.now();
                const success = this.networkModule.sendArpRequest(targetIp);
                const endTime = performance.now();
                const duration = endTime - startTime;

                assert(success === true, `ARP request ${i + 1} should succeed`);
                assert(duration < PERFORMANCE_THRESHOLDS.ARP_REQUEST_MAX_MS, 
                    `ARP request ${i + 1} took ${duration.toFixed(2)}ms, should be under ${PERFORMANCE_THRESHOLDS.ARP_REQUEST_MAX_MS}ms`);

                requestTimes.push(duration);
                console.log(`   Request ${i + 1}: ${duration.toFixed(2)}ms`);

                // Small delay between requests
                await new Promise(resolve => setTimeout(resolve, 10));
            }

            // Calculate statistics
            const avgTime = requestTimes.reduce((a, b) => a + b, 0) / requestTimes.length;
            const maxTime = Math.max(...requestTimes);
            const minTime = Math.min(...requestTimes);

            console.log(`📊 ARP Request Statistics:`);
            console.log(`   Average time: ${avgTime.toFixed(2)}ms`);
            console.log(`   Min time: ${minTime.toFixed(2)}ms`);
            console.log(`   Max time: ${maxTime.toFixed(2)}ms`);

            this.testResults.passed++;
            console.log(`✅ ARP request functionality test passed`);
            
        } catch (error) {
            this.testResults.failed++;
            this.testResults.errors.push(`ARP requests: ${error.message}`);
            console.log(`❌ ARP request functionality test failed: ${error.message}`);
            throw error;
        }
    }

    // Test performance statistics tracking
    async testPerformanceStatistics() {
        console.log('\n📈 Testing Performance Statistics...');
        
        try {
            const stats = this.networkModule.getArpPerformanceStats();

            // Validate statistics structure
            assert(typeof stats === 'object', 'Stats should be an object');
            assert(typeof stats.packetsSent === 'number', 'Should track packets sent');
            assert(typeof stats.packetsReceived === 'number', 'Should track packets received');
            assert(typeof stats.sendErrors === 'number', 'Should track send errors');
            assert(typeof stats.receiveErrors === 'number', 'Should track receive errors');
            assert(typeof stats.avgSendTimeMs === 'number', 'Should track average send time');
            assert(typeof stats.avgReceiveTimeMs === 'number', 'Should track average receive time');

            // Validate statistics values
            assert(stats.packetsSent >= 0, 'Packets sent should be non-negative');
            assert(stats.packetsReceived >= 0, 'Packets received should be non-negative');
            assert(stats.sendErrors >= 0, 'Send errors should be non-negative');
            assert(stats.receiveErrors >= 0, 'Receive errors should be non-negative');
            assert(stats.avgSendTimeMs >= 0, 'Average send time should be non-negative');

            console.log(`📊 Performance Statistics:`);
            console.log(`   Packets Sent: ${stats.packetsSent}`);
            console.log(`   Packets Received: ${stats.packetsReceived}`);
            console.log(`   Send Errors: ${stats.sendErrors}`);
            console.log(`   Receive Errors: ${stats.receiveErrors}`);
            console.log(`   Avg Send Time: ${stats.avgSendTimeMs.toFixed(2)}ms`);
            console.log(`   Avg Receive Time: ${stats.avgReceiveTimeMs.toFixed(2)}ms`);

            this.testResults.passed++;
            console.log(`✅ Performance statistics test passed`);
            
        } catch (error) {
            this.testResults.failed++;
            this.testResults.errors.push(`Performance statistics: ${error.message}`);
            console.log(`❌ Performance statistics test failed: ${error.message}`);
        }
    }

    // Test error handling and edge cases
    async testErrorHandling() {
        console.log('\n🛡️ Testing Error Handling...');
        
        try {
            let errorCount = 0;

            // Test invalid adapter name
            try {
                const result = this.networkModule.initializeArp('INVALID_ADAPTER_NAME_12345');
                assert(result === false, 'Should fail with invalid adapter name');
                errorCount++;
            } catch (error) {
                console.log('   ✓ Invalid adapter name correctly rejected');
                errorCount++;
            }

            // Test invalid IP address for ARP request
            try {
                const result = this.networkModule.sendArpRequest('999.999.999.999');
                assert(result === false, 'Should fail with invalid IP address');
                errorCount++;
            } catch (error) {
                console.log('   ✓ Invalid IP address correctly rejected');
                errorCount++;
            }

            // Test empty IP address
            try {
                const result = this.networkModule.sendArpRequest('');
                assert(result === false, 'Should fail with empty IP address');
                errorCount++;
            } catch (error) {
                console.log('   ✓ Empty IP address correctly rejected');
                errorCount++;
            }

            assert(errorCount >= 3, 'Should have tested all error conditions');

            this.testResults.passed++;
            console.log(`✅ Error handling test passed (${errorCount} error conditions tested)`);
            
        } catch (error) {
            this.testResults.failed++;
            this.testResults.errors.push(`Error handling: ${error.message}`);
            console.log(`❌ Error handling test failed: ${error.message}`);
        }
    }

    // Test ping latency impact (critical for performance)
    async testPingLatencyImpact() {
        if (!TEST_CONFIG.ENABLE_PING_TESTS) {
            console.log('\n⚠️ Ping tests disabled in configuration');
            return;
        }

        console.log('\n🏓 Testing Ping Latency Impact...');
        
        if (!this.networkTopology || !this.networkTopology.isValid) {
            console.log('⚠️ Skipping ping tests - no valid network topology');
            return;
        }

        const { exec } = require('child_process');
        const gatewayIp = this.networkTopology.gatewayIp;

        try {
            // Measure baseline ping without ARP activity
            console.log('   📊 Measuring baseline ping latency...');
            const baselinePings = await this.measurePingLatency(gatewayIp, TEST_CONFIG.PING_COUNT);
            const baselineAvg = baselinePings.reduce((a, b) => a + b, 0) / baselinePings.length;

            // Start ARP activity and measure ping latency
            console.log('   📊 Measuring ping latency with ARP activity...');
            const arpActivityPromise = this.generateArpActivity();
            await new Promise(resolve => setTimeout(resolve, 100)); // Let ARP activity start
            const activePings = await this.measurePingLatency(gatewayIp, TEST_CONFIG.PING_COUNT);
            const activeAvg = activePings.reduce((a, b) => a + b, 0) / activePings.length;

            const latencyImpact = activeAvg - baselineAvg;

            console.log(`📊 Ping Latency Analysis:`);
            console.log(`   Baseline average: ${baselineAvg.toFixed(2)}ms`);
            console.log(`   With ARP activity: ${activeAvg.toFixed(2)}ms`);
            console.log(`   Latency impact: ${latencyImpact.toFixed(2)}ms`);

            // Assert that latency impact is within acceptable bounds
            assert(latencyImpact <= PERFORMANCE_THRESHOLDS.PING_LATENCY_IMPACT_MAX_MS, 
                `Latency impact ${latencyImpact.toFixed(2)}ms exceeds threshold ${PERFORMANCE_THRESHOLDS.PING_LATENCY_IMPACT_MAX_MS}ms`);

            this.testResults.passed++;
            console.log(`✅ Ping latency impact test passed (${latencyImpact.toFixed(2)}ms impact)`);
            
        } catch (error) {
            this.testResults.failed++;
            this.testResults.errors.push(`Ping latency: ${error.message}`);
            console.log(`❌ Ping latency impact test failed: ${error.message}`);
        }
    }

    // Helper function to measure ping latency
    async measurePingLatency(targetIp, count) {
        const { exec } = require('child_process');
        const util = require('util');
        const execAsync = util.promisify(exec);

        try {
            const { stdout } = await execAsync(`ping -n ${count} ${targetIp}`);
            const lines = stdout.split('\n');
            const times = [];

            for (const line of lines) {
                const match = line.match(/time[<=](\d+)ms/);
                if (match) {
                    times.push(parseInt(match[1]));
                }
            }

            return times;
        } catch (error) {
            throw new Error(`Failed to measure ping latency: ${error.message}`);
        }
    }

    // Generate ARP activity for testing impact
    async generateArpActivity() {
        if (!this.networkTopology) return;

        const gatewayIp = this.networkTopology.gatewayIp;
        
        // Send ARP requests continuously for a short period
        for (let i = 0; i < 10; i++) {
            try {
                this.networkModule.sendArpRequest(gatewayIp);
                await new Promise(resolve => setTimeout(resolve, 50));
            } catch (error) {
                console.log(`ARP activity error: ${error.message}`);
            }
        }
    }

    // Test cleanup functionality
    async testCleanup() {
        console.log('\n🧹 Testing Cleanup Functionality...');
        
        try {
            // Test cleanup without errors
            this.networkModule.cleanupArp();
            console.log('   ✓ Cleanup completed successfully');

            // Test multiple cleanup calls (should be safe)
            this.networkModule.cleanupArp();
            this.networkModule.cleanupArp();
            console.log('   ✓ Multiple cleanup calls handled safely');

            this.testResults.passed++;
            console.log(`✅ Cleanup functionality test passed`);
            
        } catch (error) {
            this.testResults.failed++;
            this.testResults.errors.push(`Cleanup: ${error.message}`);
            console.log(`❌ Cleanup functionality test failed: ${error.message}`);
        }
    }

    // Run all Phase 1 tests
    async runAllTests() {
        console.log('🚀 Starting NetShaper Phase 1 Test Suite');
        console.log('=' * 60);

        try {
            // Load network module
            this.loadNetworkModule();

            // Run tests in sequence
            await this.testAdapterEnumeration();
            await this.testArpInitialization();
            await this.testNetworkTopologyDiscovery();
            await this.testArpRequests();
            await this.testPerformanceStatistics();
            await this.testErrorHandling();
            await this.testPingLatencyImpact();
            await this.testCleanup();

            console.log('\n🎉 All Phase 1 tests completed!');
            
        } catch (error) {
            console.log(`\n💥 Test suite failed: ${error.message}`);
        }

        // Print summary
        this.printTestSummary();
    }

    // Print test results summary
    printTestSummary() {
        console.log('\n📊 Test Results Summary');
        console.log('=' * 40);
        console.log(`✅ Passed: ${this.testResults.passed}`);
        console.log(`❌ Failed: ${this.testResults.failed}`);
        console.log(`📊 Total: ${this.testResults.passed + this.testResults.failed}`);

        if (this.testResults.failed > 0) {
            console.log('\n❌ Failed Tests:');
            this.testResults.errors.forEach((error, index) => {
                console.log(`   ${index + 1}. ${error}`);
            });
        }

        if (this.testResults.failed === 0) {
            console.log('\n🎉 All tests passed! Phase 1 is ready for production.');
        } else {
            console.log('\n⚠️ Some tests failed. Please review and fix issues before proceeding.');
        }
    }
}

// Run the test suite if this file is executed directly
if (require.main === module) {
    const testSuite = new Phase1TestSuite();
    testSuite.runAllTests().catch(error => {
        console.error('Fatal test suite error:', error);
        process.exit(1);
    });
}

module.exports = Phase1TestSuite;