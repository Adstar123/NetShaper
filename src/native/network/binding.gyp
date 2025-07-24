{
  "targets": [
    {
      "target_name": "network",
      "sources": [ "network.cpp", "arp.cpp" ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "./lib/Npcap/include"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS", "WPCAP", "HAVE_REMOTE" ],
      "conditions": [
        ["OS=='win'", {
          "conditions": [
            ["target_arch=='x64'", {
              "libraries": [
                "../lib/Npcap/Lib/x64/wpcap.lib",
                "../lib/Npcap/Lib/x64/Packet.lib",
                "ws2_32.lib",
                "iphlpapi.lib"
              ]
            }],
            ["target_arch=='arm64'", {
              "libraries": [
                "../lib/Npcap/Lib/ARM64/wpcap.lib",
                "../lib/Npcap/Lib/ARM64/Packet.lib",
                "ws2_32.lib",
                "iphlpapi.lib"
              ]
            }],
            ["target_arch=='ia32'", {
              "libraries": [
                "../lib/Npcap/Lib/wpcap.lib",
                "../lib/Npcap/Lib/Packet.lib",
                "ws2_32.lib",
                "iphlpapi.lib"
              ]
            }]
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1
            }
          }
        }]
      ]
    }
  ]
}