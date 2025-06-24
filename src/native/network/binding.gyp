{
  "targets": [
    {
      "target_name": "network",
      "sources": [ "network.cpp" ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "./lib/WinDivert/include"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
      "conditions": [
        ["OS=='win'", {
          "libraries": [
            "../lib/WinDivert/x64/WinDivert.lib",
            "ws2_32.lib",
            "iphlpapi.lib"
          ],
          "copies": [
            {
              "destination": "../../build/Release/",
              "files": [
                "./lib/WinDivert/x64/WinDivert.dll"
              ]
            }
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