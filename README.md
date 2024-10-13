# Introduction

If you want to develop a wireless keyless system yourself that consists of a remote control for locking and unlocking doors with a high level of security, then you are on the right page.

The handheld remote control is hereinafter referred to as the `keyless client`, whereby the controller that is responsible for locking and unlocking the locking cylinder is hereinafter referred to as the `keyless server`. The system uses inexpensive and widely available electronic components that you can order from your local electronics retailer. The wireless medium used for communication is Wi-Fi, either the Wi-Fi of your existing home network or the Wi-Fi of an access point running on the `keyless server`. The security of the sytem is based on the asymetric cryptographic method RSA-2048, which implements a challenge-response authentication algorithm between the `keyless client` and the `keyless server`.

Please understand this project as an experiment and feel free to improve and extend it to your own needs. It is fully working but neither completely penetration tested nor measures were taken to prevent all kind of side channel attacks. The reproduction is therefore at your own risk. I assume no liability whatsoever.

# Hardware

## Components

### Raspberry Pi Zero W

Any board or PC can be used as the  `keyless server`, which is able to run the Python server script. If it is a headless system it is useful to activate SSH to be able to connect to the board in a secure way for configuration, up- and downloading files, maintenance, etc. I'm using the Raspberry Pi Zero W for the `keyless server` with the Raspberry Pi OS installed. Python version 3.x is required.

<img src="/KeylessServer/Hardware/RaspberryPI_ZeroW.png" alt="Raspberry PI Zero W" width="512"/>

### Microcontroller

I decided to use an ESP-12F ESP8266 Wi-Fi module from Adafruit Industries for the `keyless client`. It has a small form factor, enough CPU performance, all the required pins needed for this project, and most important no wakeup problems from deep sleep like many other ESP8266 boards had which I tested. The ESP-12F can be ordered with a white breakout PCB which can be seen in the following picture. The breakout board has already resistors mounted to pull LOW the GPIO15 pin and pull HIGH the Chip-Enable pin.

<img src="/KeylessClient/Hardware/ESP8266.png" alt="ESP8266" width="512"/>

### High-End Security Controller

There don't exist many standalone security controllers on the market. Often they are integrated only into high-end microcontollers. The standalone Optiga Trust M SLS32AIA chip from Infineon Technolgies was the best choice because of its well supported and easy to use software library. The asymetric cryptographic method RSA-2048 is perfectly supported including a secure private keystore. The chip comes on a breakout board from Adafruit Industries with pins for I²C.

<img src="/KeylessClient/Hardware/TrustM.png" alt="ESP8266" width="384"/>

### 3.3V Step-Up Voltage Regulator

### USB – Serial UART (TTL) Development Module

## Schematic

# Software

## Certificate Authority

## Keyless System

### Keyless Client

### Keyless Server
