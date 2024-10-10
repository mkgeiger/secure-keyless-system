# Introduction

If you want to develop a wireless keyless system yourself that consists of a remote control for locking and unlocking doors with a high level of security, then you are on the right page.

The handheld remote control is hereinafter referred to as the `keyless client`, whereby the controller that is responsible for locking and unlocking the locking cylinder is hereinafter referred to as the `keyless server`. The system uses inexpensive and widely available electronic components that you can order from your local electronics retailer. The wireless medium used for communication is Wi-Fi, either the Wi-Fi of your existing home network or the Wi-Fi of an access point running on the `keyless server`. The security of the sytem is based on the asymetric cryptographic method RSA-2048, which implements a challenge-response authentication algorithm between the `keyless client` and the `keyless server`.

Please understand this project as an experiment and feel free to improve and extend it to your own needs. It is fully working but neither completely penetration tested nor measures were taken to prevent all kind of side channel attacks. The reproduction is therefore at your own risk. I assume no liability whatsoever.

# Hardware

## Components

### Raspberry Pi Zero W

Any board or PC can be used as the  `keyless server`, which is able to run the Python server script. If it is a headless system it is useful to activate SSH to be able to connect to the board in a secure way for configuration, up- and downloading files, maintenance, etc. I'm using the Raspberry Pi Zero W for the `keyless server` with the Raspberry Pi OS installed. Python version 3.x is required.

<img src="/KeylessServer/Hardware/RaspberryPI_ZeroW.png" alt="Raspberry PI Zero W" width="1024"/>

### Microcontroller

### High-End Security Controller

### 3.3V Step-Up Voltage Regulator

### USB – Serial UART (TTL) Development Module

## Schematic

# Software

## Certificate Authority

## Keyless System

### Keyless Client

### Keyless Server
