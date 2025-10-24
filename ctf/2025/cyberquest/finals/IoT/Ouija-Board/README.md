# CyberQuest 2025 - Final - Ouija Board

## Description

# Ouija Board

I'm shivering to the bone! Would you look at weather. It's FREEZING cold.

Is it though? What's the temperature?

> Remarks from the authors:
> * You will need the provided hardware.
> * Start with the "Mission: Comission #2" challenge first.
> * Device needs to be USB powered. There is no battery. You should see some e-ink flashes.
> * The device is already on the Wi-Fi network, there is no need for special Bluetooth LE equipment.
> * If a pairing/commissioning fails for whatever reason, it is recommended to restart the device before the next try. Click the small RST button shortly on the device.

Challenge difficulty: `medium`

*Proudly sponsored by CUJO AI*

## Metadata

- Filename: -
- Tags: `iot`, `matter`

## Solution

If we connect the device via USB to our computer it will be available on `/dev/ttyACM0`.

Using `minicom` we can connect to it.

It prints a lot of information during boot and after commissioning, it also prints the characters of the flag (as temperature values).

```
$ sudo minicom -s
[...]
mode:DIO, clock div:2
load:0x3fff0030,len:6276
load:0x40078000,len:15748
load:0x40080400,len:4
ho 8 tail 4 room 4
load:0x40080404,len:3860
entry 0x4008063c
I (31) boot: ESP-IDF...
I (51) boot: Partition Table:
I (53) boot: ## Label            Usage          Type ST Offset   Length
I (60) boot:  0 esp_secure_cert  unknown          3f 06 0000d000 00002000
I (66) boot:  1 nvs              WiFi data        01 02 00010000 0000c000
I (73) boot:  2 nvs_keys         NVS keys         01 04 0001c000 00001000
I (79) boot:  3 otadata          OTA data         01 00 0001d000 00002000
I (86) boot:  4 phy_init         RF data          01 01 0001f000 00001000
I (92) boot:  5 ota_0            OTA app          00 10 00020000 001e0000
I (99) boot:  6 ota_1            OTA app          00 11 00200000 001e0000
I (105) boot:  7 fctry            WiFi data        01 02 003e0000 00006000
I (112) boot: End of partition table
I (115) esp_image: segment 0: paddr=00020020 vaddr=3f400020 size=462a4h (287396) map
I (221) esp_image: segment 1: paddr=000662cc vaddr=3ff80000 size=0001ch (    28) load
I (221) esp_image: segment 2: paddr=000662f0 vaddr=3ffbdb60 size=06250h ( 25168) load
I (234) esp_image: segment 3: paddr=0006c548 vaddr=40080000 size=03ad0h ( 15056) load
I (240) esp_image: segment 4: paddr=00070020 vaddr=400d0020 size=112db8h (1125816) map
I (625) esp_image: segment 5: paddr=00182de0 vaddr=40083ad0 size=1ae94h (110228) load
I (683) boot: Loaded app from partition at offset 0x20000
I (683) boot: Disabling RNG early entropy source...
I (694) cpu_start: Multicore app
I (702) cpu_start: Pro cpu start user code
I (702) cpu_start: cpu freq: 160000000 Hz
I (702) app_init: Application information:
I (702) app_init: Project name:     demo-badge
I (706) app_init: App version:      not.a.flag
I (710) app_init: Compile time:     Sep 19 2025 08:05:19
I (716) app_init: ELF file SHA256:  b59898ac4...
I (720) app_init: ESP-IDF:          4c2820d3
I (724) efuse_init: Min chip rev:     v0.0
I (728) efuse_init: Max chip rev:     v3.99
I (732) efuse_init: Chip rev:         v3.0
I (736) heap_init: Initializing. RAM available for dynamic allocation:
I (742) heap_init: At 3FFAFF10 len 000000F0 (0 KiB): DRAM
I (747) heap_init: At 3FFB6388 len 00001C78 (7 KiB): DRAM
I (752) heap_init: At 3FFB9A20 len 00004108 (16 KiB): DRAM
I (757) heap_init: At 3FFD9290 len 00006D70 (27 KiB): DRAM
I (762) heap_init: At 3FFE0440 len 00003AE0 (14 KiB): D/IRAM
I (768) heap_init: At 3FFE4350 len 0001BCB0 (111 KiB): D/IRAM
I (773) heap_init: At 4009E964 len 0000169C (5 KiB): IRAM
I (780) spi_flash: detected chip: winbond
I (782) spi_flash: flash io: dio
I (789) coexist: coex firmware version: e727207
I (791) main_task: Started on CPU0
I (801) main_task: Calling app_main()
I (801) gpio: GPIO[4]| InputEn: 1| OutputEn: 0| OpenDrain: 0| Pullup: 0| Pulldown: 1| Intr:0
I (801) gpio: GPIO[5]| InputEn: 0| OutputEn: 1| OpenDrain: 0| Pullup: 0| Pulldown: 1| Intr:0
I (811) gpio: GPIO[16]| InputEn: 0| OutputEn: 1| OpenDrain: 0| Pullup: 0| Pulldown: 1| Intr:0
I (821) gpio: GPIO[17]| InputEn: 0| OutputEn: 1| OpenDrain: 0| Pullup: 0| Pulldown: 1| Intr:0
I (821) gpio: GPIO[18]| InputEn: 0| OutputEn: 1| OpenDrain: 0| Pullup: 0| Pulldown: 1| Intr:0
I (831) gpio: GPIO[23]| InputEn: 0| OutputEn: 1| OpenDrain: 0| Pullup: 0| Pulldown: 1| Intr:0
I (851) lowpower_evb_epaper: before epaper init, heap: 157564
I (851) epaper: gpio init ok
I (851) epaper: spi init ok
79fa3f41ba
I (71, core=0
I (7181) wifi:wifi firmware version: IulloT Button Version: 4.1.3
I (7131) app_main: Light created with endpoint_id 1
I (7141) app_main: Creating temperature sensor endpoint
I (7141) app_main: Temperature sensor created... Getting endpoint ID
I (7141) app_main: Temperature sensor created 79fa3f41ba
I (7181) wifi:wifi certification version: v7.0
I (7181) wifi:config NVS flash: enabled
I (7181) wifi:config nano formatting: disabled
I (7191) wifi:Init data frame dynamic rx buffer num: 32
I (7191) wifi:Init static rx mgmt buffer num: 5
I (7201) wifi:Init management short buffer num: 32
I (7201) wifi:Init dynamic tx buffer num: 32
I (7211) wifi:Init static rx buffer size: 1600
I (7211) wifi:Init static rx buffer num: 10
I (7211) wifi:Init dynamic rx buffer num: 32
I (7221) wifi_init: rx ba win: 6
I (7221) wifi_init: accept mbox: 6
I (7221) wifi_init: tcpip mbox: 32
I (7231) wifi_init: udp mbox: 6
I (7231) wifi_init: tcp mbox: 6
I (7231) wifi_init: tcp tx win: 5760
I (7241) wifi_init: tcp rx win: 5760
I (7241) wifi_init: tcp mss: 1440
I (7241) wifi_init: WiFi IRAM OP enabled
I (7251) wifi_init: WiFi RX IRAM OP enabled
I (7271) chip[DL]: NVS set: chip-counters/reboot-count = 6 (0x6)
I (7271) chip[DL]: Real time clock set to 946684800 (2000-01-01 00:00:00 UTC)
I (7271) BTDM_INIT: BT controller compile version [dc1cd58]
I (7281) BTDM_INIT: Bluetooth MAC: d4:d4:da:5c:c3:fe
I (7281) phy_init: phy_version 4860,6b7a6e5,Feb  6 2025,14:47:07
I (7371) phy_init: Saving new calibration data due to checksum failure or outdated calibration data, mode(0)
I (7671) CHIP[DL]: BLE host-controller synced
E (8181) chip[DL]: Long dispatch time: 904 ms, for event type 2
I (8181) chip[DL]: Starting ESP WiFi layer
I (8181) wifi:mode : sta (d4:d4:da:5c:c3:fc)
I (8181) wifi:enable tsf
W (8181) wifi:Haven't to connect to a suitable AP now!
I (8191) chip[DL]: Attempting to connect WiFi station interface
I (8191) chip[DL]: I (8191) chip[DL]: Posting ESPSystemEvent: Wifi Event with eventId : 43WiFi station state change: NotConnected -> Connecting

W (8201) wifi:Haven't to connect to a suitable AP now!
E (8211) chip[DL]: Failed to get configured network when updating network status: Error ESP32:0x0500300F
I (8211) chip[DL]: I (8221) chip[DL]: Posting ESPSystemEvent: Wifi Event with eventId : 2Done driving station state, nothing else to do...

I (8231) chip[SVR]: Initializing subscription resumption storage...
I (8241) chip[SVR]: Server initializing...
I (8241) chip[TS]: Last Known Good Time: 2023-10-14T01:16:48
I (8251) chip[DMG]: AccessControl: initializing
I (8251) chip[DMG]: Examples::AccessControlDelegate::Init
I (8261) chip[DMG]: AccessControl: setting
I (8261) chip[DMG]: DefaultAclStorage: initializing
I (8261) chip[DMG]: DefaultAclStorage: 0 entries loaded
I (8271) chip[SVR]: WARNING: mTestEventTriggerDelegate is null
I (8331) chip[ZCL]: Using ZAP configuration...
I (8331) esp_matter_cluster: Cluster plugin init common callback
I (8331) chip[DMG]: AccessControlCluster: initializing
I (8341) chip[ZCL]: WRITE ERR: ep 0 clus 0x0000_0030 attr 0x0000_0000 not supported
I (8341) chip[ZCL]: Initiating Admin Commissioning cluster.
I (8351) chip[DIS]: Updating services using commissioning mode 1
I (8351) chip[DIS]: CHIP minimal mDNS started advertising.
I (8361) chip[DIS]: Advertise commission parameter vendorID=65521 productID=32768 discriminator=0639/02 cm=1 cp=0
I (8371) chip[DIS]: CHIP minimal mDNS configured as 'Commissionable node device'; instance name: 7DCCF4E3ADB35BC9.
I (8381) chip[DIS]: mDNS service published: _matterc._udp
I (8391) chip[IN]: CASE Server enabling CASE session setups
I (8391) chip[SVR]: Joining Multicast groups
I (8391) chip[SVR]: Server Listening...
I (8401) data_model: Dynamic endpoint 0 added
I (8401) esp_matter_attribute: ********** R : Endpoint 0x0001's Cluster 0x00000003's Attribute 0x00000001 is 1 **********
I (8411) esp_matter_attribute: ********** R : Endpoint 0x0001's Cluster 0x00000004's Attribute 0x00000000 is 128 **********
I (8421) esp_matter_attribute: ********** R : Endpoint 0x0001's Cluster 0x00000004's Attribute 0x0000FFFC is 1 **********
I (8431) esp_matter_attribute: ********** R : Endpoint 0x0001's Cluster 0x00000006's Attribute 0x0000FFFC is 1 **********
I (8441) esp_matter_attribute: ********** R : Endpoint 0x0001's Cluster 0x00000006's Attribute 0x00004003 is null **********
I (8461) esp_matter_attribute: ********** R : Endpoint 0x0001's Cluster 0x00000006's Attribute 0x00000000 is 1 **********
I (8471) esp_matter_attribute: ********** R : Endpoint 0x0001's Cluster 0x00000006's Attribute 0x00000000 is 1 **********
I (8481) chip[ZCL]: Endpoint 1 On/off already set to new value
I (8481) data_model: Dynamic endpoint 1 added
I (8491) esp_matter_attribute: ********** R : Endpoint 0x0002's Cluster 0x00000003's Attribute 0x00000001 is 2 **********
I (8501) data_model: Dynamic endpoint 2 added
I (8501) chip[DL]: WIFI_EVENT_STA_START
W (8511) wifi:Haven't to connect to a suitable AP nhip[DL]: esp_wifi_connect() failed: ESP_ERR_WIFI_CONN
I (8531) chip[DL]: Configuring CHIPoBLE advertising (interval 25 ms, connectable)
I (8531) NimBLE: GAP procedure initiated: advertise;
I (8531) NimBLE: disc_mode=2
I (8541) NimBLE:  adv_channel_map=0 own_addr_type=1 adv_filter_policy=0 adv_itvl_min=40 adv_itvl_max=40
I (8541) NimBLE:

I (8551) chip[DL]: CHIPoBLE advertising started
I (8551) app_main: Commissioning window opened
I (8571) app_main: Not commissioned yet; deferring temperature updates until pairing completes
                                                                                                                                                                             )
> E (10401) chip[DL]: Long dispatch time: 1851 ms, for event type 53250
I (12661) wifi:new:<1,0>, old:<1,0>, ap:<255,255>, sta:<1,0>, prof:1, snd_ch_cfg:0x0
I (12671) wifi:state: init -> auth (0xb0)
I (12951) wifi:state: auth -> assoc (0x0)
I (12961) wifi:state: assoc -> run (0x10)
I (12971) wifi:connected with CyberQuest, aid = 1, channel 1, BW20, bssid = 94:83:c4:27:eb:1b
I (12971) wifi:security: WPA2-PSK, phy: bgn, rssi: -47
I (12981) wifi:pm start, type: 1

I (12981) wifi:dp: 1, bi: 102400, li: 3, scale listen interval from 307200 us to 307200 us
I (12991) chip[DL]: Posting ESPSystemEvent: Wifi Event with eventId : 4
I (12991) chip[DL]: WIFI_EVENT_STA_CONNECTED
I (13001) chip[DL]: WiFi station state change: Connecting -> Connecting_Succeeded
I (13011) chip[DL]: WiFi station state change: Connecting_Succeeded -> Connected
I (13011) chip[DL]: WiFi station interface connected
I (13021) chip[DL]: Done driving station state, nothing else to do...
I (13021) chip[DL]: Updating advertising data
I (13031) chip[DL]: Configuring CHIPoBLE advertising (interval 25 ms, connectable)
I (13041) chip[DL]: Device already advertising, stop active advertisement and restart
I (13041) NimBLE: GAP procedure initiated: stop advertising.

I (13051) NimBLE: GAP procedure initiated: advertise;
I (13061) NimBLE: disc_mode=2
I (13061) NimBLE:  adv_channel_map=0 own_addr_type=1 adv_filter_policy=0 adv_itvl_min=40 adv_itvl_max=40
I (13061) wifi:I (13071) NimBLE:

dp: 2, bi: 102400, li: 4, scale listen interval from 307200 us to 409600 us
I (13071) wifi:AP's beacon interval = 102400 us, DTIM period = 2
I (13491) wifi:<ba-add>idx:0 (ifx:0, 94:83:c4:27:eb:1b), tid:7, ssn:0, winSize:64
I (14151) chip[DL]: Posting ESPSystemEvent: IP Event with eventId : 3
I (14151) chip[DL]: IP_EVENT_GOT_IP6
I (14151) chip[DL]: IPv6 addr available. Ready on WIFI_STA_DEF interface: fe80:0000:0000:0000:d6d4:daff:fe5c:c3fc
I (14161) app_main: Interface IP Address changed
I (14171) chip[DIS]: Updating services using commissioning mode 1
I (14171) chip[DIS]: CHIP minimal mDNS started advertising.
I (14191) chip[DIS]: Advertise commission parameter vendorID=65521 productID=32768 discriminator=0639/02 cm=1 cp=0
I (14201) chip[DIS]: CHIP minimal mDNS configured as 'Commissionable node device'; instance name: 7DCCF4E3ADB35BC9.
I (14211) chip[DIS]: mDNS service published: _matterc._udp
I (14211) chip[SVR]: Server initialization complete
I (14211) chip[DIS]: Updating services using commissioning mode 1
I (14231) chip[DIS]: CHIP minimal mDNS started advertising.
I (14241) chip[DIS]: Advertise commission parameter vendorID=65521 productID=32768 discriminator=0639/02 cm=1 cp=0
I (14241) chip[DIS]: CHIP minimal mDNS configured as 'Commissionable node device'; instance name: 7DCCF4E3ADB35BC9.
I (14261) chip[DIS]: mDNS service published: _matterc._udp
I (14261) chip[IM]: No subscriptions to resume
I (14501) esp_netif_handlers: sta ip: 192.168.8.195, mask: 255.255.255.0, gw: 192.168.8.1
I (14501) chip[DL]: Posting ESPSystemEvent: IP Event with eventId : 0
I (14501) chip[DL]: IP_EVENT_STA_GOT_IP
I (14511) chip[DL]: IPv4 address changed on WiFi station interface: 192.168.8.195/255.255.255.0 gateway 192.168.8.1
I (14531) chip[DL]: IPv4 Internet connectivity ESTABLISHED
I (14531) app_main: Interface IP Address changed
I (14531) chip[DIS]: Updating services using commissioning mode 1
I (14541) chip[DIS]: CHIP minimal mDNS started advertising.
I (14561) chip[DIS]: Advertise commission parameter vendorID=65521 productID=32768 discriminator=0639/02 cm=1 cp=0
I (14561) chip[DIS]: CHIP minimal mDNS configured as 'Commissionable node device'; instance name: 7DCCF4E3ADB35BC9.
I (14581) chip[DIS]: mDNS service published: _matterc._udp
I (16151) wifi:<ba-add>idx:1 (ifx:0, 94:83:c4:27:eb:1b), tid:0, ssn:0, winSize:64
I (16151) ROUTE_HOOK: Received RIO
I (16161) ROUTE_HOOK: prefix FD66:E878:FC4E:: lifetime 5400
I (18151) chip[DL]: Posting ESPSystemEvent: IP Event with eventId : 3
I (18151) chip[DL]: IP_EVENT_GOT_IP6
I (18151) chip[DL]: IPv6 addr available. Ready on WIFI_STA_DEF interface: fd66:e878:fc4e:0000:d6d4:daff:fe5c:c3fc
I (18161) ROUTE_HOOK: Hook already installed on netif, skip...
I (18161) app_main: Interface IP Address changed
I (18181) chip[DIS]: Updating services using commissioning mode 1
I (18181) chip[DIS]: CHIP minimal mDNS started advertising.
I (18201) chip[DIS]: Advertise commission parameter vendorID=65521 productID=32768 discriminator=0639/02 cm=1 cp=0
I (18201) chip[DIS]: CHIP minimal mDNS configured as 'Commissionable node device'; instance name: 7DCCF4E3ADB35BC9.
I (18221) chip[DIS]: mDNS service published: _matterc._udp
I (38391) NimBLE:

licy=0 adv_itvl_min=800 adv_itvE(38 advertising (interval 500 ms, connectable)
I (38361) chip[DL]: Device already advertising, stop active advertisement and restart
I (38371) NimBLE: GAP procedure initiated: stop advertising.

I (38381) NimBLE: GAP procedure initiated: advertise;
l_max=800
I (38391) NimBLE:


I (84471) app_main: Updating temperature to ASCII 'C' -> value: 6700 (67.00°C)
I (85471) app_main: Updating temperature to ASCII 'Q' -> value: 8100 (81.00°C)
I (86471) app_main: Updating temperature to ASCII '2' -> value: 5000 (50.00°C)
I (87471) app_main: Updating temperature to ASCII '5' -> value: 5300 (53.00°C)
I (88471) app_main: Updating temperature to ASCII '{' -> value: 12300 (123.00°C)
I (89471) app_main: Updating temperature to ASCII 't' -> value: 11600 (116.00°C)
I (90471) app_main: Updating temperature to ASCII '3' -> value: 5100 (51.00°C)
I (91471) app_main: Updating temperature to ASCII 'm' -> value: 10900 (109.00°C)
I (92471) app_main: Updating temperature to ASCII 'p' -> value: 11200 (112.00°C)
I (93471) app_main: Updating temperature to ASCII '3' -> value: 5100 (51.00°C)
I (94471) app_main: Updating temperature to ASCII 'r' -> value: 11400 (114.00°C)
I (95471) app_main: Updating temperature to ASCII '4' -> value: 5200 (52.00°C)
I (96471) app_main: Updating temperature to ASCII 't' -> value: 11600 (116.00°C)
I (97471) app_main: Updating temperature to ASCII 'u' -> value: 11700 (117.00°C)
I (98471) app_main: Updating temperature to ASCII 'r' -> value: 11400 (114.00°C)
I (99471) app_main: Updating temperature to ASCII '3' -> value: 5100 (51.00°C)
I (100471) app_main: Updating temperature to ASCII '_' -> value: 9500 (95.00°C)
I (101471) app_main: Updating temperature to ASCII '1' -> value: 4900 (49.00°C)
I (102471) app_main: Updating temperature to ASCII 's' -> value: 11500 (115.00°C)
I (103471) app_main: Updating temperature to ASCII '_' -> value: 9500 (95.00°C)
I (104471) app_main: Updating temperature to ASCII 't' -> value: 11600 (116.00°C)
I (105471) app_main: Updating temperature to ASCII 'h' -> value: 10400 (104.00°C)
I (106471) app_main: Updating temperature to ASCII '3' -> value: 5100 (51.00°C)
I (107471) app_main: Updating temperature to ASCII '_' -> value: 9500 (95.00°C)
I (108471) app_main: Updating temperature to ASCII 'k' -> value: 10700 (107.00°C)
I (109471) app_main: Updating temperature to ASCII '3' -> value: 5100 (51.00°C)
I (110471) app_main: Updating temperature to ASCII 'y' -> value: 12100 (121.00°C)
I (111471) app_main: Updating temperature to ASCII '}' -> value: 12500 (125.00°C)
```

Flag: `CQ25{t3mp3r4tur3_1s_th3_k3y}`