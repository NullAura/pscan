#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import socket
import sys
import ipaddress
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sr1, IP, TCP, UDP, ICMP

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='端口扫描工具')
    parser.add_argument('target', nargs='?', help='目标IP地址')
    parser.add_argument('-p', dest='ports', help='指定端口范围 (例如: 22,80,443 或 1-1000)')
    parser.add_argument('-sS', action='store_true', help='执行TCP SYN扫描')
    parser.add_argument('-sT', action='store_true', help='执行TCP Connect扫描')
    parser.add_argument('-sU', action='store_true', help='执行UDP扫描')
    parser.add_argument('-iL', dest='input_file', help='从文件读取目标列表')
    parser.add_argument('-oN', dest='output_file', help='将结果写入文件')
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=20, 
                       help='设置并发线程数 (默认: 20, 范围: 1-500)')
    return parser.parse_args()

def parse_port_range(port_str):
    """解析端口范围字符串"""
    ports = []
    if not port_str:
        # 默认扫描常用端口
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    for item in port_str.split(','):
        if '-' in item:
            start, end = map(int, item.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(item))
    return ports

def tcp_syn_scan(target, port):
    """执行TCP SYN扫描"""
    try:
        # 使用scapy发送SYN包
        packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response is None:
            return port, "过滤"
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            # 发送RST包关闭连接
            rst_packet = IP(dst=target)/TCP(dport=port, flags="R")
            sr1(rst_packet, timeout=1, verbose=0)
            return port, "开放"
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST-ACK
            return port, "关闭"
        else:
            return port, "未知"
    except Exception as e:
        return port, f"错误: {str(e)}"

def tcp_connect_scan(target, port):
    """执行TCP Connect扫描"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        s.close()
        
        if result == 0:
            return port, "开放"
        else:
            return port, "关闭"
    except Exception as e:
        return port, f"错误: {str(e)}"

def udp_scan(target, port):
    """执行UDP扫描"""
    try:
        # 发送UDP包
        packet = IP(dst=target)/UDP(dport=port)
        response = sr1(packet, timeout=2, verbose=0)
        
        if response is None:
            return port, "开放|过滤"
        elif response.haslayer(ICMP):
            # ICMP端口不可达表示端口关闭
            if int(response[ICMP].type) == 3 and int(response[ICMP].code) == 3:
                return port, "关闭"
            else:
                return port, "过滤"
        elif response.haslayer(UDP):
            return port, "开放"
        else:
            return port, "未知"
    except Exception as e:
        return port, f"错误: {str(e)}"

def scan_target(target, ports, scan_type, results, threads=20):
    """扫描指定目标的端口"""
    print(f"\n开始扫描目标: {target}（使用 {threads} 个线程）")
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        if scan_type == "SYN":
            future_to_port = {executor.submit(tcp_syn_scan, target, port): port for port in ports}
        elif scan_type == "TCP":
            future_to_port = {executor.submit(tcp_connect_scan, target, port): port for port in ports}
        elif scan_type == "UDP":
            future_to_port = {executor.submit(udp_scan, target, port): port for port in ports}
        
        for future in future_to_port:
            port, status = future.result()
            if "开放" in status:
                open_ports.append(port)
                print(f"端口 {port}: {status}")
    
    results[target] = open_ports
    print(f"\n扫描完成。目标 {target} 开放的端口: {', '.join(map(str, open_ports)) if open_ports else '无'}")

def main():
    args = parse_arguments()
    
    # 验证线程数范围
    if args.threads < 1 or args.threads > 500:
        print("错误: 线程数必须在1-500之间")
        sys.exit(1)
    
    # 确定扫描类型
    scan_type = "TCP"  # 默认为TCP Connect扫描
    if args.sS:
        scan_type = "SYN"
    elif args.sU:
        scan_type = "UDP"
    
    # 解析端口范围
    ports = parse_port_range(args.ports)
    
    # 确定目标
    targets = []
    if args.input_file:
        try:
            with open(args.input_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"读取输入文件时出错: {e}")
            sys.exit(1)
    elif args.target:
        targets = [args.target]
    else:
        print("错误: 未指定目标。使用 -h 查看帮助信息。")
        sys.exit(1)
    
    # 存储结果
    scan_results = {}
    
    # 扫描所有目标
    for target in targets:
        scan_target(target, ports, scan_type, scan_results, args.threads)
    
    # 输出结果到文件
    if args.output_file:
        try:
            with open(args.output_file, 'w') as f:
                f.write("# 端口扫描结果\n\n")
                for target, open_ports in scan_results.items():
                    f.write(f"## 目标: {target}\n")
                    if open_ports:
                        f.write("开放的端口:\n")
                        for port in open_ports:
                            f.write(f"- {port}\n")
                    else:
                        f.write("无开放端口\n")
                    f.write("\n")
            print(f"结果已保存到文件: {args.output_file}")
        except Exception as e:
            print(f"写入输出文件时出错: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n扫描被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"发生错误: {e}")
        sys.exit(1) 