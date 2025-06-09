#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ipaddress
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sr1, IP, TCP, UDP, ICMP

class PortScanner:
    def __init__(self):
        self.is_scanning = False
    
    def parse_port_range(self, port_str):
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
    
    def tcp_syn_scan(self, target, port):
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
    
    def tcp_connect_scan(self, target, port):
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
    
    def udp_scan(self, target, port):
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
    
    def scan_target(self, target, ports, scan_type, threads=20, progress_callback=None, result_callback=None):
        """扫描指定目标的端口
        
        Args:
            target: 目标IP或域名
            ports: 端口列表
            scan_type: 扫描类型 ("SYN", "TCP", "UDP")
            threads: 线程数
            progress_callback: 进度回调函数(current, total)
            result_callback: 结果回调函数(port, status)
        
        Returns:
            list: 开放的端口列表
        """
        if progress_callback:
            progress_callback(f"开始扫描目标: {target}")
        
        open_ports = []
        completed = 0
        total = len(ports)
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # 根据扫描类型选择扫描函数
            if scan_type == "SYN":
                future_to_port = {executor.submit(self.tcp_syn_scan, target, port): port for port in ports}
            elif scan_type == "TCP":
                future_to_port = {executor.submit(self.tcp_connect_scan, target, port): port for port in ports}
            elif scan_type == "UDP":
                future_to_port = {executor.submit(self.udp_scan, target, port): port for port in ports}
            
            for future in future_to_port:
                if not self.is_scanning:
                    break
                    
                port, status = future.result()
                completed += 1
                
                if "开放" in status:
                    open_ports.append(port)
                    if result_callback:
                        result_callback(port, status)
        
        return open_ports
    
    def scan_multiple_targets(self, targets, ports, scan_type, threads=20, 
                            progress_callback=None, result_callback=None, summary_callback=None):
        """扫描多个目标
        
        Args:
            targets: 目标列表
            ports: 端口列表
            scan_type: 扫描类型
            threads: 线程数
            progress_callback: 进度回调函数
            result_callback: 结果回调函数
            summary_callback: 摘要回调函数
        
        Returns:
            dict: {target: [open_ports]}
        """
        self.is_scanning = True
        results = {}
        
        try:
            for i, target in enumerate(targets):
                if not self.is_scanning:
                    break
                
                if progress_callback:
                    progress_callback(f"正在扫描目标 {i+1}/{len(targets)}: {target}")
                
                open_ports = self.scan_target(target, ports, scan_type, threads, 
                                            progress_callback, result_callback)
                results[target] = open_ports
                
                if summary_callback:
                    if open_ports:
                        summary_callback(f"目标 {target} 开放的端口: {', '.join(map(str, open_ports))}")
                    else:
                        summary_callback(f"目标 {target} 没有发现开放的端口")
        
        finally:
            self.is_scanning = False
        
        return results
    
    def stop_scan(self):
        """停止扫描"""
        self.is_scanning = False
    
    def load_targets_from_file(self, file_path):
        """从文件加载目标列表"""
        try:
            with open(file_path, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            return targets
        except Exception as e:
            raise Exception(f"读取文件失败: {e}")
    
    def save_results_to_file(self, results, file_path):
        """将结果保存到文件"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("# 端口扫描结果\n\n")
                for target, open_ports in results.items():
                    f.write(f"## 目标: {target}\n")
                    if open_ports:
                        f.write("开放的端口:\n")
                        for port in open_ports:
                            f.write(f"- {port}\n")
                    else:
                        f.write("无开放端口\n")
                    f.write("\n")
        except Exception as e:
            raise Exception(f"保存文件失败: {e}") 