#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from scanner import PortScanner

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

# 回调函数用于命令行输出
def progress_callback(message):
    """进度回调函数"""
    print(message)

def result_callback(port, status):
    """结果回调函数"""
    print(f"端口 {port}: {status}")

def summary_callback(message):
    """摘要回调函数"""
    print(f"\n{message}")

def main():
    args = parse_arguments()
    
    # 验证线程数范围
    if args.threads < 1 or args.threads > 500:
        print("错误: 线程数必须在1-500之间")
        sys.exit(1)
    
    # 创建扫描器实例
    scanner = PortScanner()
    
    # 确定扫描类型
    scan_type = "TCP"  # 默认为TCP Connect扫描
    if args.sS:
        scan_type = "SYN"
    elif args.sU:
        scan_type = "UDP"
    
    # 解析端口范围
    try:
        ports = scanner.parse_port_range(args.ports)
    except Exception as e:
        print(f"端口范围解析错误: {e}")
        sys.exit(1)
    
    # 确定目标
    targets = []
    if args.input_file:
        try:
            targets = scanner.load_targets_from_file(args.input_file)
        except Exception as e:
            print(f"读取输入文件时出错: {e}")
            sys.exit(1)
    elif args.target:
        targets = [args.target]
    else:
        print("错误: 未指定目标。使用 -h 查看帮助信息。")
        sys.exit(1)
    
    print(f"开始扫描 {len(targets)} 个目标，{len(ports)} 个端口（使用 {args.threads} 个线程）")
    
    # 执行扫描
    try:
        scan_results = scanner.scan_multiple_targets(
            targets, ports, scan_type, args.threads,
            progress_callback, result_callback, summary_callback
        )
    except KeyboardInterrupt:
        print("\n\n扫描被用户中断")
        scanner.stop_scan()
        sys.exit(0)
    except Exception as e:
        print(f"扫描过程中发生错误: {e}")
        sys.exit(1)
    
    # 输出结果到文件
    if args.output_file:
        try:
            scanner.save_results_to_file(scan_results, args.output_file)
            print(f"\n结果已保存到文件: {args.output_file}")
        except Exception as e:
            print(f"写入输出文件时出错: {e}")
    
    print(f"\n扫描完成！")
    total_open_ports = sum(len(ports) for ports in scan_results.values())
    print(f"共发现 {total_open_ports} 个开放端口")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n扫描被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"发生错误: {e}")
        sys.exit(1) 