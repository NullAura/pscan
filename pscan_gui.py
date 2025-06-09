#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import queue
import time
from scanner import PortScanner

# 设置CustomTkinter主题
ctk.set_appearance_mode("dark")  # 或 "light"
ctk.set_default_color_theme("blue")  # 或 "green", "dark-blue"

class PortScannerGUI:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.title("端口扫描工具 - GUI版本")
        self.window.geometry("900x700")
        
        # 创建扫描器实例
        self.scanner = PortScanner()
        
        # GUI控制变量
        self.scan_thread = None
        self.result_queue = queue.Queue()
        
        self.setup_ui()
        
        # 启动结果更新线程
        self.window.after(100, self.check_result_queue)
    
    def setup_ui(self):
        # 主框架
        main_frame = ctk.CTkFrame(self.window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # 标题
        title_label = ctk.CTkLabel(main_frame, text="端口扫描工具", font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(pady=(20, 30))
        
        # 目标设置框架
        target_frame = ctk.CTkFrame(main_frame)
        target_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        target_label = ctk.CTkLabel(target_frame, text="扫描目标", font=ctk.CTkFont(size=16, weight="bold"))
        target_label.pack(pady=(15, 5))
        
        # 目标输入
        self.target_entry = ctk.CTkEntry(target_frame, placeholder_text="输入IP地址或域名，如: 192.168.1.1 或 google.com", width=400)
        self.target_entry.pack(pady=(0, 10))
        
        # 文件选择按钮
        file_frame = ctk.CTkFrame(target_frame)
        file_frame.pack(pady=(0, 15))
        
        self.file_button = ctk.CTkButton(file_frame, text="从文件选择目标", command=self.load_targets_from_file)
        self.file_button.pack(side="left", padx=(0, 10))
        
        self.file_label = ctk.CTkLabel(file_frame, text="未选择文件")
        self.file_label.pack(side="left")
        
        # 扫描设置框架
        settings_frame = ctk.CTkFrame(main_frame)
        settings_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        settings_label = ctk.CTkLabel(settings_frame, text="扫描设置", font=ctk.CTkFont(size=16, weight="bold"))
        settings_label.pack(pady=(15, 10))
        
        # 端口设置
        port_frame = ctk.CTkFrame(settings_frame)
        port_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        port_label = ctk.CTkLabel(port_frame, text="端口范围:")
        port_label.pack(side="left", padx=(10, 5))
        
        self.port_entry = ctk.CTkEntry(port_frame, placeholder_text="例如: 80,443 或 1-1000", width=200)
        self.port_entry.pack(side="left", padx=(0, 10))
        
        common_ports_button = ctk.CTkButton(port_frame, text="常用端口", command=self.set_common_ports, width=100)
        common_ports_button.pack(side="left")
        
        # 扫描类型
        scan_type_frame = ctk.CTkFrame(settings_frame)
        scan_type_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        scan_type_label = ctk.CTkLabel(scan_type_frame, text="扫描类型:")
        scan_type_label.pack(side="left", padx=(10, 10))
        
        self.scan_type_var = ctk.StringVar(value="TCP")
        
        tcp_radio = ctk.CTkRadioButton(scan_type_frame, text="TCP Connect", variable=self.scan_type_var, value="TCP")
        tcp_radio.pack(side="left", padx=(0, 10))
        
        syn_radio = ctk.CTkRadioButton(scan_type_frame, text="TCP SYN (需要管理员权限)", variable=self.scan_type_var, value="SYN")
        syn_radio.pack(side="left", padx=(0, 10))
        
        udp_radio = ctk.CTkRadioButton(scan_type_frame, text="UDP (需要管理员权限)", variable=self.scan_type_var, value="UDP")
        udp_radio.pack(side="left")
        
        # 线程设置
        thread_frame = ctk.CTkFrame(settings_frame)
        thread_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        thread_label = ctk.CTkLabel(thread_frame, text="线程数:")
        thread_label.pack(side="left", padx=(10, 10))
        
        self.thread_var = ctk.IntVar(value=20)
        thread_slider = ctk.CTkSlider(thread_frame, from_=1, to=200, number_of_steps=199, variable=self.thread_var, width=200)
        thread_slider.pack(side="left", padx=(0, 10))
        
        self.thread_value_label = ctk.CTkLabel(thread_frame, text="20")
        self.thread_value_label.pack(side="left")
        
        thread_slider.configure(command=self.update_thread_label)
        
        # 控制按钮
        control_frame = ctk.CTkFrame(main_frame)
        control_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        button_frame = ctk.CTkFrame(control_frame)
        button_frame.pack(pady=15)
        
        self.scan_button = ctk.CTkButton(button_frame, text="开始扫描", command=self.start_scan, width=120, height=40)
        self.scan_button.pack(side="left", padx=(0, 10))
        
        self.stop_button = ctk.CTkButton(button_frame, text="停止扫描", command=self.stop_scan, width=120, height=40, state="disabled")
        self.stop_button.pack(side="left", padx=(0, 10))
        
        self.save_button = ctk.CTkButton(button_frame, text="保存结果", command=self.save_results, width=120, height=40)
        self.save_button.pack(side="left")
        
        # 进度条
        self.progress_bar = ctk.CTkProgressBar(control_frame, width=400)
        self.progress_bar.pack(pady=(0, 15))
        self.progress_bar.set(0)
        
        # 状态标签
        self.status_label = ctk.CTkLabel(control_frame, text="就绪")
        self.status_label.pack(pady=(0, 15))
        
        # 结果显示
        result_frame = ctk.CTkFrame(main_frame)
        result_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        result_label = ctk.CTkLabel(result_frame, text="扫描结果", font=ctk.CTkFont(size=16, weight="bold"))
        result_label.pack(pady=(15, 10))
        
        # 结果文本框
        self.result_text = ctk.CTkTextbox(result_frame, height=200, font=ctk.CTkFont(family="Courier"))
        self.result_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
    
    def update_thread_label(self, value):
        self.thread_value_label.configure(text=str(int(value)))
    
    def set_common_ports(self):
        self.port_entry.delete(0, "end")
        self.port_entry.insert(0, "21,22,23,25,53,80,110,443,993,995,3389")
    
    def load_targets_from_file(self):
        file_path = filedialog.askopenfilename(
            title="选择目标文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            self.file_label.configure(text=file_path.split('/')[-1])
            self.selected_file = file_path
        else:
            self.selected_file = None
    
    # GUI回调函数
    def progress_callback(self, message):
        """进度回调函数"""
        self.result_queue.put(('status', message))
    
    def result_callback(self, port, status):
        """结果回调函数"""
        self.result_queue.put(('result', f"端口 {port}: {status}"))
    
    def scan_worker(self, targets, ports, scan_type, threads):
        """扫描工作函数"""
        try:
            def summary_callback(message):
                self.result_queue.put(('summary', message))
            
            # 使用扫描器执行扫描
            results = self.scanner.scan_multiple_targets(
                targets, ports, scan_type, threads,
                self.progress_callback, self.result_callback, summary_callback
            )
            
            self.result_queue.put(('complete', '扫描完成！'))
            
        except Exception as e:
            self.result_queue.put(('error', f"扫描错误: {str(e)}"))
    
    def start_scan(self):
        # 验证输入
        targets = []
        
        # 获取目标
        if hasattr(self, 'selected_file') and self.selected_file:
            try:
                targets = self.scanner.load_targets_from_file(self.selected_file)
            except Exception as e:
                messagebox.showerror("错误", f"读取文件失败: {e}")
                return
        else:
            target = self.target_entry.get().strip()
            if not target:
                messagebox.showerror("错误", "请输入目标地址或选择目标文件")
                return
            targets = [target]
        
        # 解析端口
        try:
            ports = self.scanner.parse_port_range(self.port_entry.get().strip())
        except Exception as e:
            messagebox.showerror("错误", f"端口范围格式错误: {e}")
            return
        
        # 获取设置
        scan_type = self.scan_type_var.get()
        threads = self.thread_var.get()
        
        # 检查权限
        if scan_type in ["SYN", "UDP"]:
            import os
            if os.geteuid() != 0:  # Linux/Mac
                messagebox.showwarning("权限警告", f"{scan_type}扫描需要管理员权限，可能无法正常工作")
        
        # 开始扫描
        self.scanner.is_scanning = True
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.progress_bar.set(0)
        
        # 启动扫描线程
        self.scan_thread = threading.Thread(
            target=self.scan_worker,
            args=(targets, ports, scan_type, threads)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def stop_scan(self):
        self.scanner.stop_scan()
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_label.configure(text="扫描已停止")
    
    def save_results(self):
        content = self.result_text.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showwarning("警告", "没有结果可保存")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="保存扫描结果",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("成功", f"结果已保存到: {file_path}")
            except Exception as e:
                messagebox.showerror("错误", f"保存失败: {e}")
    
    def check_result_queue(self):
        """检查结果队列并更新界面"""
        try:
            while True:
                msg_type, msg_data = self.result_queue.get_nowait()
                
                if msg_type == 'status':
                    self.status_label.configure(text=msg_data)
                elif msg_type == 'result':
                    self.result_text.insert("end", msg_data + "\n")
                    self.result_text.see("end")
                elif msg_type == 'summary':
                    self.result_text.insert("end", "\n" + msg_data + "\n" + "="*50 + "\n")
                    self.result_text.see("end")
                elif msg_type == 'progress':
                    self.progress_bar.set(msg_data)
                elif msg_type == 'complete':
                    self.status_label.configure(text=msg_data)
                    self.scan_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
                    self.scanner.is_scanning = False
                elif msg_type == 'error':
                    self.status_label.configure(text=msg_data)
                    self.scan_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
                    self.scanner.is_scanning = False
                    
        except queue.Empty:
            pass
        
        # 继续检查队列
        self.window.after(100, self.check_result_queue)
    
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = PortScannerGUI()
    app.run() 