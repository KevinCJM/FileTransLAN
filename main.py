# -*- encoding: utf-8 -*-
"""
@File: main.py
@Modify Time: 2025/5/7 16:23       
@Author: Kevin-Chen
@Descriptions: 局域网文件传输工具 (在两台运行本程序的电脑之间端对端传输各类文件)
"""
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter import PhotoImage
import tkinter as tk
import socket
import threading
import os
import queue
import json
import zipfile
import tempfile


class SimpleFileTransfer:
    def __init__(self, root):
        self.root = root
        self.root.title("简易文件传输工具")
        self.root.geometry("700x550")

        # 网络设置
        self.local_ip = self._get_local_ip()
        self.transfer_port = 50001

        # IP地址簿管理
        self.saved_ips = {}  # 格式: {ip: nickname}
        self.load_saved_ips()

        # 消息队列
        self.message_queue = queue.Queue()

        # GUI初始化
        self.create_widgets()

        # 传输状态
        self.transfer_socket = None
        self.stop_event = threading.Event()

        # 开始处理消息队列
        self.process_queue()

    def process_queue(self):
        """处理消息队列中的GUI更新请求"""
        try:
            while True:
                task = self.message_queue.get_nowait()
                if isinstance(task, tuple):
                    func, args, kwargs = task
                    func(*args, **kwargs)
                else:
                    task()
        except queue.Empty:
            pass
        self.root.after(100, self.process_queue)

    def queue_messagebox(self, func, title, message):
        """将消息框调用放入队列"""
        self.message_queue.put((func, (title, message), {}))

    def queue_gui_update(self, func, *args, **kwargs):
        """将GUI更新放入队列"""
        self.message_queue.put((func, args, kwargs))

    def _get_local_ip(self):
        """获取本机IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def load_saved_ips(self):
        """加载保存的IP地址"""
        try:
            with open('saved_ips.json', 'r') as f:
                self.saved_ips = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.saved_ips = {}

    def save_saved_ips(self):
        """保存IP地址到文件"""
        with open('saved_ips.json', 'w') as f:
            json.dump(self.saved_ips, f, indent=4)

    def create_widgets(self):
        """创建主界面组件"""
        # 顶部信息栏
        info_frame = ttk.Frame(self.root, padding="10")
        info_frame.pack(fill=tk.X)
        ttk.Label(info_frame, text=f"本机IP: {self.local_ip}").pack(side=tk.LEFT)

        # 模式选择
        mode_frame = ttk.LabelFrame(self.root, text="传输模式", padding="10")
        mode_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(mode_frame, text="发送文件", command=self.setup_sender).pack(side=tk.LEFT, padx=5)
        ttk.Button(mode_frame, text="接收文件", command=self.setup_receiver).pack(side=tk.LEFT, padx=5)

        # 主界面区域
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN).pack(fill=tk.X, side=tk.BOTTOM)

        # 默认显示提示
        ttk.Label(self.main_frame, text="请选择传输模式").pack(pady=50)

    def clear_main_frame(self):
        """清空主界面区域"""
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def setup_sender(self):
        """初始化发送界面"""
        self.clear_main_frame()
        self.stop_event.set()

        container = ttk.Frame(self.main_frame)
        container.pack(fill=tk.BOTH, expand=True)

        # 顶部控制栏
        top_frame = ttk.Frame(container)
        top_frame.pack(fill=tk.X, pady=5)

        # IP输入区域
        ip_frame = ttk.Frame(top_frame)
        ip_frame.pack(side=tk.LEFT)

        ttk.Label(ip_frame, text="接收方IP:").pack(side=tk.LEFT)
        self.target_ip_combobox = ttk.Combobox(ip_frame, width=25)
        self.target_ip_combobox.pack(side=tk.LEFT, padx=5)
        self.update_ip_combobox()

        # 组合框选择事件
        def on_select(event):
            selected = self.target_ip_combobox.get()
            if ' - ' in selected:
                nickname, ip = selected.split(' - ', 1)
                self.target_ip_combobox.set(ip)

        self.target_ip_combobox.bind("<<ComboboxSelected>>", on_select)

        # IP管理按钮
        btn_frame = ttk.Frame(ip_frame)
        btn_frame.pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="+", width=2, command=self.add_current_ip).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="管理", command=self.manage_ips).pack(side=tk.LEFT)

        # 文件操作按钮
        ttk.Button(top_frame, text="选择文件", command=self.select_files).pack(side=tk.LEFT, padx=10)
        self.send_btn = ttk.Button(top_frame, text="开始发送", command=self.start_sending, state=tk.DISABLED)
        self.send_btn.pack(side=tk.LEFT)

        # 文件列表
        list_frame = ttk.LabelFrame(container, text="已选文件", padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.file_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scrollbar.set,
            selectmode=tk.EXTENDED,
            height=8
        )
        self.file_listbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.file_listbox.yview)

        # 进度显示
        progress_frame = ttk.Frame(container)
        progress_frame.pack(fill=tk.X, pady=5)

        self.current_file_var = tk.StringVar()
        ttk.Label(progress_frame, textvariable=self.current_file_var).pack(anchor=tk.W)

        self.progress = ttk.Progressbar(
            progress_frame,
            orient=tk.HORIZONTAL,
            length=300,
            mode='determinate'
        )
        self.progress.pack(fill=tk.X, pady=5)

        self.queue_gui_update(self.status_var.set, "就绪 - 发送模式")

    def setup_receiver(self):
        """初始化接收界面"""
        self.clear_main_frame()
        self.stop_event.clear()

        # 永久等待提示
        self.waiting_label = ttk.Label(self.main_frame, text="等待接收文件...", font=('Arial', 12))
        self.waiting_label.pack(pady=30)

        # 当前文件提示（临时显示）
        self.current_file_var = tk.StringVar()
        self.current_label = ttk.Label(self.main_frame, textvariable=self.current_file_var)
        self.current_label.pack(pady=5)

        # 进度条
        self.progress = ttk.Progressbar(
            self.main_frame,
            orient=tk.HORIZONTAL,
            length=300,
            mode='determinate'
        )
        self.progress.pack(fill=tk.X, pady=10)

        threading.Thread(target=self.start_receiving, daemon=True).start()
        self.queue_gui_update(self.status_var.set, f"监听中 - 端口 {self.transfer_port}")

    def update_ip_combobox(self):
        """更新IP下拉列表"""
        values = [f"{nickname} - {ip}" for ip, nickname in self.saved_ips.items()]
        self.target_ip_combobox['values'] = values

    def add_current_ip(self):
        """添加当前输入的IP到地址簿"""
        ip = self.target_ip_combobox.get().strip()
        if not ip:
            self.queue_messagebox(messagebox.showwarning, "警告", "请输入有效的IP地址")
            return

        nickname = simpledialog.askstring("设置昵称", "请输入该IP的昵称:", parent=self.root)
        if nickname:
            self.saved_ips[ip] = nickname
            self.save_saved_ips()
            self.update_ip_combobox()

    def manage_ips(self):
        """IP地址管理窗口"""
        manage_win = tk.Toplevel(self.root)
        manage_win.title("IP地址管理")
        manage_win.geometry("400x300")

        # Treeview组件
        tree = ttk.Treeview(manage_win, columns=('ip', 'nickname'), show='headings')
        tree.heading('ip', text='IP地址')
        tree.heading('nickname', text='昵称')
        tree.column('ip', width=150)
        tree.column('nickname', width=150)
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 填充数据
        for ip, nickname in self.saved_ips.items():
            tree.insert('', tk.END, values=(ip, nickname))

        # 按钮面板
        btn_frame = ttk.Frame(manage_win)
        btn_frame.pack(pady=5)

        def edit_entry():
            selected = tree.selection()
            if selected:
                item = tree.item(selected[0])
                old_ip, old_nick = item['values']

                edit_win = tk.Toplevel(manage_win)
                edit_win.title("编辑条目")

                ttk.Label(edit_win, text="IP地址:").grid(row=0, column=0, padx=5, pady=5)
                ip_entry = ttk.Entry(edit_win)
                ip_entry.insert(0, old_ip)
                ip_entry.grid(row=0, column=1, padx=5, pady=5)

                ttk.Label(edit_win, text="昵称:").grid(row=1, column=0, padx=5, pady=5)
                nick_entry = ttk.Entry(edit_win)
                nick_entry.insert(0, old_nick)
                nick_entry.grid(row=1, column=1, padx=5, pady=5)

                def save_changes():
                    new_ip = ip_entry.get().strip()
                    new_nick = nick_entry.get().strip()
                    if not new_ip or not new_nick:
                        messagebox.showwarning("错误", "所有字段必须填写")
                        return

                    if new_ip != old_ip and new_ip in self.saved_ips:
                        messagebox.showwarning("错误", "该IP已存在")
                        return

                    del self.saved_ips[old_ip]
                    self.saved_ips[new_ip] = new_nick
                    self.save_saved_ips()
                    tree.item(selected[0], values=(new_ip, new_nick))
                    edit_win.destroy()
                    self.update_ip_combobox()

                ttk.Button(edit_win, text="保存", command=save_changes).grid(row=2, columnspan=2, pady=5)

        ttk.Button(btn_frame, text="编辑", command=edit_entry).pack(side=tk.LEFT, padx=5)

        def delete_entry():
            selected = tree.selection()
            if selected:
                ip = tree.item(selected[0])['values'][0]
                if messagebox.askyesno("确认", f"确定删除 {ip} 吗？"):
                    del self.saved_ips[ip]
                    self.save_saved_ips()
                    tree.delete(selected[0])
                    self.update_ip_combobox()

        ttk.Button(btn_frame, text="删除", command=delete_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="关闭", command=manage_win.destroy).pack(side=tk.LEFT, padx=5)

    def select_files(self):
        """选择要发送的文件"""
        files = filedialog.askopenfilenames()
        if files:
            self.selected_files = files
            self.file_listbox.delete(0, tk.END)
            for f in files:
                name = os.path.basename(f)
                size = os.path.getsize(f) // 1024
                self.file_listbox.insert(tk.END, f"{name} ({size} KB)")
            self.send_btn.config(state=tk.NORMAL)

    def start_sending(self):
        """启动发送线程"""
        ip = self.target_ip_combobox.get().split(' - ')[-1].strip()
        if not ip:
            self.queue_messagebox(messagebox.showwarning, "错误", "请选择或输入有效的IP地址")
            return

        if not hasattr(self, 'selected_files'):
            self.queue_messagebox(messagebox.showwarning, "错误", "请先选择要发送的文件")
            return

        self.send_btn.config(state=tk.DISABLED)
        threading.Thread(
            target=self.send_files,
            args=(ip, self.selected_files),
            daemon=True
        ).start()

    def send_files(self, target_ip, files):
        """发送文件的核心逻辑（包含压缩功能）"""
        zip_path = None  # 用于跟踪临时压缩文件
        try:
            # 压缩处理逻辑
            if len(files) > 1:
                # 创建临时压缩文件
                temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
                zip_path = temp_zip.name
                temp_zip.close()

                with zipfile.ZipFile(zip_path, 'w') as zipf:
                    for file in files:
                        zipf.write(file, arcname=os.path.basename(file))

                files_to_send = [zip_path]
                is_zip = True
            else:
                files_to_send = files
                is_zip = False

            total = len(files_to_send)
            self.queue_gui_update(self.status_var.set, f"正在连接 {target_ip}...")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, self.transfer_port))

            # 发送文件数量
            sock.sendall(str(total).encode())
            if sock.recv(1024).decode() != "READY":
                raise ConnectionError("接收方未准备就绪")

            # 发送文件（可能为压缩包）
            for idx, filepath in enumerate(files_to_send, 1):
                filename = os.path.basename(filepath)
                filesize = os.path.getsize(filepath)

                # 更新界面
                self.queue_gui_update(
                    self.current_file_var.set,
                    f"正在发送 ({idx}/{total}): {filename}"
                )

                # 发送增强的元数据
                metadata = json.dumps({
                    "filename": filename,
                    "filesize": filesize,
                    "is_zip": is_zip,
                    "original_count": len(files) if is_zip else 1
                }).encode()
                sock.sendall(len(metadata).to_bytes(4, 'big'))
                sock.sendall(metadata)

                if sock.recv(1024).decode() != "METADATA_OK":
                    raise ConnectionError("元数据接收失败")

                # 发送文件内容
                sent = 0
                with open(filepath, 'rb') as f:
                    while sent < filesize:
                        chunk = f.read(1024 * 1024)
                        sock.sendall(chunk)
                        sent += len(chunk)
                        progress = int(sent / filesize * 100)
                        self.queue_gui_update(self.progress.configure, value=progress)

                if sock.recv(1024).decode() != "FILE_OK":
                    raise ConnectionError("文件接收失败")

            # 发送完成处理
            sock.close()
            self.queue_gui_update(self.status_var.set, "发送完成")
            self.queue_messagebox(
                messagebox.showinfo,
                "完成",
                f"成功发送 {len(files)} 个文件" + ("（已压缩）" if is_zip else "")
            )

            # 提示保存新IP
            if target_ip not in self.saved_ips:
                self.queue_gui_update(self.prompt_save_ip, target_ip)

        except Exception as e:
            self.queue_gui_update(self.status_var.set, f"发送错误: {str(e)}")
            self.queue_messagebox(messagebox.showerror, "错误", f"发送失败: {str(e)}")
        finally:
            # 清理临时压缩文件
            if zip_path and os.path.exists(zip_path):
                try:
                    os.unlink(zip_path)
                except Exception as e:
                    print(f"删除临时文件失败: {str(e)}")
            self.queue_gui_update(self.progress.configure, value=0)
            self.queue_gui_update(self.current_file_var.set, "")
            self.queue_gui_update(self.send_btn.config, state=tk.NORMAL)

    def prompt_save_ip(self, ip):
        """提示保存新IP地址"""
        if messagebox.askyesno("保存地址", f"是否保存新地址 {ip}？"):
            nickname = simpledialog.askstring("设置昵称", "请输入昵称:")
            if nickname:
                self.saved_ips[ip] = nickname
                self.save_saved_ips()
                self.update_ip_combobox()

    def start_receiving(self):
        """启动接收监听（包含解压功能）"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', self.transfer_port))
            sock.listen(1)

            while not self.stop_event.is_set():
                # 重置界面状态
                self.queue_gui_update(self.waiting_label.pack)
                self.queue_gui_update(self.current_file_var.set, "")
                self.queue_gui_update(self.progress.configure, value=0)

                sock.settimeout(1)
                try:
                    conn, addr = sock.accept()
                except socket.timeout:
                    continue

                self.queue_gui_update(self.status_var.set, f"来自 {addr[0]} 的连接")
                save_dir = filedialog.askdirectory()
                if not save_dir:
                    conn.close()
                    continue

                try:
                    total = int(conn.recv(1024).decode())
                    conn.sendall(b"READY")

                    for _ in range(total):
                        # 接收元数据
                        meta_len = int.from_bytes(conn.recv(4), 'big')
                        metadata = json.loads(conn.recv(meta_len).decode())
                        conn.sendall(b"METADATA_OK")

                        # 准备接收文件
                        filename = metadata["filename"]
                        filesize = metadata["filesize"]
                        is_zip = metadata.get("is_zip", False)
                        original_count = metadata.get("original_count", 1)
                        save_path = os.path.join(save_dir, filename)

                        self.queue_gui_update(
                            self.current_file_var.set,
                            f"正在接收: {filename}"
                        )

                        # 接收文件内容
                        received = 0
                        with open(save_path, 'wb') as f:
                            while received < filesize:
                                chunk = conn.recv(4096)
                                if not chunk:
                                    break
                                f.write(chunk)
                                received += len(chunk)
                                progress = int(received / filesize * 100)
                                self.queue_gui_update(self.progress.configure, value=progress)

                        conn.sendall(b"FILE_OK")

                        # 解压处理逻辑
                        if is_zip:
                            try:
                                with zipfile.ZipFile(save_path, 'r') as zip_ref:
                                    zip_ref.extractall(save_dir)
                                os.remove(save_path)
                            except Exception as e:
                                self.queue_gui_update(
                                    self.status_var.set,
                                    f"解压失败: {str(e)}"
                                )

                    # 接收完成后重置界面
                    self.queue_gui_update(self.current_file_var.set, "")
                    self.queue_gui_update(self.progress.configure, value=0)
                    self.queue_gui_update(self.waiting_label.pack)
                    self.queue_messagebox(
                        messagebox.showinfo,
                        "完成",
                        f"文件已保存到:\n{save_dir}" + ("（已自动解压）" if is_zip else "")
                    )

                except Exception as e:
                    self.queue_gui_update(self.status_var.set, f"接收错误: {str(e)}")
                finally:
                    conn.close()
                    # 强制恢复等待界面
                    self.queue_gui_update(self.waiting_label.pack)
                    self.queue_gui_update(self.current_file_var.set, "")
                    self.queue_gui_update(self.progress.configure, value=0)

        except Exception as e:
            self.queue_gui_update(self.status_var.set, f"监听错误: {str(e)}")
        finally:
            sock.close()
            # 最终状态重置
            self.queue_gui_update(self.current_file_var.set, "")
            self.queue_gui_update(self.progress.configure, value=0)
            self.queue_gui_update(self.waiting_label.pack)


if __name__ == "__main__":
    root = tk.Tk()

    # 设置自定义图标
    icon_path = "logo.png"  # 你上传的图标文件
    icon_image = PhotoImage(file=icon_path)
    root.iconphoto(True, icon_image)

    app = SimpleFileTransfer(root)
    root.mainloop()
