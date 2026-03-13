#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import re


class IptablesGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Iptables GUI Manager")
        self.root.geometry("1000x900")
        
        self.previous_counts = {}
        
        self.create_widgets()
        self.refresh_rules()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        config_frame = ttk.LabelFrame(main_frame, text="Rule Configuration", padding="10")
        config_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        row = 0
        
        ttk.Label(config_frame, text="Protocol:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.protocol_var = tk.StringVar(value="TCP")
        protocol_combo = ttk.Combobox(config_frame, textvariable=self.protocol_var, 
                                      values=["TCP", "UDP"], state="readonly", width=15)
        protocol_combo.grid(row=row, column=1, sticky=tk.W, pady=5)
        protocol_combo.bind("<<ComboboxSelected>>", self.toggle_tcp_flags)
        
        row += 1
        
        self.tcp_flags_frame = ttk.LabelFrame(config_frame, text="TCP Flags", padding="5")
        self.tcp_flags_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.flag_vars = {}
        flags = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]
        for i, flag in enumerate(flags):
            var = tk.BooleanVar()
            self.flag_vars[flag] = var
            ttk.Checkbutton(self.tcp_flags_frame, text=flag, variable=var).grid(
                row=0, column=i, padx=5, pady=2)
        
        row += 1
        
        ttk.Label(config_frame, text="Source IP/CIDR:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.src_ip_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.src_ip_var, width=30).grid(
            row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        
        ttk.Label(config_frame, text="Destination IP:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.dst_ip_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.dst_ip_var, width=30).grid(
            row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        
        ttk.Label(config_frame, text="Source Port:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.src_port_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.src_port_var, width=30).grid(
            row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        
        ttk.Label(config_frame, text="Destination Port:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.dst_port_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.dst_port_var, width=30).grid(
            row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        
        ttk.Label(config_frame, text="Action:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.action_var = tk.StringVar(value="ACCEPT")
        action_combo = ttk.Combobox(config_frame, textvariable=self.action_var,
                                    values=["ACCEPT", "DROP"], state="readonly", width=15)
        action_combo.grid(row=row, column=1, sticky=tk.W, pady=5)
        
        row += 1
        
        ttk.Button(config_frame, text="Add Rule", command=self.add_rule).grid(
            row=row, column=0, columnspan=2, pady=10)
        
        bulk_frame = ttk.LabelFrame(main_frame, text="Bulk IP Operations", padding="10")
        bulk_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        bulk_frame.columnconfigure(0, weight=1)
        bulk_frame.columnconfigure(1, weight=1)
        
        ttk.Label(bulk_frame, text="Whitelist IPs (one per line):").grid(row=0, column=0, sticky=tk.W)
        self.whitelist_text = scrolledtext.ScrolledText(bulk_frame, height=4, width=30)
        self.whitelist_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        ttk.Button(bulk_frame, text="Add Whitelist", 
                  command=lambda: self.bulk_add_ips("ACCEPT")).grid(row=2, column=0, pady=5)
        
        ttk.Label(bulk_frame, text="Blacklist IPs (one per line):").grid(row=0, column=1, sticky=tk.W)
        self.blacklist_text = scrolledtext.ScrolledText(bulk_frame, height=4, width=30)
        self.blacklist_text.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0))
        ttk.Button(bulk_frame, text="Add Blacklist",
                  command=lambda: self.bulk_add_ips("DROP")).grid(row=2, column=1, pady=5)
        
        list_frame = ttk.LabelFrame(main_frame, text="Current INPUT Chain Rules", padding="10")
        list_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        main_frame.rowconfigure(2, weight=1)
        
        columns = ("Line", "Protocol", "Flags", "Source", "Destination",  
                  "SPort", "DPort", "Action", "Packets")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        self.tree.heading("Line", text="Line")
        self.tree.heading("Protocol", text="Proto")
        self.tree.heading("Flags", text="Flags")
        self.tree.heading("Source", text="Source IP")
        self.tree.heading("Destination", text="Dest IP")
        self.tree.heading("SPort", text="SPort")
        self.tree.heading("DPort", text="DPort")
        self.tree.heading("Action", text="Action")
        self.tree.heading("Packets", text="Packets")
        
        self.tree.column("Line", width=50)
        self.tree.column("Protocol", width=60)
        self.tree.column("Flags", width=100)
        self.tree.column("Source", width=120)
        self.tree.column("Destination", width=120)
        self.tree.column("SPort", width=60)
        self.tree.column("DPort", width=60)
        self.tree.column("Action", width=80)
        self.tree.column("Packets", width=80)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        button_frame = ttk.Frame(list_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Refresh", command=self.refresh_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Disable Rule", command=self.disable_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reorder by Usage", command=self.reorder_by_usage).pack(side=tk.LEFT, padx=5)
    
    def toggle_tcp_flags(self, event=None):
        """Show/hide TCP flags based on protocol selection"""
        if self.protocol_var.get() == "TCP":
            self.tcp_flags_frame.grid()
        else:
            self.tcp_flags_frame.grid_remove()
    
    def validate_ip(self, ip_str):
        """Validate IPv4 address with optional CIDR notation"""
        if not ip_str:
            return True
        pattern = r'^\d+\.\d+\.\d+\.\d+(\/\d+)?$'
        return re.match(pattern, ip_str) is not None
    
    def validate_port(self, port_str):
        """Validate port number (1-65535)"""
        if not port_str:
            return True
        try:
            port = int(port_str)
            return 1 <= port <= 65535
        except ValueError:
            return False
    
    def add_rule(self):
        """Add a new iptables rule"""
        protocol = self.protocol_var.get().lower()
        src_ip = self.src_ip_var.get().strip()
        dst_ip = self.dst_ip_var.get().strip()
        src_port = self.src_port_var.get().strip()
        dst_port = self.dst_port_var.get().strip()
        action = self.action_var.get()
        
        # Validation
        if not self.validate_ip(src_ip):
            messagebox.showerror("Validation Error", "Invalid source IP format")
            return
        
        if not self.validate_ip(dst_ip):
            messagebox.showerror("Validation Error", "Invalid destination IP format")
            return
        
        if not self.validate_port(src_port):
            messagebox.showerror("Validation Error", "Invalid source port (must be 1-65535)")
            return
        
        if not self.validate_port(dst_port):
            messagebox.showerror("Validation Error", "Invalid destination port (must be 1-65535)")
            return
        
        cmd = ["iptables", "-I", "INPUT", "1", "-p", protocol]
        
        if protocol == "tcp":
            selected_flags = [flag for flag, var in self.flag_vars.items() if var.get()]
            if selected_flags:
                all_flags = "SYN,ACK,FIN,RST,PSH,URG"
                match_flags = ",".join(selected_flags)
                cmd.extend(["--tcp-flags", all_flags, match_flags])
        
        if src_ip:
            cmd.extend(["-s", src_ip])
        
        if dst_ip:
            cmd.extend(["-d", dst_ip])
        
        if src_port:
            cmd.extend(["--sport", src_port])
        
        if dst_port:
            cmd.extend(["--dport", dst_port])
        
        cmd.extend(["-j", action])
        
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            messagebox.showinfo("Success", "Rule added successfully")
            self.refresh_rules()
            self.clear_inputs()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to add rule:\n{e.stderr}")
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Run with sudo/root privileges.")
    
    def bulk_add_ips(self, action):
        """Add multiple IP addresses as whitelist or blacklist"""
        if action == "ACCEPT":
            text_widget = self.whitelist_text
            action_name = "whitelist"
        else:
            text_widget = self.blacklist_text
            action_name = "blacklist"
        
        ips = text_widget.get("1.0", tk.END).strip().split("\n")
        ips = [ip.strip() for ip in ips if ip.strip()]
        
        if not ips:
            messagebox.showwarning("Warning", f"No IPs to {action_name}")
            return
        
        protocol = self.protocol_var.get().lower()
        added = 0
        failed = 0
        
        for ip in ips:
            if not self.validate_ip(ip):
                messagebox.showerror("Validation Error", f"Invalid IP format: {ip}")
                failed += 1
                continue
            
            cmd = ["iptables", "-I", "INPUT", "1", "-p", protocol, "-s", ip, "-j", action]
            
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                added += 1
            except subprocess.CalledProcessError as e:
                failed += 1
        
        messagebox.showinfo("Bulk Operation", 
                          f"{action_name.capitalize()} complete:\n{added} added, {failed} failed")
        text_widget.delete("1.0", tk.END)
        self.refresh_rules()
    
    def refresh_rules(self):
        """Refresh the rule list from iptables"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-v", "-n", "--line-numbers"],
                capture_output=True, text=True, check=True
            )
            
            lines = result.stdout.split("\n")
            
            data_started = False
            for line in lines:
                if line.startswith("num"):
                    data_started = True
                    continue
                
                if not data_started or not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 8:
                    continue
                
                line_num = parts[0]
                packets = parts[1]
                protocol = parts[3]
                source = parts[7] if len(parts) > 7 else "anywhere"
                destination = parts[8] if len(parts) > 8 else "anywhere"
                action = parts[2]
                
                flags = ""
                sport = ""
                dport = ""
                
                remaining = " ".join(parts[9:]) if len(parts) > 9 else ""
                
                dport_match = re.search(r'dpt:(\d+)', remaining)
                if dport_match:
                    dport = dport_match.group(1)
                
                sport_match = re.search(r'spt:(\d+)', remaining)
                if sport_match:
                    sport = sport_match.group(1)
                
                flags_match = re.search(r'flags:([\w,/]+)', remaining)
                if flags_match:
                    flags = flags_match.group(1)
                
                self.tree.insert("", tk.END, values=(
                    line_num, protocol, flags, source, destination,
                    sport, dport, action, packets
                ))
        
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to list rules:\n{e.stderr}")
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Run with sudo/root privileges.")
    
    def disable_rule(self):
        """Remove the selected rule"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to disable")
            return
        
        item = self.tree.item(selection[0])
        line_num = item['values'][0]
        
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", str(line_num)],
                check=True, capture_output=True, text=True
            )
            messagebox.showinfo("Success", f"Rule {line_num} disabled")
            self.refresh_rules()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to disable rule:\n{e.stderr}")
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Run with sudo/root privileges.")
    
    def reorder_by_usage(self):
        """Reorder rules based on packet hit count"""
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-v", "-n", "--line-numbers"],
                capture_output=True, text=True, check=True
            )
            
            lines = result.stdout.split("\n")
            rules = []
            
            data_started = False
            for line in lines:
                if line.startswith("num"):
                    data_started = True
                    continue
                
                if not data_started or not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 8:
                    continue
                
                line_num = parts[0]
                packets = int(parts[1]) if parts[1].isdigit() else 0
                bytes_count = parts[2]  
                
                prev_count = self.previous_counts.get(line_num, 0)
                delta = packets - prev_count
                self.previous_counts[line_num] = packets
                
                rule_spec = " ".join(parts[3:])
                rules.append((delta, packets, bytes_count, line_num, rule_spec, line))
            
            if not rules:
                messagebox.showinfo("Info", "No rules to reorder")
                return
            
            rules.sort(key=lambda x: x[0], reverse=True)
            
            total_delta = sum(r[0] for r in rules)
            
            info = "Reordering rules by usage:\n\n"
            for delta, packets, bytes_count, line_num, rule_spec, original_line in rules:
                ratio = (delta / total_delta * 100) if total_delta > 0 else 0
                info += f"Line {line_num}: Δ{delta} pkts ({ratio:.1f}%)\n"
            
            response = messagebox.askyesno("Reorder Confirmation", 
                                          info + "\nProceed with reordering?")
            
            if not response:
                return
            
            for rule in reversed(rules):
                subprocess.run(
                    ["iptables", "-D", "INPUT", "1"],
                    check=True, capture_output=True, text=True
                )
            
            for delta, packets, bytes_count, line_num, rule_spec, original_line in rules:
                parts = original_line.split()
                if len(parts) < 10:
                    continue
                
                action = parts[3]      
                protocol = parts[4]    
                source = parts[8]      
                destination = parts[9] 
                
                cmd = ["iptables", "-A", "INPUT", "-c", str(packets), str(bytes_count), "-p", protocol]
                
                if source and source != "anywhere" and source != "0.0.0.0/0":
                    cmd.extend(["-s", source])
                
                if destination and destination != "anywhere" and destination != "0.0.0.0/0":
                    cmd.extend(["-d", destination])
                
                remaining = " ".join(parts[10:]) if len(parts) > 10 else ""
                
                dport_match = re.search(r'dpt:(\d+)', remaining)
                if dport_match:
                    cmd.extend(["--dport", dport_match.group(1)])
                
                sport_match = re.search(r'spt:(\d+)', remaining)
                if sport_match:
                    cmd.extend(["--sport", sport_match.group(1)])
                
                flags_match = re.search(r'flags:(0x[0-9A-Fa-f]+/0x[0-9A-Fa-f]+)', remaining)
                if flags_match:
                    flag_names = []
                    for flag in ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']:
                        if flag in remaining:
                            flag_names.append(flag)
                    
                    if flag_names:
                        all_flags = "SYN,ACK,FIN,RST,PSH,URG"
                        match_flags = ",".join(flag_names)
                        cmd.extend(["--tcp-flags", all_flags, match_flags])
                
                cmd.extend(["-j", action])
                
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            messagebox.showinfo("Success", "Rules reordered by usage")
            self.refresh_rules()
        
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to reorder rules:\n{e.stderr}")
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Run with sudo/root privileges.")
    
    def clear_inputs(self):
        """Clear all input fields"""
        self.src_ip_var.set("")
        self.dst_ip_var.set("")
        self.src_port_var.set("")
        self.dst_port_var.set("")
        for var in self.flag_vars.values():
            var.set(False)


def main():
    root = tk.Tk()
    app = IptablesGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
