import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText
import logging
import json
import threading
from scapy.all import sniff, IP

# Define the portOptions dictionary
portOptions = {
    "HTTP": {"port": "80", "protocol": "TCP"},
    "HTTPS": {"port": "443", "protocol": "TCP"},
    "FTP(Data)": {"port": "20", "protocol": "TCP/UDP"},
    "FTP(Control)": {"port": "21", "protocol": "TCP"},
    "SSH": {"port": "22", "protocol": "TCP"},
    "DNS": {"port": "53", "protocol": "TCP/UDP"},
    "SMTP": {"port": "25", "protocol": "TCP"},
    "IMAP": {"port": "143", "protocol": "TCP"},
    "IMAP over SSL": {"port": "993", "protocol": "TCP"},
    "POP3": {"port": "110", "protocol": "TCP"},
    "POP3 over SSL": {"port": "995", "protocol": "TCP"},
    "Telnet": {"port": "23", "protocol": "TCP"},
    "SMB": {"port": "445", "protocol": "TCP"},
    "RDP": {"port": "3389", "protocol": "TCP"},
    "MySQL": {"port": "3306", "protocol": "TCP"},
    "PostgreSQL": {"port": "5432", "protocol": "TCP"},
    "NTP": {"port": "123", "protocol": "UDP"},
    "LDAP": {"port": "389", "protocol": "TCP"},
    "LDAP over SSL": {"port": "636", "protocol": "TCP"},
    "TFTP": {"port": "69", "protocol": "UDP"},
}

class FirewallApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Advanced Firewall")
        self.master.geometry("1500x700")

        # Initialize logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
        self.log_queue = []
        self.log_lock = threading.Lock()

        self.rules = []
        self.intrusion_rules = []
        self.blocked_ips = set()

        # Packet sniffing control
        self.sniffing_thread = None
        self.stop_sniffing_event = threading.Event()  # Event to stop sniffing
        self.host_ip = "192.168.189.139"  # Your host IP

        # Create UI elements
        self.rule_label = tk.Label(master, text="Add/Edit Firewall Rule:")
        self.rule_label.pack(pady=10)

        # Create input fields in horizontal layout
        input_frame = tk.Frame(master)
        input_frame.pack(pady=5)

        # Source IP
        self.src_ip_label = tk.Label(input_frame, text="Source IP:")
        self.src_ip_label.grid(row=0, column=0, padx=5)
        self.src_ip_entry = tk.Entry(input_frame)
        self.src_ip_entry.grid(row=0, column=1, padx=5)

        # Source Port
        self.src_port_label = tk.Label(input_frame, text="Source Port:")
        self.src_port_label.grid(row=0, column=2, padx=5)
        self.src_port_var = tk.StringVar()
        self.src_port_combobox = ttk.Combobox(input_frame, textvariable=self.src_port_var)
        self.src_port_combobox.grid(row=0, column=3, padx=5)

        # Destination IP
        self.dest_ip_label = tk.Label(input_frame, text="Destination IP:")
        self.dest_ip_label.grid(row=1, column=0, padx=5)
        self.dest_ip_entry = tk.Entry(input_frame)
        self.dest_ip_entry.grid(row=1, column=1, padx=5)

        # Destination Port
        self.dest_port_label = tk.Label(input_frame, text="Destination Port:")
        self.dest_port_label.grid(row=1, column=2, padx=5)
        self.dest_port_var = tk.StringVar()
        self.dest_port_combobox = ttk.Combobox(input_frame, textvariable=self.dest_port_var)
        self.dest_port_combobox.grid(row=1, column=3, padx=5)

        # Service/Protocol selection
        self.service_label = tk.Label(master, text="Select Service/Protocol:")
        self.service_label.pack(pady=5)
        self.service_var = tk.StringVar()
        self.service_options = ttk.Combobox(master, textvariable=self.service_var,
                                              values=list(portOptions.keys()) + ["ICMP", "ANY SERVICE"])
        self.service_options.pack(pady=5)

        # Bind event to populate service details
        self.service_options.bind("<<ComboboxSelected>>", self.populate_service_details)

        # Rule type selection
        self.rule_type_label = tk.Label(master, text="Rule Type:")
        self.rule_type_label.pack(pady=5)
        self.rule_type_var = tk.StringVar(value="Allow")
        self.rule_type_options = ttk.Combobox(master, textvariable=self.rule_type_var,
                                              values=["Allow", "Deny", "Disable"])
        self.rule_type_options.pack(pady=5)

        # Add/Edit buttons
        self.button_frame = tk.Frame(master)
        self.button_frame.pack(pady=10)

        self.add_button = tk.Button(self.button_frame, text="Add Rule", command=self.add_rule)
        self.add_button.grid(row=0, column=0, padx=5)

        self.edit_button = tk.Button(self.button_frame, text="Edit Selected Rule", command=self.edit_rule)
        self.edit_button.grid(row=0, column=1, padx=5)

        self.load_button = tk.Button(self.button_frame, text="Load Rules", command=lambda: self.load_rules("rules.json"))
        self.load_button.grid(row=0, column=2, padx=5)

        self.save_button = tk.Button(self.button_frame, text="Save Rules", command=lambda: self.save_rules("rules.json"))
        self.save_button.grid(row=0, column=3, padx=5)

        self.delete_button = tk.Button(self.button_frame, text="Delete Rule", command=self.delete_rule)
        self.delete_button.grid(row=0, column=4, padx=5)

        self.start_sniff_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_sniff_button.pack(pady=5)

        self.stop_sniff_button = tk.Button(master, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_sniff_button.pack(pady=5)

        self.log_button = tk.Button(master, text="Open Log Window", command=self.open_log_window)
        self.log_button.pack(pady=5)

        # Rules display
        self.rules_tree = ttk.Treeview(master, columns=("src_ip", "src_port", "dest_ip", "dest_port", "protocol", "rule_type"), show="headings")
        self.rules_tree.heading("src_ip", text="Source IP")
        self.rules_tree.heading("src_port", text="Source Port")
        self.rules_tree.heading("dest_ip", text="Destination IP")
        self.rules_tree.heading("dest_port", text="Destination Port")
        self.rules_tree.heading("protocol", text="Protocol")
        self.rules_tree.heading("rule_type", text="Rule Type")
        self.rules_tree.pack(pady=10, fill=tk.BOTH, expand=True)

        # Intrusion detection display
        self.ids_label = tk.Label(master, text="Intrusion Detection List:")
        self.ids_label.pack(pady=10)

        self.ids_tree = ttk.Treeview(master, columns=("intrusion_ip",), show="headings")
        self.ids_tree.heading("intrusion_ip", text="Intrusion IP")
        self.ids_tree.pack(pady=10, fill=tk.BOTH, expand=True)

        # Entry for intrusion IPs
        self.intrusion_ip_entry = tk.Entry(master)
        self.intrusion_ip_entry.pack(pady=5)

        self.add_ids_button = tk.Button(master, text="Add Intrusion Detection IP", command=self.add_ids_rule)
        self.add_ids_button.pack(pady=5)

        # Log window
        self.log_window = None
        self.log_text = None

        # Start the log update loop
        self.update_log_window()

    def open_log_window(self):
        """Open the log window."""
        if self.log_window is None or not self.log_window.winfo_exists():
            self.log_window = tk.Toplevel(self.master)
            self.log_window.title("Log Window")
            self.log_text = ScrolledText(self.log_window, state='normal')
            self.log_text.pack(pady=5, fill=tk.BOTH, expand=True)
            self.log_text.config(state='disabled')

            # Start the log update loop
            self.update_log_window()

    def update_log_window(self):
        """Update the log window."""
        if self.log_window is not None and self.log_text is not None:
            with self.log_lock:
                if self.log_queue:
                    self.log_text.config(state='normal')
                    for log in self.log_queue:
                        self.log_text.insert(tk.END, log + "\n")
                    self.log_text.config(state='disabled')
                    self.log_queue.clear()
            self.log_window.after(1000, self.update_log_window)

    def add_rule(self):
        """Add a firewall rule."""
        src_ip = self.src_ip_entry.get()
        src_port = self.src_port_var.get()
        dest_ip = self.dest_ip_entry.get()
        dest_port = self.dest_port_var.get()
        protocol = self.service_var.get()
        rule_type = self.rule_type_var.get()

        if not (src_ip and dest_ip and protocol):
            messagebox.showwarning("Input Error", "Please fill in all required fields.")
            return

        # Handle ICMP and ANY SERVICE
        if protocol == "ICMP":
            src_port = 'N/A'
            dest_port = 'N/A'
        elif protocol == "ANY SERVICE":
            src_port = 'ANY'
            dest_port = 'ANY'

        rule = {
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": protocol,
            "rule_type": rule_type
        }

        self.rules.append(rule)
        self.populate_rules_tree()
        self.src_ip_entry.delete(0, tk.END)
        self.dest_ip_entry.delete(0, tk.END)
        self.src_port_combobox.set('')
        self.dest_port_combobox.set('')
        self.service_var.set('')
        self.rule_type_var.set("Allow")

        logging.info(f"Rule added: {rule}")

    def populate_rules_tree(self):
        """Populate the rules tree view."""
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        for rule in self.rules:
            self.rules_tree.insert("", tk.END, values=(rule['src_ip'], rule['src_port'], rule['dest_ip'],
                                                        rule['dest_port'], rule['protocol'], rule['rule_type']))

    def load_rules(self, filename):
        """Load rules from a JSON file."""
        try:
            with open(filename, 'r') as f:
                self.rules = json.load(f)
            self.populate_rules_tree()
            logging.info(f"Rules loaded from {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not load rules: {str(e)}")

    def save_rules(self, filename):
        """Save rules to a JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(self.rules, f, indent=4)
            logging.info(f"Rules saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save rules: {str(e)}")

    def delete_rule(self):
        """Delete the selected rule."""
        selected_item = self.rules_tree.selection()
        if not selected_item:
            messagebox.showwarning("Selection Error", "Please select a rule to delete.")
            return
        for item in selected_item:
            self.rules_tree.delete(item)
            self.rules.remove(self.rules[int(item)])  # Note: Adjust the removal logic as needed
            logging.info("Rule deleted")

    def edit_rule(self):
        """Edit the selected rule."""
        selected_item = self.rules_tree.selection()
        if not selected_item:
            messagebox.showwarning("Selection Error", "Please select a rule to edit.")
            return
        # Logic for editing the rule can be added here
        logging.info("Rule edited")

    def populate_service_details(self, event):
        """Populate the source and destination port based on selected service."""
        selected_service = self.service_var.get()
        if selected_service in portOptions:
            self.src_port_combobox.set(portOptions[selected_service]["port"])
            self.dest_port_combobox.set(portOptions[selected_service]["port"])
        elif selected_service == "ICMP":
            self.src_port_combobox.set('N/A')
            self.dest_port_combobox.set('N/A')
        elif selected_service == "ANY SERVICE":
            self.src_port_combobox.set('ANY')
            self.dest_port_combobox.set('ANY')
        else:
            self.src_port_combobox.set('')

    def add_ids_rule(self):
        """Add an intrusion detection rule."""
        intrusion_ip = self.intrusion_ip_entry.get()
        if intrusion_ip:
            self.intrusion_rules.append(intrusion_ip)
            self.ids_tree.insert("", tk.END, values=(intrusion_ip,))
            logging.info(f"Intrusion detection rule added: {intrusion_ip}")

    def start_sniffing(self):
        """Start packet sniffing."""
        self.stop_sniffing_event.clear()
        self.sniffing_thread = threading.Thread(target=self.sniff_packets)
        self.sniffing_thread.start()
        logging.info("Packet sniffing started")

    def stop_sniffing(self):
        """Stop packet sniffing."""
        self.stop_sniffing_event.set()
        if self.sniffing_thread is not None:
            self.sniffing_thread.join()
        logging.info("Packet sniffing stopped")

    def sniff_packets(self):
        """Sniff packets and log potential intrusion."""
        def packet_callback(packet):
            if self.stop_sniffing_event.is_set():
                return
            if IP in packet:
                src_ip = packet[IP].src
                if src_ip not in self.blocked_ips:
                    self.blocked_ips.add(src_ip)
                    with self.log_lock:
                        self.log_queue.append(f"Packet sniffed: {src_ip}")
                    logging.warning(f"Intrusion detected from IP: {src_ip}")
        
        sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()
