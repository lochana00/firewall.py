import tkinter as tk
from tkinter import messagebox, ttk
import subprocess
import logging
import json
import threading
from scapy.all import sniff, IP
from tkinter.scrolledtext import ScrolledText

class FirewallApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Advanced Firewall")
        self.master.geometry("800x600")

        # Initialize logging
        self.log_window = None
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
        self.log_queue = []

        self.rules = []
        self.intrusion_rules = []
        self.blocked_ips = set()

        # Packet sniffing control
        self.sniffing_thread = None
        self.stop_sniffing_event = threading.Event()  # Event to stop sniffing

        # Create UI elements
        self.rule_label = tk.Label(master, text="Add Firewall Rule:")
        self.rule_label.pack(pady=10)

        # Create input fields
        self.src_ip_label = tk.Label(master, text="Source IP:")
        self.src_ip_label.pack(pady=5)
        self.src_ip_entry = tk.Entry(master)
        self.src_ip_entry.pack(pady=5)

        self.src_port_label = tk.Label(master, text="Source Port:")
        self.src_port_label.pack(pady=5)
        self.src_port_entry = tk.Entry(master)
        self.src_port_entry.pack(pady=5)

        self.dest_ip_label = tk.Label(master, text="Destination IP:")
        self.dest_ip_label.pack(pady=5)
        self.dest_ip_entry = tk.Entry(master)
        self.dest_ip_entry.pack(pady=5)

        self.dest_port_label = tk.Label(master, text="Destination Port:")
        self.dest_port_label.pack(pady=5)
        self.dest_port_entry = tk.Entry(master)
        self.dest_port_entry.pack(pady=5)

        # Protocol selection
        self.protocol_label = tk.Label(master, text="Protocol:")
        self.protocol_label.pack(pady=5)
        self.protocol_var = tk.StringVar(value="TCP")
        self.protocol_options = ttk.Combobox(master, textvariable=self.protocol_var,
                                             values=["TCP", "UDP", "ICMP"])
        self.protocol_options.pack(pady=5)

        # Rule type selection
        self.rule_type_label = tk.Label(master, text="Rule Type:")
        self.rule_type_label.pack(pady=5)
        self.rule_type_var = tk.StringVar(value="Allow")
        self.rule_type_options = ttk.Combobox(master, textvariable=self.rule_type_var,
                                              values=["Allow", "Deny", "Disable"])
        self.rule_type_options.pack(pady=5)

        # Add buttons
        self.add_button = tk.Button(master, text="Add Rule", command=self.add_rule)
        self.add_button.pack(pady=10)

        self.load_button = tk.Button(master, text="Load Rules", command=lambda: self.load_rules("rules.json"))
        self.load_button.pack(pady=5)

        self.save_button = tk.Button(master, text="Save Rules", command=lambda: self.save_rules("rules.json"))
        self.save_button.pack(pady=5)

        self.delete_button = tk.Button(master, text="Delete Rule", command=self.delete_rule)
        self.delete_button.pack(pady=5)

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
        self.add_ids_button = tk.Button(master, text="Add Intrusion IP", command=self.add_ids_rule)
        self.add_ids_button.pack(pady=5)

    def open_log_window(self):
        """Open a separate log window."""
        if self.log_window is None or not self.log_window.winfo_exists():
            self.log_window = tk.Toplevel(self.master)
            self.log_window.title("Log Output")
            self.log_window.geometry("600x400")

            # Create a scrolled text box for logs
            self.log_output = ScrolledText(self.log_window, state='disabled', wrap='word')
            self.log_output.pack(expand=True, fill='both')

            # Continuously update the log window
            self.update_log_window()
        else:
            self.log_window.lift()

    def update_log_window(self):
        """Update the log window with new log entries."""
        while self.log_queue:
            log_entry = self.log_queue.pop(0)
            self.log_output.configure(state='normal')
            self.log_output.insert(tk.END, log_entry + '\n')
            self.log_output.configure(state='disabled')
            self.log_output.yview(tk.END)

        # Schedule next update
        self.master.after(1000, self.update_log_window)

    def log(self, message):
        """Log messages and store them for display in the log window."""
        logging.info(message)
        self.log_queue.append(message)

    def load_rules(self, filename):
        """Load rules from a JSON configuration file."""
        try:
            with open(filename, 'r') as f:
                self.rules = json.load(f)
            self.update_rules_tree()
            self.log("Rules loaded from configuration file.")
        except Exception as e:
            self.log(f"Failed to load rules: {e}")
            messagebox.showerror("Error", "Failed to load rules.")

    def save_rules(self, filename):
        """Save current rules to a JSON configuration file."""
        try:
            with open(filename, 'w') as f:
                json.dump(self.rules, f)
            self.log("Rules saved to configuration file.")
        except Exception as e:
            self.log(f"Failed to save rules: {e}")
            messagebox.showerror("Error", "Failed to save rules.")

    def delete_rule(self):
        """Delete the selected rule from the table and the internal list."""
        selected_item = self.rules_tree.selection()
        if selected_item:
            rule_values = self.rules_tree.item(selected_item)["values"]
            self.rules_tree.delete(selected_item)
            
            # Convert the selected rule's values into a tuple for comparison with rules list
            rule_to_delete = tuple(rule_values)
            
            # Remove the rule from the internal list of rules
            if rule_to_delete in self.rules:
                self.rules.remove(rule_to_delete)
                
            self.log(f"Rule deleted: {rule_to_delete}")
        else:
            messagebox.showwarning("Selection Error", "Please select a rule to delete.")

    def start_sniffing(self):
        """Start packet sniffing in a separate thread."""
        if self.sniffing_thread is None or not self.sniffing_thread.is_alive():
            self.stop_sniffing_event.clear()  # Clear the event (i.e., allow sniffing)
            self.sniffing_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniffing_thread.start()

    def stop_sniffing(self):
        """Stop packet sniffing."""
        if self.sniffing_thread is not None and self.sniffing_thread.is_alive():
            self.stop_sniffing_event.set()  # Set the event (i.e., stop sniffing)
            self.log("Sniffing stopped.")

    def sniff_packets(self):
        """Capture packets and process them."""
        sniff(prn=self.packet_handler, filter="ip", store=0, stop_filter=self.stop_filter)

    def stop_filter(self, packet):
        """Stop sniffing if the event is set."""
        return self.stop_sniffing_event.is_set()

    def packet_handler(self, packet):
        """Handle incoming packets."""
        src_ip = packet[IP].src
        if src_ip in self.blocked_ips:
            self.log(f"Blocked packet from {src_ip}")
        else:
            self.log(f"Allowed packet from {src_ip}")

    def add_rule(self):
        """Add a firewall rule."""
        src_ip = self.src_ip_entry.get()
        src_port = self.src_port_entry.get()
        dest_ip = self.dest_ip_entry.get()
        dest_port = self.dest_port_entry.get()
        protocol = self.protocol_var.get()
        rule_type = self.rule_type_var.get()

        if src_ip and dest_ip:
            rule = (src_ip, src_port, dest_ip, dest_port, protocol, rule_type)
            self.rules.append(rule)
            self.rules_tree.insert("", tk.END, values=rule)
            self.log(f"Rule added: {rule}")
            self.clear_entries()
        else:
            messagebox.showwarning("Input Error", "Please fill in the required fields.")

    def add_ids_rule(self):
        """Add an IP to the intrusion detection list."""
        intrusion_ip = self.intrusion_ip_entry.get()
        if intrusion_ip:
            self.intrusion_rules.append(intrusion_ip)
            self.ids_tree.insert("", tk.END, values=(intrusion_ip,))
            self.blocked_ips.add(intrusion_ip)
            self.log(f"Intrusion IP added: {intrusion_ip}")
        else:
            messagebox.showwarning("Input Error", "Please enter an IP address.")

    def update_rules_tree(self):
        """Update the rules displayed in the Treeview."""
        # Clear existing entries
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)

        # Insert new rules
        for rule in self.rules:
            self.rules_tree.insert("", tk.END, values=rule)

    def clear_entries(self):
        """Clear input fields."""
        self.src_ip_entry.delete(0, tk.END)
        self.src_port_entry.delete(0, tk.END)
        self.dest_ip_entry.delete(0, tk.END)
        self.dest_port_entry.delete(0, tk.END)
        self.protocol_var.set("TCP")
        self.rule_type_var.set("Allow")


if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()
