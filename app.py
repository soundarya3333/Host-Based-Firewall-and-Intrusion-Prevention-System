import subprocess
import socket
import sqlite3
import logging
import platform
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP
import streamlit as st
from datetime import datetime
import os

# Configure logging
logging.basicConfig(
    filename='firewall.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('firewall_rules.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY)''')
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ports (port INTEGER PRIMARY KEY)''')
    c.execute('''CREATE TABLE IF NOT EXISTS allowed_ports (port INTEGER PRIMARY KEY)''')
    conn.commit()
    return conn

# Load rules from database
def load_rules(conn):
    c = conn.cursor()
    c.execute('SELECT ip FROM blocked_ips')
    blocked_ips = [row[0] for row in c.fetchall()]
    c.execute('SELECT port FROM blocked_ports')
    blocked_ports = [row[0] for row in c.fetchall()]
    c.execute('SELECT port FROM allowed_ports')
    allowed_ports = [row[0] for row in c.fetchall()]
    return blocked_ips, blocked_ports, allowed_ports

# Save rules to database
def save_rule(conn, table, value):
    c = conn.cursor()
    c.execute(f'INSERT OR IGNORE INTO {table} VALUES (?)', (value,))
    conn.commit()

def delete_rule(conn, table, value):
    c = conn.cursor()
    c.execute(f'DELETE FROM {table} WHERE {"ip" if table == "blocked_ips" else "port"} = ?', (value,))
    conn.commit()

# Firewall rule management (Windows and Linux)
def manage_firewall_rule(action, ip=None, port=None):
    system = platform.system()
    try:
        if system == "Windows":
            if ip:
                rule_name = f"Block_IP_{ip.replace('.', '_')}"
                command = f'netsh advfirewall firewall {action} rule name="{rule_name}" dir=in action=block remoteip={ip}'
            elif port:
                rule_name = f"Block_Port_{port}"
                command = f'netsh advfirewall firewall {action} rule name="{rule_name}" protocol=TCP dir=in action=block localport={port}'
        elif system == "Linux":
            if ip:
                command = f'iptables -{"A" if action == "add" else "D"} INPUT -s {ip} -j DROP'
            elif port:
                command = f'iptables -{"A" if action == "add" else "D"} INPUT -p tcp --dport {port} -j DROP'
        else:
            raise ValueError("Unsupported OS")
        
        subprocess.run(command, shell=True, check=True)
        logging.info(f"{action.capitalize()} rule for {'IP ' + ip if ip else 'Port ' + str(port)}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to {action} rule for {'IP ' + ip if ip else 'Port ' + str(port)}: {e}")
        return False

# Packet processing
def create_packet_record(packet, status):
    return {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Source IP": packet[IP].src if IP in packet else "N/A",
        "Destination IP": packet[IP].dst if IP in packet else "N/A",
        "Source Port": packet[TCP].sport if packet.haslayer(TCP) else "N/A",
        "Destination Port": packet[TCP].dport if packet.haslayer(TCP) else "N/A",
        "Protocol": "TCP" if packet.haslayer(TCP) else "Other",
        "Status": status
    }

def process_packet(packet, blocked_ips, blocked_ports):
    status = "Allowed"
    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        if src_ip in blocked_ips or dst_ip in blocked_ips:
            status = "Blocked"
        elif packet.haslayer(TCP):
            src_port, dst_port = packet[TCP].sport, packet[TCP].dport
            if src_port in blocked_ports or dst_port in blocked_ports:
                status = "Blocked"
    return create_packet_record(packet, status)

# Get host IP address
def get_host_ip():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        logging.error(f"Failed to get host IP: {e}")
        return "Unknown"

# Streamlit app
def main():
    st.set_page_config(page_title="Host-Based Firewall", layout="wide")
    
    # Initialize session state for authentication
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

    # Simple authentication
    if not st.session_state.authenticated:
        st.title("Login")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            # Replace with secure password hashing in production
            if password == "admin123":  # Placeholder password
                st.session_state.authenticated = True
                st.experimental_rerun()
            else:
                st.error("Incorrect password")
        return

    st.title("Host-Based Firewall Management")
    
    # Initialize database and load rules
    conn = init_db()
    blocked_ips, blocked_ports, allowed_ports = load_rules(conn)
    
    # Network interface configuration
    interface = st.text_input("Network Interface", value="eth0" if platform.system() == "Linux" else "Wi-Fi")
    packet_count = st.number_input("Number of Packets to Capture", min_value=1, value=10)

    # Packet records
    packet_records = []

    # Sniff packets
    try:
        packets = sniff(count=packet_count, iface=interface, timeout=10)
        for packet in packets:
            record = process_packet(packet, blocked_ips, blocked_ports)
            packet_records.append(record)
    except Exception as e:
        st.error(f"Packet sniffing failed: {e}")
        logging.error(f"Packet sniffing failed: {e}")

    # Convert to DataFrame
    packet_df = pd.DataFrame(packet_records)

    # UI Layout
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Manage IP Rules")
        new_ip = st.text_input("Enter IP to Block")
        if st.button("Block IP") and new_ip:
            if manage_firewall_rule("add", ip=new_ip):
                save_rule(conn, "blocked_ips", new_ip)
                blocked_ips.append(new_ip)
                st.success(f"Blocked IP: {new_ip}")
        
        ip_to_unblock = st.selectbox("Select IP to Unblock", blocked_ips, key="unblock_ip")
        if st.button("Unblock IP") and ip_to_unblock:
            if manage_firewall_rule("delete", ip=ip_to_unblock):
                delete_rule(conn, "blocked_ips", ip_to_unblock)
                blocked_ips.remove(ip_to_unblock)
                st.success(f"Unblocked IP: {ip_to_unblock}")

    with col2:
        st.subheader("Manage Port Rules")
        new_port = st.number_input("Enter Port to Block", min_value=1, max_value=65535, step=1)
        if st.button("Block Port") and new_port:
            if new_port in allowed_ports:
                allowed_ports.remove(new_port)
                delete_rule(conn, "allowed_ports", new_port)
            if manage_firewall_rule("add", port=new_port):
                save_rule(conn, "blocked_ports", new_port)
                blocked_ports.append(new_port)
                st.success(f"Blocked Port: {new_port}")
        
        port_to_unblock = st.selectbox("Select Port to Allow", blocked_ports, key="unblock_port")
        if st.button("Allow Port") and port_to_unblock:
            if manage_firewall_rule("delete", port=port_to_unblock):
                delete_rule(conn, "blocked_ports", port_to_unblock)
                blocked_ports.remove(port_to_unblock)
                save_rule(conn, "allowed_ports", port_to_unblock)
                allowed_ports.append(port_to_unblock)
                st.success(f"Allowed Port: {port_to_unblock}")

    # Display packet data
    st.subheader("Packet Monitoring")
    st.dataframe(packet_df)

    # Export packet data
    if not packet_df.empty:
        csv = packet_df.to_csv(index=False)
        st.download_button("Download Packet Data", csv, "packet_data.csv", "text/csv")

    # Display host IP
    st.subheader("Host Information")
    st.write(f"Host IP Address: {get_host_ip()}")

    # Visualization
    if not packet_df.empty:
        st.subheader("Packet Analysis")
        packet_counts = packet_df.groupby(['Source IP', 'Status']).size().reset_index(name='Count')
        fig = px.bar(packet_counts, x='Source IP', y='Count', color='Status',
                     title='Packet Status by Source IP',
                     labels={'Count': 'Number of Packets', 'Source IP': 'Source IP'},
                     text='Count')
        fig.update_traces(texttemplate='%{text}', textposition='outside')
        fig.update_layout(barmode='stack', xaxis_title='Source IP', yaxis_title='Number of Packets')
        st.plotly_chart(fig)

    # Help section
    with st.expander("Help"):
        st.markdown("""
        ### Host-Based Firewall Guide
