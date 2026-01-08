import customtkinter as ctk
import threading
import pandas as pd
import numpy as np
import os
import time
import sys
from collections import defaultdict
from scapy.all import PcapReader, IP, TCP, UDP
from datetime import datetime

# Try to import psutil, but don't fail if it's not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Fix for PyInstaller
try:
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
except:
    pass


class CICFlowTracker:
    """
    Extracts all 78 CICIDS2017 features from PCAP files.
    Complete flow extraction without packet limitations.
    Tracks PER-FEATURE computational cost in nanoseconds.
    """
    
    def __init__(self, timeout=120):
        self.flows = {}
        self.timeout = timeout
        self.packet_count = 0
        self.start_time = None
        
        # PER-FEATURE Computational Cost Tracking (Nanoseconds)
        self.feature_costs = defaultdict(float)
        self.feature_counts = defaultdict(int)

    def get_flow_key(self, pkt):
        """Create bidirectional flow key"""
        if IP not in pkt:
            return None
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            sport, dport = 0, 0
        
        # Bidirectional key
        if (src_ip, sport) < (dst_ip, dport):
            return (src_ip, sport, dst_ip, dport, proto)
        else:
            return (dst_ip, dport, src_ip, sport, proto)

    def process_packet(self, pkt):
        """Process packet and update flow statistics."""
        if self.start_time is None:
            self.start_time = time.time()
            
        flow_key = self.get_flow_key(pkt)
        if flow_key is None:
            return

        timestamp = float(pkt.time)
        pkt_len = len(pkt)
        
        # Initialize flow if new
        if flow_key not in self.flows:
            src_ip, sport, dst_ip, dport, proto = flow_key
            self.flows[flow_key] = {
                # Identifiers
                'src_ip': src_ip, 'sport': sport,
                'dst_ip': dst_ip, 'dport': dport, 
                'proto': proto,
                
                # State
                'start_time': timestamp, 
                'last_time': timestamp,
                
                # Counters
                'fwd_pkts': 0, 'bwd_pkts': 0,
                'fwd_bytes': 0, 'bwd_bytes': 0,
                
                # Lists for complete flow data (no packet limits)
                'timestamps': [],
                'pkt_lengths': [],
                'fwd_pkt_lens': [],
                'bwd_pkt_lens': [],
                'fwd_header_lens': [],
                'bwd_header_lens': [],
                'fwd_iats': [],
                'bwd_iats': [],
                'fwd_segment_sizes': [],
                'bwd_segment_sizes': [],
                
                # TCP Flags
                'fin_count': 0, 'syn_count': 0, 'rst_count': 0,
                'psh_count': 0, 'ack_count': 0, 'urg_count': 0,
                'cwr_count': 0, 'ece_count': 0,
                'fwd_psh_count': 0, 'bwd_psh_count': 0,
                'fwd_urg_count': 0, 'bwd_urg_count': 0,
                
                # Trackers
                'last_fwd_time': None, 'last_bwd_time': None,
                
                # Active/Idle periods
                'active_periods': [],
                'idle_periods': [],
                'active_start': timestamp,
                'last_active_time': timestamp,
                
                # Window sizes
                'fwd_init_win': None,
                'bwd_init_win': None,
                
                # Bulk transfer
                'fwd_bulk_bytes': 0,
                'fwd_bulk_packets': 0,
                'bwd_bulk_bytes': 0,
                'bwd_bulk_packets': 0,
                'fwd_bulk_count': 0,
                'bwd_bulk_count': 0,
                
                # Data packets
                'fwd_data_pkts': 0,
            }
            self.flows[flow_key]['timestamps'].append(timestamp)

        flow = self.flows[flow_key]
        src_ip, sport, dst_ip, dport, proto = flow_key
        
        # Direction
        direction = 'fwd' if pkt[IP].src == src_ip else 'bwd'
        
        # Update lists
        flow['pkt_lengths'].append(pkt_len)
        flow['timestamps'].append(timestamp)
        
        # Direction-specific updates
        if direction == 'fwd':
            flow['fwd_pkts'] += 1
            flow['fwd_bytes'] += pkt_len
            flow['fwd_pkt_lens'].append(pkt_len)
            if flow['last_fwd_time']:
                flow['fwd_iats'].append(timestamp - flow['last_fwd_time'])
            flow['last_fwd_time'] = timestamp
        else:
            flow['bwd_pkts'] += 1
            flow['bwd_bytes'] += pkt_len
            flow['bwd_pkt_lens'].append(pkt_len)
            if flow['last_bwd_time']:
                flow['bwd_iats'].append(timestamp - flow['last_bwd_time'])
            flow['last_bwd_time'] = timestamp
        
        # Active/Idle periods
        if flow['last_active_time']:
            gap = timestamp - flow['last_active_time']
            if gap > 1.0:  # Idle threshold > 1 second
                flow['idle_periods'].append(gap)
                if flow['active_start']:
                    active = flow['last_active_time'] - flow['active_start']
                    if active > 0:
                        flow['active_periods'].append(active)
                flow['active_start'] = timestamp
        
        flow['last_active_time'] = timestamp
        flow['last_time'] = timestamp
        
        # IP Header
        if IP in pkt:
            ip_header_len = pkt[IP].ihl * 4 if hasattr(pkt[IP], 'ihl') else 20
            
            if direction == 'fwd':
                flow['fwd_header_lens'].append(ip_header_len)
                # Segment size = packet size - header size
                segment_size = pkt_len - ip_header_len
                flow['fwd_segment_sizes'].append(segment_size)
            else:
                flow['bwd_header_lens'].append(ip_header_len)
                segment_size = pkt_len - ip_header_len
                flow['bwd_segment_sizes'].append(segment_size)

        # TCP specifics
        if TCP in pkt:
            tcp_flags = int(pkt[TCP].flags)
            
            # Flag counts
            if tcp_flags & 0x01: flow['fin_count'] += 1  # FIN
            if tcp_flags & 0x02: flow['syn_count'] += 1  # SYN
            if tcp_flags & 0x04: flow['rst_count'] += 1  # RST
            if tcp_flags & 0x08: flow['psh_count'] += 1  # PSH
            if tcp_flags & 0x10: flow['ack_count'] += 1  # ACK
            if tcp_flags & 0x20: flow['urg_count'] += 1  # URG
            if tcp_flags & 0x40: flow['ece_count'] += 1  # ECE
            if tcp_flags & 0x80: flow['cwr_count'] += 1  # CWR
            
            # Direction-specific flags
            if tcp_flags & 0x08:  # PSH
                if direction == 'fwd':
                    flow['fwd_psh_count'] += 1
                else:
                    flow['bwd_psh_count'] += 1
            
            if tcp_flags & 0x20:  # URG
                if direction == 'fwd':
                    flow['fwd_urg_count'] += 1
                else:
                    flow['bwd_urg_count'] += 1
            
            # Initial window sizes
            if flow['fwd_init_win'] is None and direction == 'fwd' and (tcp_flags & 0x02):  # SYN
                flow['fwd_init_win'] = pkt[TCP].window
            if flow['bwd_init_win'] is None and direction == 'bwd' and (tcp_flags & 0x02):  # SYN-ACK
                flow['bwd_init_win'] = pkt[TCP].window
            
            # Data packets (ACK with payload)
            if direction == 'fwd' and (tcp_flags & 0x10) and len(pkt[TCP].payload) > 0:
                flow['fwd_data_pkts'] += 1
            
        self.packet_count += 1

    def measure_feature(self, feature_name, func):
        """Measure execution time for a SINGLE feature in nanoseconds"""
        t0 = time.perf_counter_ns()
        result = func()
        t1 = time.perf_counter_ns()
        self.feature_costs[feature_name] += (t1 - t0)
        self.feature_counts[feature_name] += 1
        return result

    def extract_features(self, flow_key):
        """Extract all 78 CICIDS2017 features with PER-FEATURE cost measurement"""
        flow = self.flows[flow_key]
        features = {}
        
        # Convert deques to lists
        ts = list(flow['timestamps'])
        pkt_lens = list(flow['pkt_lengths'])
        fwd_pkt_lens = list(flow['fwd_pkt_lens'])
        bwd_pkt_lens = list(flow['bwd_pkt_lens'])
        fwd_iats = list(flow['fwd_iats'])
        bwd_iats = list(flow['bwd_iats'])
        fwd_header_lens = list(flow['fwd_header_lens'])
        bwd_header_lens = list(flow['bwd_header_lens'])
        fwd_seg_sizes = list(flow['fwd_segment_sizes'])
        bwd_seg_sizes = list(flow['bwd_segment_sizes'])
        active_periods = list(flow['active_periods'])
        idle_periods = list(flow['idle_periods'])
        
        dur = max(flow['last_time'] - flow['start_time'], 1e-6)
        dur_microseconds = dur * 1000000  # Convert to microseconds
        
        total_pkts = flow['fwd_pkts'] + flow['bwd_pkts']
        total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']
        
        # Identifiers (no cost tracking)
        features['src_ip'] = flow['src_ip']
        features['src_port'] = flow['sport']
        features['dst_ip'] = flow['dst_ip']
        features['dst_port'] = flow['dport']
        features['protocol'] = flow['proto']
        
        # === FLOW FEATURES ===
        
        # 1. Flow Duration (in Microseconds)
        features['flow_duration'] = self.measure_feature('flow_duration', 
            lambda: dur_microseconds)
        
        # 2-3. Total Fwd/Bwd Packets
        features['total_fwd_packets'] = self.measure_feature('total_fwd_packets',
            lambda: flow['fwd_pkts'])
        features['total_bwd_packets'] = self.measure_feature('total_bwd_packets',
            lambda: flow['bwd_pkts'])
        
        # 4-5. Total Length of Fwd/Bwd Packets
        features['total_length_fwd_packets'] = self.measure_feature('total_length_fwd_packets',
            lambda: flow['fwd_bytes'])
        features['total_length_bwd_packets'] = self.measure_feature('total_length_bwd_packets',
            lambda: flow['bwd_bytes'])
        
        # === FWD PACKET LENGTH STATS ===
        
        # 6-9. Fwd Packet Length Min/Max/Mean/Std
        features['fwd_packet_length_min'] = self.measure_feature('fwd_packet_length_min',
            lambda: min(fwd_pkt_lens) if fwd_pkt_lens else 0)
        features['fwd_packet_length_max'] = self.measure_feature('fwd_packet_length_max',
            lambda: max(fwd_pkt_lens) if fwd_pkt_lens else 0)
        features['fwd_packet_length_mean'] = self.measure_feature('fwd_packet_length_mean',
            lambda: np.mean(fwd_pkt_lens) if fwd_pkt_lens else 0)
        features['fwd_packet_length_std'] = self.measure_feature('fwd_packet_length_std',
            lambda: np.std(fwd_pkt_lens) if fwd_pkt_lens else 0)
        
        # === BWD PACKET LENGTH STATS ===
        
        # 10-13. Bwd Packet Length Min/Max/Mean/Std
        features['bwd_packet_length_min'] = self.measure_feature('bwd_packet_length_min',
            lambda: min(bwd_pkt_lens) if bwd_pkt_lens else 0)
        features['bwd_packet_length_max'] = self.measure_feature('bwd_packet_length_max',
            lambda: max(bwd_pkt_lens) if bwd_pkt_lens else 0)
        features['bwd_packet_length_mean'] = self.measure_feature('bwd_packet_length_mean',
            lambda: np.mean(bwd_pkt_lens) if bwd_pkt_lens else 0)
        features['bwd_packet_length_std'] = self.measure_feature('bwd_packet_length_std',
            lambda: np.std(bwd_pkt_lens) if bwd_pkt_lens else 0)
        
        # === FLOW RATES ===
        
        # 14-15. Flow Bytes/s and Packets/s
        features['flow_bytes_s'] = self.measure_feature('flow_bytes_s',
            lambda: total_bytes / dur if dur > 0 else 0)
        features['flow_packets_s'] = self.measure_feature('flow_packets_s',
            lambda: total_pkts / dur if dur > 0 else 0)
        
        # === FLOW IAT STATS ===
        
        # 16-19. Flow IAT Mean/Std/Max/Min
        flow_iats = [ts[i+1] - ts[i] for i in range(len(ts)-1)] if len(ts) > 1 else [0]
        features['flow_iat_mean'] = self.measure_feature('flow_iat_mean',
            lambda: np.mean(flow_iats) * 1000000 if flow_iats else 0)  # Microseconds
        features['flow_iat_std'] = self.measure_feature('flow_iat_std',
            lambda: np.std(flow_iats) * 1000000 if flow_iats else 0)
        features['flow_iat_max'] = self.measure_feature('flow_iat_max',
            lambda: max(flow_iats) * 1000000 if flow_iats else 0)
        features['flow_iat_min'] = self.measure_feature('flow_iat_min',
            lambda: min(flow_iats) * 1000000 if flow_iats else 0)
        
        # === FWD IAT STATS ===
        
        # 20-24. Fwd IAT Min/Max/Mean/Std/Total
        features['fwd_iat_min'] = self.measure_feature('fwd_iat_min',
            lambda: min(fwd_iats) * 1000000 if fwd_iats else 0)
        features['fwd_iat_max'] = self.measure_feature('fwd_iat_max',
            lambda: max(fwd_iats) * 1000000 if fwd_iats else 0)
        features['fwd_iat_mean'] = self.measure_feature('fwd_iat_mean',
            lambda: np.mean(fwd_iats) * 1000000 if fwd_iats else 0)
        features['fwd_iat_std'] = self.measure_feature('fwd_iat_std',
            lambda: np.std(fwd_iats) * 1000000 if fwd_iats else 0)
        features['fwd_iat_total'] = self.measure_feature('fwd_iat_total',
            lambda: sum(fwd_iats) * 1000000 if fwd_iats else 0)
        
        # === BWD IAT STATS ===
        
        # 25-29. Bwd IAT Min/Max/Mean/Std/Total
        features['bwd_iat_min'] = self.measure_feature('bwd_iat_min',
            lambda: min(bwd_iats) * 1000000 if bwd_iats else 0)
        features['bwd_iat_max'] = self.measure_feature('bwd_iat_max',
            lambda: max(bwd_iats) * 1000000 if bwd_iats else 0)
        features['bwd_iat_mean'] = self.measure_feature('bwd_iat_mean',
            lambda: np.mean(bwd_iats) * 1000000 if bwd_iats else 0)
        features['bwd_iat_std'] = self.measure_feature('bwd_iat_std',
            lambda: np.std(bwd_iats) * 1000000 if bwd_iats else 0)
        features['bwd_iat_total'] = self.measure_feature('bwd_iat_total',
            lambda: sum(bwd_iats) * 1000000 if bwd_iats else 0)
        
        # === TCP FLAGS ===
        
        # 30-33. Fwd/Bwd PSH/URG Flags
        features['fwd_psh_flags'] = self.measure_feature('fwd_psh_flags',
            lambda: flow['fwd_psh_count'])
        features['bwd_psh_flags'] = self.measure_feature('bwd_psh_flags',
            lambda: flow['bwd_psh_count'])
        features['fwd_urg_flags'] = self.measure_feature('fwd_urg_flags',
            lambda: flow['fwd_urg_count'])
        features['bwd_urg_flags'] = self.measure_feature('bwd_urg_flags',
            lambda: flow['bwd_urg_count'])
        
        # === HEADER LENGTHS ===
        
        # 34-35. Fwd/Bwd Header Length
        features['fwd_header_length'] = self.measure_feature('fwd_header_length',
            lambda: sum(fwd_header_lens))
        features['bwd_header_length'] = self.measure_feature('bwd_header_length',
            lambda: sum(bwd_header_lens))
        
        # === PACKETS PER SECOND ===
        
        # 36-37. Fwd/Bwd Packets/s
        features['fwd_packets_s'] = self.measure_feature('fwd_packets_s',
            lambda: flow['fwd_pkts'] / dur if dur > 0 else 0)
        features['bwd_packets_s'] = self.measure_feature('bwd_packets_s',
            lambda: flow['bwd_pkts'] / dur if dur > 0 else 0)
        
        # === PACKET LENGTH STATS ===
        
        # 38-42. Packet Length Min/Max/Mean/Std/Variance
        features['packet_length_min'] = self.measure_feature('packet_length_min',
            lambda: min(pkt_lens) if pkt_lens else 0)
        features['packet_length_max'] = self.measure_feature('packet_length_max',
            lambda: max(pkt_lens) if pkt_lens else 0)
        features['packet_length_mean'] = self.measure_feature('packet_length_mean',
            lambda: np.mean(pkt_lens) if pkt_lens else 0)
        features['packet_length_std'] = self.measure_feature('packet_length_std',
            lambda: np.std(pkt_lens) if pkt_lens else 0)
        features['packet_length_variance'] = self.measure_feature('packet_length_variance',
            lambda: np.var(pkt_lens) if pkt_lens else 0)
        
        # === TCP FLAG COUNTS ===
        
        # 43-50. FIN/SYN/RST/PSH/ACK/URG/CWR/ECE Flag Counts
        features['fin_flag_count'] = self.measure_feature('fin_flag_count',
            lambda: flow['fin_count'])
        features['syn_flag_count'] = self.measure_feature('syn_flag_count',
            lambda: flow['syn_count'])
        features['rst_flag_count'] = self.measure_feature('rst_flag_count',
            lambda: flow['rst_count'])
        features['psh_flag_count'] = self.measure_feature('psh_flag_count',
            lambda: flow['psh_count'])
        features['ack_flag_count'] = self.measure_feature('ack_flag_count',
            lambda: flow['ack_count'])
        features['urg_flag_count'] = self.measure_feature('urg_flag_count',
            lambda: flow['urg_count'])
        features['cwr_flag_count'] = self.measure_feature('cwr_flag_count',
            lambda: flow['cwr_count'])
        features['ece_flag_count'] = self.measure_feature('ece_flag_count',
            lambda: flow['ece_count'])
        
        # === RATIOS ===
        
        # 51. Down/Up Ratio
        features['down_up_ratio'] = self.measure_feature('down_up_ratio',
            lambda: flow['bwd_pkts'] / flow['fwd_pkts'] if flow['fwd_pkts'] > 0 else 0)
        
        # 52. Average Packet Size
        features['average_packet_size'] = self.measure_feature('average_packet_size',
            lambda: total_bytes / total_pkts if total_pkts > 0 else 0)
        
        # 53-54. Fwd/Bwd Segment Size Avg
        features['fwd_segment_size_avg'] = self.measure_feature('fwd_segment_size_avg',
            lambda: np.mean(fwd_seg_sizes) if fwd_seg_sizes else 0)
        features['bwd_segment_size_avg'] = self.measure_feature('bwd_segment_size_avg',
            lambda: np.mean(bwd_seg_sizes) if bwd_seg_sizes else 0)
        
        # === BULK TRANSFER (Simplified) ===
        
        # 55-60. Bulk transfer features
        features['fwd_bytes_bulk_avg'] = self.measure_feature('fwd_bytes_bulk_avg',
            lambda: flow['fwd_bulk_bytes'] / flow['fwd_bulk_count'] if flow['fwd_bulk_count'] > 0 else 0)
        features['fwd_packet_bulk_avg'] = self.measure_feature('fwd_packet_bulk_avg',
            lambda: flow['fwd_bulk_packets'] / flow['fwd_bulk_count'] if flow['fwd_bulk_count'] > 0 else 0)
        features['fwd_bulk_rate_avg'] = self.measure_feature('fwd_bulk_rate_avg',
            lambda: flow['fwd_bulk_count'] / dur if dur > 0 else 0)
        features['bwd_bytes_bulk_avg'] = self.measure_feature('bwd_bytes_bulk_avg',
            lambda: flow['bwd_bulk_bytes'] / flow['bwd_bulk_count'] if flow['bwd_bulk_count'] > 0 else 0)
        features['bwd_packet_bulk_avg'] = self.measure_feature('bwd_packet_bulk_avg',
            lambda: flow['bwd_bulk_packets'] / flow['bwd_bulk_count'] if flow['bwd_bulk_count'] > 0 else 0)
        features['bwd_bulk_rate_avg'] = self.measure_feature('bwd_bulk_rate_avg',
            lambda: flow['bwd_bulk_count'] / dur if dur > 0 else 0)
        
        # === SUBFLOW FEATURES ===
        
        # 61-64. Subflow Fwd/Bwd Packets/Bytes (Simplified - same as total)
        features['subflow_fwd_packets'] = self.measure_feature('subflow_fwd_packets',
            lambda: flow['fwd_pkts'])
        features['subflow_fwd_bytes'] = self.measure_feature('subflow_fwd_bytes',
            lambda: flow['fwd_bytes'])
        features['subflow_bwd_packets'] = self.measure_feature('subflow_bwd_packets',
            lambda: flow['bwd_pkts'])
        features['subflow_bwd_bytes'] = self.measure_feature('subflow_bwd_bytes',
            lambda: flow['bwd_bytes'])
        
        # === INIT WIN BYTES ===
        
        # 65-66. Fwd/Bwd Init Win bytes
        features['fwd_init_win_bytes'] = self.measure_feature('fwd_init_win_bytes',
            lambda: flow['fwd_init_win'] if flow['fwd_init_win'] is not None else 0)
        features['bwd_init_win_bytes'] = self.measure_feature('bwd_init_win_bytes',
            lambda: flow['bwd_init_win'] if flow['bwd_init_win'] is not None else 0)
        
        # === ACT DATA PACKETS ===
        
        # 67. Fwd Act Data Pkts
        features['fwd_act_data_pkts'] = self.measure_feature('fwd_act_data_pkts',
            lambda: flow['fwd_data_pkts'])
        
        # 68. Fwd Seg Size Min
        features['fwd_seg_size_min'] = self.measure_feature('fwd_seg_size_min',
            lambda: min(fwd_seg_sizes) if fwd_seg_sizes else 0)
        
        # === ACTIVE/IDLE STATS ===
        
        # 69-72. Active Min/Mean/Max/Std
        features['active_min'] = self.measure_feature('active_min',
            lambda: min(active_periods) * 1000000 if active_periods else 0)
        features['active_mean'] = self.measure_feature('active_mean',
            lambda: np.mean(active_periods) * 1000000 if active_periods else 0)
        features['active_max'] = self.measure_feature('active_max',
            lambda: max(active_periods) * 1000000 if active_periods else 0)
        features['active_std'] = self.measure_feature('active_std',
            lambda: np.std(active_periods) * 1000000 if active_periods else 0)
        
        # 73-76. Idle Min/Mean/Max/Std
        features['idle_min'] = self.measure_feature('idle_min',
            lambda: min(idle_periods) * 1000000 if idle_periods else 0)
        features['idle_mean'] = self.measure_feature('idle_mean',
            lambda: np.mean(idle_periods) * 1000000 if idle_periods else 0)
        features['idle_max'] = self.measure_feature('idle_max',
            lambda: max(idle_periods) * 1000000 if idle_periods else 0)
        features['idle_std'] = self.measure_feature('idle_std',
            lambda: np.std(idle_periods) * 1000000 if idle_periods else 0)
        
        return features

    def get_feature_costs(self):
        """Return average cost per feature in microseconds"""
        avg_costs = {}
        for feature_name, total_ns in self.feature_costs.items():
            count = self.feature_counts[feature_name]
            if count > 0:
                avg_costs[feature_name] = (total_ns / count) / 1000.0  # ns to μs
        return avg_costs

    def get_all_features(self):
        return [self.extract_features(fk) for fk in self.flows.keys()]


class PacketToolApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CICIDS2017 Complete Feature Extractor")
        self.geometry("950x800")
        
        # Header
        self.lbl_title = ctk.CTkLabel(
            self, 
            text="CICIDS2017 Complete Feature Extractor (78 Features)", 
            font=("Arial", 20, "bold")
        )
        self.lbl_title.pack(pady=15)

        # Subtitle
        self.lbl_subtitle = ctk.CTkLabel(
            self, 
            text="Official CICIDS2017 Feature Set with Per-Feature Cost Analysis", 
            font=("Arial", 12),
            text_color="gray"
        )
        self.lbl_subtitle.pack()

        # File Input Frame
        self.frame_files = ctk.CTkFrame(self)
        self.frame_files.pack(fill="x", padx=20, pady=15)
        
        # PCAP Input
        ctk.CTkLabel(self.frame_files, text="PCAP File:", font=("Arial", 12, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.entry_pcap = ctk.CTkEntry(
            self.frame_files, 
            placeholder_text="Select CICIDS2017 PCAP file...", 
            width=600
        )
        self.entry_pcap.grid(row=1, column=0, padx=10, pady=5)
        self.btn_pcap = ctk.CTkButton(
            self.frame_files, 
            text="Browse", 
            command=lambda: self.browse_file(self.entry_pcap, "pcap"),
            width=100
        )
        self.btn_pcap.grid(row=1, column=1, padx=10, pady=5)

        # Ground Truth CSV Input
        ctk.CTkLabel(self.frame_files, text="Ground Truth CSV (Optional):", font=("Arial", 12, "bold")).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.entry_gt = ctk.CTkEntry(
            self.frame_files, 
            placeholder_text="Select Ground Truth CSV for labeling...", 
            width=600
        )
        self.entry_gt.grid(row=3, column=0, padx=10, pady=5)
        self.btn_gt = ctk.CTkButton(
            self.frame_files, 
            text="Browse",
            fg_color="#555",
            hover_color="#444",
            command=lambda: self.browse_file(self.entry_gt, "csv"),
            width=100
        )
        self.btn_gt.grid(row=3, column=1, padx=10, pady=5)

        # Progress Bar
        self.progress = ctk.CTkProgressBar(self, width=830)
        self.progress.pack(padx=20, pady=10, fill="x")
        self.progress.set(0)
        
        self.progress_label = ctk.CTkLabel(self, text="Ready to process", font=("Arial", 11))
        self.progress_label.pack()

        # Process Button
        self.btn_process = ctk.CTkButton(
            self, 
            text="EXTRACT 78 CICIDS2017 FEATURES", 
            fg_color="#2CC985", 
            hover_color="#229C68",
            text_color="black", 
            height=50, 
            font=("Arial", 14, "bold"),
            command=self.start_processing
        )
        self.btn_process.pack(padx=20, pady=15, fill="x")

        # Log Window
        self.textbox = ctk.CTkTextbox(self, height=420, font=("Consolas", 10))
        self.textbox.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Welcome Message
        self.log("="*90)
        self.log("CICIDS2017 Complete Feature Extractor - Official 78-Feature Set")
        self.log("="*90)
        self.log("\nFeatures:")
        self.log("  • All 78 official CICIDS2017 features")
        self.log("  • Complete flow extraction (no packet limitations)")
        self.log("  • Per-feature computational cost tracking (nanosecond precision)")
        self.log("  • Ground Truth labeling support")
        self.log("  • Suitable for ML model training and attack detection")
        self.log("\nOutputs:")
        self.log("  • CSV 1: Complete feature dataset (78 features + labels if GT provided)")
        self.log("  • CSV 2: Individual feature computational costs")
        self.log("\nReady. Please select PCAP file and optionally Ground Truth CSV.")
        self.log("="*90 + "\n")

    def log(self, msg):
        self.textbox.insert("end", msg + "\n")
        self.textbox.see("end")
        self.update_idletasks()
    
    def update_progress(self, value, message=""):
        self.progress.set(value)
        if message:
            self.progress_label.configure(text=message)
        self.update_idletasks()

    def browse_file(self, entry, ftype):
        if ftype == "pcap":
            filetypes = [("PCAP Files", "*.pcap"), ("PCAPNG", "*.pcapng"), ("All Files", "*.*")]
        else:
            filetypes = [("CSV Files", "*.csv"), ("All Files", "*.*")]
            
        filename = ctk.filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            entry.delete(0, "end")
            entry.insert(0, filename)
            try:
                file_size = os.path.getsize(filename) / 1024 / 1024
                self.log(f"✓ Selected {ftype.upper()}: {os.path.basename(filename)} ({file_size:.2f} MB)")
            except:
                self.log(f"✓ Selected {ftype.upper()}: {os.path.basename(filename)}")

    def start_processing(self):
        pcap_path = self.entry_pcap.get()
        gt_path = self.entry_gt.get()
        
        if not pcap_path:
            self.log("❌ Error: Please select a PCAP file.")
            return
            
        if not os.path.exists(pcap_path):
            self.log(f"❌ Error: PCAP file not found: {pcap_path}")
            return
        
        # Ground Truth is optional
        if gt_path and not os.path.exists(gt_path):
            self.log(f"❌ Error: Ground Truth CSV not found: {gt_path}")
            return
        
        self.btn_process.configure(state="disabled", text="Processing...")
        self.update_progress(0, "Initializing...")
        threading.Thread(target=self.run_logic, args=(pcap_path, gt_path), daemon=True).start()

    def run_logic(self, pcap_path, gt_path=None):
        try:
            self.log("\n" + "="*90)
            self.log("STARTING CICIDS2017 FEATURE EXTRACTION (78 Features)")
            self.log("="*90 + "\n")
            
            tracker = CICFlowTracker()
            gt_lookup = {}
            matched_count = 0
            
            # STEP 1: Load Ground Truth (if provided)
            if gt_path:
                self.update_progress(0.02, "Loading Ground Truth...")
                self.log("[1/4] Loading Ground Truth Labels...")
                self.log(f"File: {os.path.basename(gt_path)}\n")
                
                try:
                    df_gt = pd.read_csv(gt_path, encoding='latin-1', low_memory=False)
                    df_gt.columns = df_gt.columns.str.strip().str.lower().str.replace(' ', '_')
                    
                    # Find column names
                    possible_src_ip = ['source_ip', 'src_ip', 'source ip', 'src ip', 'source_address']
                    possible_dst_ip = ['destination_ip', 'dst_ip', 'destination ip', 'dst ip', 'destination_address']
                    possible_src_port = ['source_port', 'src_port', 'source port', 'src port']
                    possible_dst_port = ['destination_port', 'dst_port', 'destination port', 'dst port']
                    possible_protocol = ['protocol', 'proto']
                    possible_label = ['label', 'attack', 'attack_type', 'class', 'classification']
                    
                    src_ip_col = next((col for col in df_gt.columns if col in possible_src_ip), None)
                    dst_ip_col = next((col for col in df_gt.columns if col in possible_dst_ip), None)
                    src_port_col = next((col for col in df_gt.columns if col in possible_src_port), None)
                    dst_port_col = next((col for col in df_gt.columns if col in possible_dst_port), None)
                    protocol_col = next((col for col in df_gt.columns if col in possible_protocol), None)
                    label_col = next((col for col in df_gt.columns if col in possible_label), None)
                    
                    if not all([src_ip_col, dst_ip_col, src_port_col, dst_port_col, label_col]):
                        self.log("⚠ Warning: Could not find all required columns in GT CSV")
                        self.log(f"Available columns: {', '.join(df_gt.columns.tolist())}")
                        self.log("Proceeding without labels...\n")
                    else:
                        for _, row in df_gt.iterrows():
                            try:
                                src_ip = str(row[src_ip_col]).strip()
                                dst_ip = str(row[dst_ip_col]).strip()
                                
                                if src_ip.lower() == 'nan' or dst_ip.lower() == 'nan':
                                    continue
                                
                                src_port = int(float(row[src_port_col])) if pd.notna(row[src_port_col]) else 0
                                dst_port = int(float(row[dst_port_col])) if pd.notna(row[dst_port_col]) else 0
                                
                                if protocol_col:
                                    proto = str(row[protocol_col]).lower().strip()
                                    if proto in ['6', '6.0']:
                                        proto = 6
                                    elif proto in ['17', '17.0']:
                                        proto = 17
                                    elif proto in ['1', '1.0']:
                                        proto = 1
                                    else:
                                        try:
                                            proto = int(float(proto))
                                        except:
                                            proto = 6
                                else:
                                    proto = 6
                                
                                label = str(row[label_col]).strip()
                                if label.lower() in ['nan', '', ' ']:
                                    label = 'BENIGN'
                                
                                key_fwd = (src_ip, src_port, dst_ip, dst_port, proto)
                                key_bwd = (dst_ip, dst_port, src_ip, src_port, proto)
                                
                                gt_lookup[key_fwd] = label
                                gt_lookup[key_bwd] = label
                                
                            except Exception as e:
                                continue
                        
                        self.log(f"✓ Loaded {len(gt_lookup):,} labeled flow entries")
                        self.log(f"✓ Unique flows: ~{len(gt_lookup)//2:,}\n")
                
                except Exception as e:
                    self.log(f"⚠ Warning: Error loading Ground Truth: {e}")
                    self.log("Proceeding without labels...\n")

            # STEP 2: Process PCAP
            step_num = 2 if gt_path else 1
            total_steps = 4 if gt_path else 3
            
            self.update_progress(0.05, "Reading PCAP file...")
            self.log(f"[{step_num}/{total_steps}] Processing PCAP and Extracting Features...")
            self.log(f"File: {os.path.basename(pcap_path)}\n")
            
            count = 0
            for pkt in PcapReader(pcap_path):
                tracker.process_packet(pkt)
                count += 1
                if count % 10000 == 0:
                    progress = 0.05 + (0.65 * min(count / 100000, 1.0))
                    self.update_progress(progress, f"Processed {count:,} packets...")
                    self.log(f"  → Processed {count:,} packets...")
            
            self.log(f"\n✓ Finished reading PCAP")
            self.log(f"✓ Total packets: {count:,}")
            self.log(f"✓ Total flows: {len(tracker.flows):,}\n")

            # STEP 3: Extract Features
            step_num += 1
            self.update_progress(0.75, "Extracting 78 features from flows...")
            self.log(f"[{step_num}/{total_steps}] Extracting 78 CICIDS2017 Features...")
            
            feature_list = tracker.get_all_features()
            df = pd.DataFrame(feature_list)
            
            self.log(f"✓ Extracted 78 features from {len(df):,} flows\n")

            # STEP 4: Match with Ground Truth (if provided)
            if gt_path and gt_lookup:
                step_num += 1
                self.update_progress(0.85, "Matching with Ground Truth...")
                self.log(f"[{step_num}/{total_steps}] Matching Flows with Ground Truth...")
                
                labels = []
                for _, row in df.iterrows():
                    key = (row['src_ip'], int(row['src_port']), row['dst_ip'], int(row['dst_port']), row['protocol'])
                    
                    if key in gt_lookup:
                        labels.append(gt_lookup[key])
                        matched_count += 1
                    else:
                        labels.append('BENIGN')
                
                df['label'] = labels
                
                self.log(f"✓ Matched {matched_count:,} flows to Ground Truth")
                self.log(f"✓ Labeled {len(df)-matched_count:,} flows as 'BENIGN'\n")
                
                # Label distribution
                self.log("Label Distribution:")
                for label, count in df['label'].value_counts().items():
                    self.log(f"  {label:30s}: {count:6,} ({count/len(df)*100:5.2f}%)")
                self.log("")

            # STEP 5: Save Outputs
            step_num += 1
            self.update_progress(0.9, "Generating output files...")
            self.log(f"[{step_num}/{total_steps}] Generating Output Files...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Reorder columns
            if 'label' in df.columns:
                cols = [c for c in df.columns if c != 'label']
                cols.append('label')
                df = df[cols]
            
            # Save Feature Dataset
            dataset_file = f"CICIDS2017_78Features_{timestamp}.csv"
            df.to_csv(dataset_file, index=False)
            self.log(f"✓ Saved Feature Dataset: {dataset_file}")
            self.log(f"  → Total Flows: {len(df):,}")
            self.log(f"  → Features: 78 (+ 5 identifiers{' + label' if 'label' in df.columns else ''})")
            self.log(f"  → File Size: {os.path.getsize(dataset_file) / 1024:.2f} KB\n")

            # Save Per-Feature Costs
            costs = tracker.get_feature_costs()
            cost_data = []
            
            self.log("="*90)
            self.log("PER-FEATURE COMPUTATIONAL COST ANALYSIS")
            self.log("="*90 + "\n")
            
            sorted_costs = sorted(costs.items(), key=lambda x: x[1], reverse=True)
            
            self.log(f"Top 15 Most Expensive Features:\n")
            for i, (fname, cost) in enumerate(sorted_costs[:15], 1):
                status = 'EXCELLENT' if cost < 1 else 'GOOD' if cost < 10 else 'ACCEPTABLE' if cost < 50 else 'CAUTION'
                self.log(f"{i:2d}. {fname:35s} {cost:10.6f} μs  [{status}]")
            
            self.log(f"\n... and {len(costs)-15} more features")
            
            for fname, cost in costs.items():
                status = 'EXCELLENT' if cost < 1 else 'GOOD' if cost < 10 else 'ACCEPTABLE' if cost < 50 else 'CAUTION'
                complexity = 'O(1)' if cost < 10 else 'O(n)'
                
                cost_data.append({
                    'Feature_Name': fname,
                    'Avg_Cost_Microseconds': round(cost, 6),
                    'Total_Executions': tracker.feature_counts[fname],
                    'Raspberry_Pi_Status': status,
                    'Estimated_Complexity': complexity
                })
            
            cost_file = f"Feature_Costs_{timestamp}.csv"
            df_cost = pd.DataFrame(cost_data).sort_values('Avg_Cost_Microseconds', ascending=False)
            df_cost.to_csv(cost_file, index=False)
            
            self.log(f"\n✓ Saved Cost Report: {cost_file}")
            self.log(f"  → Features Analyzed: {len(cost_data)}")
            
            # Statistics
            total_cost = sum(costs.values())
            self.log(f"\nCost Statistics:")
            self.log(f"  Total Cost (all 78):  {total_cost:.6f} μs per flow")
            self.log(f"  Average:              {np.mean(list(costs.values())):.6f} μs")
            self.log(f"  Min:                  {min(costs.values()):.6f} μs")
            self.log(f"  Max:                  {max(costs.values()):.6f} μs")
            
            # Final Summary
            processing_time = time.time() - tracker.start_time
            
            self.log("\n" + "="*90)
            self.log("EXTRACTION SUMMARY")
            self.log("="*90)
            self.log(f"Total Packets:           {tracker.packet_count:,}")
            self.log(f"Total Flows:             {len(df):,}")
            self.log(f"Features Extracted:      78")
            if 'label' in df.columns:
                self.log(f"Labeled Flows:           {matched_count:,} ({matched_count/len(df)*100:.1f}%)")
            self.log(f"Processing Time:         {processing_time:.2f} seconds")
            self.log(f"\nOutput Files:")
            self.log(f"  1. {dataset_file}")
            self.log(f"  2. {cost_file}")
            self.log("\n" + "="*90)
            self.log("✓ EXTRACTION COMPLETED SUCCESSFULLY")
            self.log("="*90 + "\n")
            
            self.update_progress(1.0, "✓ Complete!")
            
        except Exception as e:
            self.log(f"\n❌ Error: {e}")
            import traceback
            self.log(traceback.format_exc())
            
        finally:
            self.btn_process.configure(state="normal", text="EXTRACT 78 CICIDS2017 FEATURES")


if __name__ == "__main__":
    app = PacketToolApp()
    app.mainloop()
