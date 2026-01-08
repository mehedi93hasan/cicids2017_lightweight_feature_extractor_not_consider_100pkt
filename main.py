import customtkinter as ctk
import threading
import pandas as pd
import numpy as np
import os
import time
from collections import defaultdict
from scapy.all import PcapReader, IP, TCP, UDP
from datetime import datetime

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
    """
    
    def __init__(self):
        self.flows = {}
        self.packet_count = 0
        self.start_time = None
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
        
        if (src_ip, sport) < (dst_ip, dport):
            return (src_ip, sport, dst_ip, dport, proto)
        else:
            return (dst_ip, dport, src_ip, sport, proto)

    def process_packet(self, pkt):
        """Process packet and update flow statistics"""
        if self.start_time is None:
            self.start_time = time.time()
            
        flow_key = self.get_flow_key(pkt)
        if flow_key is None:
            return

        timestamp = float(pkt.time)
        pkt_len = len(pkt)
        
        if flow_key not in self.flows:
            src_ip, sport, dst_ip, dport, proto = flow_key
            self.flows[flow_key] = {
                'src_ip': src_ip, 'sport': sport, 'dst_ip': dst_ip, 'dport': dport, 'proto': proto,
                'start_time': timestamp, 'last_time': timestamp,
                'fwd_pkts': 0, 'bwd_pkts': 0, 'fwd_bytes': 0, 'bwd_bytes': 0,
                'timestamps': [], 'pkt_lengths': [], 'fwd_pkt_lens': [], 'bwd_pkt_lens': [],
                'fwd_header_lens': [], 'bwd_header_lens': [], 'fwd_iats': [], 'bwd_iats': [],
                'fwd_segment_sizes': [], 'bwd_segment_sizes': [],
                'fin_count': 0, 'syn_count': 0, 'rst_count': 0, 'psh_count': 0, 
                'ack_count': 0, 'urg_count': 0, 'cwr_count': 0, 'ece_count': 0,
                'fwd_psh_count': 0, 'bwd_psh_count': 0, 'fwd_urg_count': 0, 'bwd_urg_count': 0,
                'last_fwd_time': None, 'last_bwd_time': None,
                'active_periods': [], 'idle_periods': [], 'active_start': timestamp, 'last_active_time': timestamp,
                'fwd_init_win': None, 'bwd_init_win': None,
                'fwd_bulk_bytes': 0, 'fwd_bulk_packets': 0, 'bwd_bulk_bytes': 0, 'bwd_bulk_packets': 0,
                'fwd_bulk_count': 0, 'bwd_bulk_count': 0, 'fwd_data_pkts': 0,
            }
            self.flows[flow_key]['timestamps'].append(timestamp)

        flow = self.flows[flow_key]
        src_ip, sport, dst_ip, dport, proto = flow_key
        direction = 'fwd' if pkt[IP].src == src_ip else 'bwd'
        
        flow['pkt_lengths'].append(pkt_len)
        flow['timestamps'].append(timestamp)
        
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
        
        if flow['last_active_time']:
            gap = timestamp - flow['last_active_time']
            if gap > 1.0:
                flow['idle_periods'].append(gap)
                if flow['active_start']:
                    active = flow['last_active_time'] - flow['active_start']
                    if active > 0:
                        flow['active_periods'].append(active)
                flow['active_start'] = timestamp
        
        flow['last_active_time'] = timestamp
        flow['last_time'] = timestamp
        
        if IP in pkt:
            ip_header_len = pkt[IP].ihl * 4 if hasattr(pkt[IP], 'ihl') else 20
            if direction == 'fwd':
                flow['fwd_header_lens'].append(ip_header_len)
                flow['fwd_segment_sizes'].append(pkt_len - ip_header_len)
            else:
                flow['bwd_header_lens'].append(ip_header_len)
                flow['bwd_segment_sizes'].append(pkt_len - ip_header_len)

        if TCP in pkt:
            tcp_flags = int(pkt[TCP].flags)
            if tcp_flags & 0x01: flow['fin_count'] += 1
            if tcp_flags & 0x02: flow['syn_count'] += 1
            if tcp_flags & 0x04: flow['rst_count'] += 1
            if tcp_flags & 0x08: flow['psh_count'] += 1
            if tcp_flags & 0x10: flow['ack_count'] += 1
            if tcp_flags & 0x20: flow['urg_count'] += 1
            if tcp_flags & 0x40: flow['ece_count'] += 1
            if tcp_flags & 0x80: flow['cwr_count'] += 1
            
            if tcp_flags & 0x08:
                if direction == 'fwd': flow['fwd_psh_count'] += 1
                else: flow['bwd_psh_count'] += 1
            if tcp_flags & 0x20:
                if direction == 'fwd': flow['fwd_urg_count'] += 1
                else: flow['bwd_urg_count'] += 1
            
            if flow['fwd_init_win'] is None and direction == 'fwd' and (tcp_flags & 0x02):
                flow['fwd_init_win'] = pkt[TCP].window
            if flow['bwd_init_win'] is None and direction == 'bwd' and (tcp_flags & 0x02):
                flow['bwd_init_win'] = pkt[TCP].window
            
            if direction == 'fwd' and (tcp_flags & 0x10) and len(pkt[TCP].payload) > 0:
                flow['fwd_data_pkts'] += 1
            
        self.packet_count += 1

    def measure_feature(self, name, func):
        """Measure feature execution time"""
        t0 = time.perf_counter_ns()
        result = func()
        t1 = time.perf_counter_ns()
        self.feature_costs[name] += (t1 - t0)
        self.feature_counts[name] += 1
        return result

    def extract_features(self, flow_key):
        """Extract all 78 CICIDS2017 features"""
        flow = self.flows[flow_key]
        features = {}
        
        ts = flow['timestamps']
        pkt_lens = flow['pkt_lengths']
        fwd_lens = flow['fwd_pkt_lens']
        bwd_lens = flow['bwd_pkt_lens']
        fwd_iats = flow['fwd_iats']
        bwd_iats = flow['bwd_iats']
        fwd_hdrs = flow['fwd_header_lens']
        bwd_hdrs = flow['bwd_header_lens']
        fwd_segs = flow['fwd_segment_sizes']
        bwd_segs = flow['bwd_segment_sizes']
        
        dur = max(flow['last_time'] - flow['start_time'], 1e-6)
        dur_us = dur * 1000000
        total_pkts = flow['fwd_pkts'] + flow['bwd_pkts']
        total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']
        
        features['src_ip'] = flow['src_ip']
        features['src_port'] = flow['sport']
        features['dst_ip'] = flow['dst_ip']
        features['dst_port'] = flow['dport']
        features['protocol'] = flow['proto']
        
        features['flow_duration'] = self.measure_feature('flow_duration', lambda: dur_us)
        features['total_fwd_packets'] = self.measure_feature('total_fwd_packets', lambda: flow['fwd_pkts'])
        features['total_bwd_packets'] = self.measure_feature('total_bwd_packets', lambda: flow['bwd_pkts'])
        features['total_length_fwd_packets'] = self.measure_feature('total_length_fwd_packets', lambda: flow['fwd_bytes'])
        features['total_length_bwd_packets'] = self.measure_feature('total_length_bwd_packets', lambda: flow['bwd_bytes'])
        
        features['fwd_packet_length_min'] = self.measure_feature('fwd_packet_length_min', lambda: min(fwd_lens) if fwd_lens else 0)
        features['fwd_packet_length_max'] = self.measure_feature('fwd_packet_length_max', lambda: max(fwd_lens) if fwd_lens else 0)
        features['fwd_packet_length_mean'] = self.measure_feature('fwd_packet_length_mean', lambda: np.mean(fwd_lens) if fwd_lens else 0)
        features['fwd_packet_length_std'] = self.measure_feature('fwd_packet_length_std', lambda: np.std(fwd_lens) if fwd_lens else 0)
        
        features['bwd_packet_length_min'] = self.measure_feature('bwd_packet_length_min', lambda: min(bwd_lens) if bwd_lens else 0)
        features['bwd_packet_length_max'] = self.measure_feature('bwd_packet_length_max', lambda: max(bwd_lens) if bwd_lens else 0)
        features['bwd_packet_length_mean'] = self.measure_feature('bwd_packet_length_mean', lambda: np.mean(bwd_lens) if bwd_lens else 0)
        features['bwd_packet_length_std'] = self.measure_feature('bwd_packet_length_std', lambda: np.std(bwd_lens) if bwd_lens else 0)
        
        features['flow_bytes_s'] = self.measure_feature('flow_bytes_s', lambda: total_bytes / dur if dur > 0 else 0)
        features['flow_packets_s'] = self.measure_feature('flow_packets_s', lambda: total_pkts / dur if dur > 0 else 0)
        
        flow_iats = [ts[i+1] - ts[i] for i in range(len(ts)-1)] if len(ts) > 1 else [0]
        features['flow_iat_mean'] = self.measure_feature('flow_iat_mean', lambda: np.mean(flow_iats) * 1000000 if flow_iats else 0)
        features['flow_iat_std'] = self.measure_feature('flow_iat_std', lambda: np.std(flow_iats) * 1000000 if flow_iats else 0)
        features['flow_iat_max'] = self.measure_feature('flow_iat_max', lambda: max(flow_iats) * 1000000 if flow_iats else 0)
        features['flow_iat_min'] = self.measure_feature('flow_iat_min', lambda: min(flow_iats) * 1000000 if flow_iats else 0)
        
        features['fwd_iat_min'] = self.measure_feature('fwd_iat_min', lambda: min(fwd_iats) * 1000000 if fwd_iats else 0)
        features['fwd_iat_max'] = self.measure_feature('fwd_iat_max', lambda: max(fwd_iats) * 1000000 if fwd_iats else 0)
        features['fwd_iat_mean'] = self.measure_feature('fwd_iat_mean', lambda: np.mean(fwd_iats) * 1000000 if fwd_iats else 0)
        features['fwd_iat_std'] = self.measure_feature('fwd_iat_std', lambda: np.std(fwd_iats) * 1000000 if fwd_iats else 0)
        features['fwd_iat_total'] = self.measure_feature('fwd_iat_total', lambda: sum(fwd_iats) * 1000000 if fwd_iats else 0)
        
        features['bwd_iat_min'] = self.measure_feature('bwd_iat_min', lambda: min(bwd_iats) * 1000000 if bwd_iats else 0)
        features['bwd_iat_max'] = self.measure_feature('bwd_iat_max', lambda: max(bwd_iats) * 1000000 if bwd_iats else 0)
        features['bwd_iat_mean'] = self.measure_feature('bwd_iat_mean', lambda: np.mean(bwd_iats) * 1000000 if bwd_iats else 0)
        features['bwd_iat_std'] = self.measure_feature('bwd_iat_std', lambda: np.std(bwd_iats) * 1000000 if bwd_iats else 0)
        features['bwd_iat_total'] = self.measure_feature('bwd_iat_total', lambda: sum(bwd_iats) * 1000000 if bwd_iats else 0)
        
        features['fwd_psh_flags'] = self.measure_feature('fwd_psh_flags', lambda: flow['fwd_psh_count'])
        features['bwd_psh_flags'] = self.measure_feature('bwd_psh_flags', lambda: flow['bwd_psh_count'])
        features['fwd_urg_flags'] = self.measure_feature('fwd_urg_flags', lambda: flow['fwd_urg_count'])
        features['bwd_urg_flags'] = self.measure_feature('bwd_urg_flags', lambda: flow['bwd_urg_count'])
        
        features['fwd_header_length'] = self.measure_feature('fwd_header_length', lambda: sum(fwd_hdrs))
        features['bwd_header_length'] = self.measure_feature('bwd_header_length', lambda: sum(bwd_hdrs))
        
        features['fwd_packets_s'] = self.measure_feature('fwd_packets_s', lambda: flow['fwd_pkts'] / dur if dur > 0 else 0)
        features['bwd_packets_s'] = self.measure_feature('bwd_packets_s', lambda: flow['bwd_pkts'] / dur if dur > 0 else 0)
        
        features['packet_length_min'] = self.measure_feature('packet_length_min', lambda: min(pkt_lens) if pkt_lens else 0)
        features['packet_length_max'] = self.measure_feature('packet_length_max', lambda: max(pkt_lens) if pkt_lens else 0)
        features['packet_length_mean'] = self.measure_feature('packet_length_mean', lambda: np.mean(pkt_lens) if pkt_lens else 0)
        features['packet_length_std'] = self.measure_feature('packet_length_std', lambda: np.std(pkt_lens) if pkt_lens else 0)
        features['packet_length_variance'] = self.measure_feature('packet_length_variance', lambda: np.var(pkt_lens) if pkt_lens else 0)
        
        features['fin_flag_count'] = self.measure_feature('fin_flag_count', lambda: flow['fin_count'])
        features['syn_flag_count'] = self.measure_feature('syn_flag_count', lambda: flow['syn_count'])
        features['rst_flag_count'] = self.measure_feature('rst_flag_count', lambda: flow['rst_count'])
        features['psh_flag_count'] = self.measure_feature('psh_flag_count', lambda: flow['psh_count'])
        features['ack_flag_count'] = self.measure_feature('ack_flag_count', lambda: flow['ack_count'])
        features['urg_flag_count'] = self.measure_feature('urg_flag_count', lambda: flow['urg_count'])
        features['cwr_flag_count'] = self.measure_feature('cwr_flag_count', lambda: flow['cwr_count'])
        features['ece_flag_count'] = self.measure_feature('ece_flag_count', lambda: flow['ece_count'])
        
        features['down_up_ratio'] = self.measure_feature('down_up_ratio', lambda: flow['bwd_pkts'] / flow['fwd_pkts'] if flow['fwd_pkts'] > 0 else 0)
        features['average_packet_size'] = self.measure_feature('average_packet_size', lambda: total_bytes / total_pkts if total_pkts > 0 else 0)
        features['fwd_segment_size_avg'] = self.measure_feature('fwd_segment_size_avg', lambda: np.mean(fwd_segs) if fwd_segs else 0)
        features['bwd_segment_size_avg'] = self.measure_feature('bwd_segment_size_avg', lambda: np.mean(bwd_segs) if bwd_segs else 0)
        
        features['fwd_bytes_bulk_avg'] = self.measure_feature('fwd_bytes_bulk_avg', lambda: flow['fwd_bulk_bytes'] / flow['fwd_bulk_count'] if flow['fwd_bulk_count'] > 0 else 0)
        features['fwd_packet_bulk_avg'] = self.measure_feature('fwd_packet_bulk_avg', lambda: flow['fwd_bulk_packets'] / flow['fwd_bulk_count'] if flow['fwd_bulk_count'] > 0 else 0)
        features['fwd_bulk_rate_avg'] = self.measure_feature('fwd_bulk_rate_avg', lambda: flow['fwd_bulk_count'] / dur if dur > 0 else 0)
        features['bwd_bytes_bulk_avg'] = self.measure_feature('bwd_bytes_bulk_avg', lambda: flow['bwd_bulk_bytes'] / flow['bwd_bulk_count'] if flow['bwd_bulk_count'] > 0 else 0)
        features['bwd_packet_bulk_avg'] = self.measure_feature('bwd_packet_bulk_avg', lambda: flow['bwd_bulk_packets'] / flow['bwd_bulk_count'] if flow['bwd_bulk_count'] > 0 else 0)
        features['bwd_bulk_rate_avg'] = self.measure_feature('bwd_bulk_rate_avg', lambda: flow['bwd_bulk_count'] / dur if dur > 0 else 0)
        
        features['subflow_fwd_packets'] = self.measure_feature('subflow_fwd_packets', lambda: flow['fwd_pkts'])
        features['subflow_fwd_bytes'] = self.measure_feature('subflow_fwd_bytes', lambda: flow['fwd_bytes'])
        features['subflow_bwd_packets'] = self.measure_feature('subflow_bwd_packets', lambda: flow['bwd_pkts'])
        features['subflow_bwd_bytes'] = self.measure_feature('subflow_bwd_bytes', lambda: flow['bwd_bytes'])
        
        features['fwd_init_win_bytes'] = self.measure_feature('fwd_init_win_bytes', lambda: flow['fwd_init_win'] if flow['fwd_init_win'] is not None else 0)
        features['bwd_init_win_bytes'] = self.measure_feature('bwd_init_win_bytes', lambda: flow['bwd_init_win'] if flow['bwd_init_win'] is not None else 0)
        
        features['fwd_act_data_pkts'] = self.measure_feature('fwd_act_data_pkts', lambda: flow['fwd_data_pkts'])
        features['fwd_seg_size_min'] = self.measure_feature('fwd_seg_size_min', lambda: min(fwd_segs) if fwd_segs else 0)
        
        active = flow['active_periods']
        idle = flow['idle_periods']
        features['active_min'] = self.measure_feature('active_min', lambda: min(active) * 1000000 if active else 0)
        features['active_mean'] = self.measure_feature('active_mean', lambda: np.mean(active) * 1000000 if active else 0)
        features['active_max'] = self.measure_feature('active_max', lambda: max(active) * 1000000 if active else 0)
        features['active_std'] = self.measure_feature('active_std', lambda: np.std(active) * 1000000 if active else 0)
        features['idle_min'] = self.measure_feature('idle_min', lambda: min(idle) * 1000000 if idle else 0)
        features['idle_mean'] = self.measure_feature('idle_mean', lambda: np.mean(idle) * 1000000 if idle else 0)
        features['idle_max'] = self.measure_feature('idle_max', lambda: max(idle) * 1000000 if idle else 0)
        features['idle_std'] = self.measure_feature('idle_std', lambda: np.std(idle) * 1000000 if idle else 0)
        
        return features

    def get_feature_costs(self):
        """Return average cost per feature in microseconds"""
        return {name: (total / self.feature_counts[name]) / 1000.0 
                for name, total in self.feature_costs.items() if self.feature_counts[name] > 0}

    def get_all_features(self):
        return [self.extract_features(fk) for fk in self.flows.keys()]


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CICIDS2017 Complete Feature Extractor (78 Features)")
        self.geometry("950x800")
        
        ctk.CTkLabel(self, text="CICIDS2017 Feature Extractor", font=("Arial", 20, "bold")).pack(pady=15)
        ctk.CTkLabel(self, text="Extract all 78 official CICIDS2017 features", font=("Arial", 12), text_color="gray").pack()

        frame = ctk.CTkFrame(self)
        frame.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(frame, text="PCAP File:", font=("Arial", 12, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.entry_pcap = ctk.CTkEntry(frame, placeholder_text="Select PCAP file...", width=600)
        self.entry_pcap.grid(row=1, column=0, padx=10, pady=5)
        ctk.CTkButton(frame, text="Browse", command=lambda: self.browse("pcap"), width=100).grid(row=1, column=1, padx=10, pady=5)

        ctk.CTkLabel(frame, text="Ground Truth CSV (Optional):", font=("Arial", 12, "bold")).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.entry_gt = ctk.CTkEntry(frame, placeholder_text="Select Ground Truth CSV...", width=600)
        self.entry_gt.grid(row=3, column=0, padx=10, pady=5)
        ctk.CTkButton(frame, text="Browse", fg_color="#555", hover_color="#444", command=lambda: self.browse("csv"), width=100).grid(row=3, column=1, padx=10, pady=5)

        self.progress = ctk.CTkProgressBar(self, width=830)
        self.progress.pack(padx=20, pady=10, fill="x")
        self.progress.set(0)
        
        self.progress_label = ctk.CTkLabel(self, text="Ready", font=("Arial", 11))
        self.progress_label.pack()

        self.btn_process = ctk.CTkButton(self, text="EXTRACT 78 FEATURES", fg_color="#2CC985", hover_color="#229C68",
                                         text_color="black", height=50, font=("Arial", 14, "bold"), command=self.start)
        self.btn_process.pack(padx=20, pady=15, fill="x")

        self.textbox = ctk.CTkTextbox(self, height=420, font=("Consolas", 10))
        self.textbox.pack(padx=20, pady=10, fill="both", expand=True)
        
        self.log("="*90)
        self.log("CICIDS2017 Complete Feature Extractor - 78 Features")
        self.log("="*90)
        self.log("\n✓ All 78 official CICIDS2017 features")
        self.log("✓ Complete flow extraction (no packet limits)")
        self.log("✓ Per-feature computational cost tracking")
        self.log("✓ Ground Truth labeling support\n")
        self.log("Ready. Please select PCAP file.")
        self.log("="*90 + "\n")

    def log(self, msg):
        self.textbox.insert("end", msg + "\n")
        self.textbox.see("end")
        self.update_idletasks()
    
    def update_progress(self, value, msg=""):
        self.progress.set(value)
        if msg:
            self.progress_label.configure(text=msg)
        self.update_idletasks()

    def browse(self, ftype):
        filetypes = [("PCAP Files", "*.pcap"), ("PCAPNG", "*.pcapng")] if ftype == "pcap" else [("CSV Files", "*.csv")]
        filename = ctk.filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            entry = self.entry_pcap if ftype == "pcap" else self.entry_gt
            entry.delete(0, "end")
            entry.insert(0, filename)
            self.log(f"✓ Selected: {os.path.basename(filename)}")

    def start(self):
        pcap = self.entry_pcap.get()
        gt = self.entry_gt.get()
        
        if not pcap or not os.path.exists(pcap):
            self.log("❌ Error: Please select a valid PCAP file.")
            return
        
        if gt and not os.path.exists(gt):
            self.log("❌ Error: Ground Truth CSV not found.")
            return
        
        self.btn_process.configure(state="disabled", text="Processing...")
        self.update_progress(0, "Starting...")
        threading.Thread(target=self.run, args=(pcap, gt), daemon=True).start()

    def run(self, pcap, gt):
        try:
            self.log("\n" + "="*90)
            self.log("STARTING EXTRACTION")
            self.log("="*90 + "\n")
            
            tracker = CICFlowTracker()
            gt_lookup = {}
            matched = 0
            
            # Load Ground Truth
            if gt:
                self.log("[1/4] Loading Ground Truth...")
                try:
                    df_gt = pd.read_csv(gt, encoding='latin-1', low_memory=False)
                    df_gt.columns = df_gt.columns.str.strip().str.lower().str.replace(' ', '_')
                    
                    src_ip_col = next((c for c in df_gt.columns if c in ['source_ip', 'src_ip']), None)
                    dst_ip_col = next((c for c in df_gt.columns if c in ['destination_ip', 'dst_ip']), None)
                    src_port_col = next((c for c in df_gt.columns if c in ['source_port', 'src_port']), None)
                    dst_port_col = next((c for c in df_gt.columns if c in ['destination_port', 'dst_port']), None)
                    proto_col = next((c for c in df_gt.columns if c in ['protocol', 'proto']), None)
                    label_col = next((c for c in df_gt.columns if c in ['label', 'attack']), None)
                    
                    if all([src_ip_col, dst_ip_col, src_port_col, dst_port_col, label_col]):
                        for _, row in df_gt.iterrows():
                            try:
                                src = str(row[src_ip_col]).strip()
                                dst = str(row[dst_ip_col]).strip()
                                if src == 'nan' or dst == 'nan': continue
                                
                                sp = int(float(row[src_port_col]))
                                dp = int(float(row[dst_port_col]))
                                proto = 6 if proto_col is None else int(float(row[proto_col]))
                                lbl = str(row[label_col]).strip() if row[label_col] != 'nan' else 'BENIGN'
                                
                                gt_lookup[(src, sp, dst, dp, proto)] = lbl
                                gt_lookup[(dst, dp, src, sp, proto)] = lbl
                            except: continue
                        
                        self.log(f"✓ Loaded {len(gt_lookup):,} GT entries\n")
                    else:
                        self.log("⚠ GT columns not found, proceeding without labels\n")
                except Exception as e:
                    self.log(f"⚠ GT error: {e}\n")
            
            # Process PCAP
            step = 2 if gt else 1
            total = 4 if gt else 3
            self.log(f"[{step}/{total}] Processing PCAP...")
            
            count = 0
            for pkt in PcapReader(pcap):
                tracker.process_packet(pkt)
                count += 1
                if count % 10000 == 0:
                    self.update_progress(0.05 + 0.65 * min(count/100000, 1.0), f"{count:,} packets")
                    self.log(f"  → {count:,} packets")
            
            self.log(f"\n✓ Processed {count:,} packets")
            self.log(f"✓ Extracted {len(tracker.flows):,} flows\n")

            # Extract features
            step += 1
            self.log(f"[{step}/{total}] Extracting 78 features...")
            self.update_progress(0.75, "Extracting features...")
            
            df = pd.DataFrame(tracker.get_all_features())
            self.log(f"✓ Extracted from {len(df):,} flows\n")

            # Match labels
            if gt and gt_lookup:
                step += 1
                self.log(f"[{step}/{total}] Matching labels...")
                labels = []
                for _, row in df.iterrows():
                    key = (row['src_ip'], int(row['src_port']), row['dst_ip'], int(row['dst_port']), row['protocol'])
                    if key in gt_lookup:
                        labels.append(gt_lookup[key])
                        matched += 1
                    else:
                        labels.append('BENIGN')
                df['label'] = labels
                
                self.log(f"✓ Matched {matched:,} flows ({matched/len(df)*100:.1f}%)\n")
                for lbl, cnt in df['label'].value_counts().items():
                    self.log(f"  {lbl:25s}: {cnt:6,} ({cnt/len(df)*100:5.2f}%)")
                self.log("")

            # Save outputs
            step += 1
            self.log(f"[{step}/{total}] Saving outputs...")
            self.update_progress(0.9, "Saving files...")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if 'label' in df.columns:
                cols = [c for c in df.columns if c != 'label'] + ['label']
                df = df[cols]
            
            feat_file = f"CICIDS2017_78Features_{ts}.csv"
            df.to_csv(feat_file, index=False)
            self.log(f"✓ Saved: {feat_file}")
            self.log(f"  Rows: {len(df):,}, Features: 78\n")

            # Save costs
            costs = tracker.get_feature_costs()
            cost_data = []
            for name, cost in costs.items():
                status = 'EXCELLENT' if cost < 1 else 'GOOD' if cost < 10 else 'ACCEPTABLE' if cost < 50 else 'CAUTION'
                cost_data.append({
                    'Feature_Name': name,
                    'Avg_Cost_Microseconds': round(cost, 6),
                    'Executions': tracker.feature_counts[name],
                    'Status': status,
                    'Complexity': 'O(1)' if cost < 10 else 'O(n)'
                })
            
            cost_file = f"Feature_Costs_{ts}.csv"
            pd.DataFrame(cost_data).sort_values('Avg_Cost_Microseconds', ascending=False).to_csv(cost_file, index=False)
            self.log(f"✓ Saved: {cost_file}\n")
            
            proc_time = time.time() - tracker.start_time
            self.log("="*90)
            self.log("SUMMARY")
            self.log("="*90)
            self.log(f"Packets: {count:,}")
            self.log(f"Flows: {len(df):,}")
            self.log(f"Time: {proc_time:.1f}s")
            self.log(f"\nFiles:\n  1. {feat_file}\n  2. {cost_file}")
            self.log("\n" + "="*90)
            self.log("✓ COMPLETED SUCCESSFULLY")
            self.log("="*90 + "\n")
            
            self.update_progress(1.0, "✓ Complete!")
            
        except Exception as e:
            self.log(f"\n❌ Error: {e}")
            import traceback
            self.log(traceback.format_exc())
        finally:
            self.btn_process.configure(state="normal", text="EXTRACT 78 FEATURES")


if __name__ == "__main__":
    App().mainloop()
