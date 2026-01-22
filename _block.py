from dataclasses import dataclass, field, asdict
from typing import Dict, List
import time
import hashlib
import json
from datetime import datetime
import copy
import math

# 
from _crypto import (
	kdf_aes_key,
	dh_server_exchange,
	dh_client,
	aes_encrypt,
	aes_decrypt,
	validate_aes_channel,
	rsa_generate,
	rsa_sign,
	rsa_verify,
	data_enc
)
from _probe import *
import matplotlib.pyplot as plt
# 

# defines the state of the node's blockchain at a given point in time
_10m_slab_span = 1 # test purpose, set to 20 seconds
hour_slab_span = 6 #test purpose, set to 1 minute

@dataclass
class NodeBlock:
    ledger_id: str
    block_height: int
    timestamp: int = 0
    quorum_slice_id: str = ""
    _10m_block_hash: str = "0"*64
    _1hr_block_hash: str = "0"*64
    _1day_block_hash: str = "0"*64
    _1week_block_hash: str = "0"*64
    _1month_block_hash: str = "0"*64
    _1year_block_hash: str = "0"*64
    consumption_value_hash: str = ""                             # hash of the consumption value data
    slab_roots: Dict[str, list] = field(default_factory=lambda: {"10m": [], "1h": [], "1d": [], "1w": [], "1m": [], "1y": []})
    temp_readings: List[Dict] = field(default_factory=list)    # optional, can store readings temporarily

    def compute_10m_block_hash(self) -> str:
        block_content = {
            "ledger_id": self.ledger_id,
            "block_height": self.block_height,
            "prev_10m_block_hash": self._10m_block_hash,
            "quorum_slice_id": self.quorum_slice_id,
            "timestamp": self.timestamp,
            "consumption_value_hash": self.consumption_value_hash
        }
        block_bytes = json.dumps(block_content, sort_keys=True)
        self._10m_block_hash = data_enc(block_bytes)
        return self._10m_block_hash
    def compute_1h_block_hash(self) -> str:
        block_content = {
            "prev_1h_block_hash": self._1hr_block_hash,
            "block_height": self.block_height,
            "timestamp": self.timestamp,
            "10m_slab_root_hash": self._10m_block_hash
        }
        block_bytes = json.dumps(block_content, sort_keys=True)
        self._1hr_block_hash = data_enc(block_bytes)
        return self._1hr_block_hash

    #a method to print block details for debugging
    def print_block(self):
        # print(f"Block Height: {self.block_height}")
        # print(f"Ledger ID: {self.ledger_id}")
        # print(f"Timestamp: {self.timestamp}")
        # print(f"10m Block Hash: {self._10m_block_hash}")
        # print(f"1hr Block Hash: {self._1hr_block_hash}")
        # print(f"1day Block Hash: {self._1day_block_hash}")
        # print(f"1week Block Hash: {self._1week_block_hash}")
        # print(f"1month Block Hash: {self._1month_block_hash}")
        # print(f"1year Block Hash: {self._1year_block_hash}")
        # print(f"Consumption Value Hash: {self.consumption_value_hash}")
        # print(f"Quorum Slice ID: {self.quorum_slice_id}")
        print(f"Slab Roots: {self.slab_roots}\n\n")
        # print(f"Temporary Readings: {self.temp_readings}") 

hw = start_meter(base_rate=0.001, variability=0.00003)

block_height = 0
basic_slab_roots = {"10m": []}
opt_slab_roots = {"10m": [], "1h": [], "1d": [], "1w": [], "1m": [], "1y": []}
# prev_block = None

# Misc --- START
def block_to_dict(block, seen=None):
    # Prevent infinite recursion by tracking already visited objects
    if seen is None:
        seen = set()
    if id(block) in seen:
        # Instead of recursing, just return a reference or minimal info
        return {
            "ledger_id": block.ledger_id,
            "block_height": block.block_height,
            "timestamp": block.timestamp,
            "_10m_block_hash": block._10m_block_hash
        }
    seen.add(id(block))
    # Manually build the dict to avoid asdict's recursion
    d = {
        "ledger_id": block.ledger_id,
        "block_height": block.block_height,
        "timestamp": block.timestamp,
        "quorum_slice_id": block.quorum_slice_id,
        "_10m_block_hash": block._10m_block_hash,
        "_1hr_block_hash": block._1hr_block_hash,
        "_1day_block_hash": block._1day_block_hash,
        "_1week_block_hash": block._1week_block_hash,
        "_1month_block_hash": block._1month_block_hash,
        "_1year_block_hash": block._1year_block_hash,
        "consumption_value_hash": block.consumption_value_hash,
        "slab_roots": {},
        "temp_readings": block.temp_readings,
    }
    for slab, blocks in block.slab_roots.items():
        d['slab_roots'][slab] = [
            block_to_dict(b, seen) if isinstance(b, NodeBlock) else b for b in blocks
        ]
    return d

def plot_optimization_comparison(data):
    """
    Plots 'size' vs 'time' for both optimized and non-optimized data.
    Handles cases where one or both datasets are empty or missing.
    """
    with_opt = data.get('with_optimization', {})
    without_opt = data.get('without_optimization', {})

    # Check if there is any data to plot at all
    has_with = with_opt.get('size') and with_opt.get('time')
    has_without = without_opt.get('size') and without_opt.get('time')

    if not has_with and not has_without:
        print("No data available to plot.")
        return

    # Find the global minimum time to normalize the X-axis to 0
    all_times = []
    if has_with: all_times.extend(with_opt['time'])
    if has_without: all_times.extend(without_opt['time'])
    
    base_time = min(all_times)

    plt.figure(figsize=(10, 6))

    # Plot 'With Optimization' if data exists
    if has_with:
        time_w = [t - base_time for t in with_opt['time']]
        plt.plot(time_w, with_opt['size'], label='With Optimization', 
                 marker='o', linestyle='-', color='blue', linewidth=2)

    # Plot 'Without Optimization' if data exists
    if has_without:
        time_wo = [t - base_time for t in without_opt['time']]
        plt.plot(time_wo, without_opt['size'], label='Without Optimization', 
                 marker='s', linestyle='--', color='red', linewidth=2)

    # Graph Formatting
    plt.xlabel('Time (Relative Seconds)', fontsize=12)
    plt.ylabel('Size', fontsize=12)
    plt.title('Performance Comparison: Optimization Analysis', fontsize=14)
    
    # Only show legend if we have at least one valid dataset
    plt.legend()
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.tight_layout()

    # Save/Show
    plt.savefig('optimization_plot.png')
    print("Plot generated successfully.")
# Misc --- END

comparison_matrix = {"with_optimization": {"size":[], "time":[]}, "without_optimization": {"size":[], "time":[]}}
while block_height<=200:
    METER_READING_DATA = read_meter(hw)
    # if prev_block is not None:
    #     slab_roots['10m'].append(prev_block)
    read_time = int(datetime.fromisoformat(METER_READING_DATA['timestamp']).timestamp())
    
    # Unoptimized
    basic_block = NodeBlock(
        ledger_id="b_62DKxsTsk7cwGLmO",
        block_height=block_height,
        timestamp=read_time,
        quorum_slice_id="b_62DKxsTsk7cwGLmO",
        consumption_value_hash=data_enc(METER_READING_DATA['value']),
        slab_roots=basic_slab_roots,
        temp_readings=[METER_READING_DATA]
    )
    basic_block.compute_10m_block_hash()

    basic_block.slab_roots['10m'].append(basic_block)

    # basic_block.print_block()

    block_data = json.dumps(block_to_dict(basic_block)).encode('utf-8')
    # print(f"Unoptimized Block size: {len(block_data)/1024:.2f} KB\n")
    
    comparison_matrix["without_optimization"]["size"].append(len(block_data)/1024)
    comparison_matrix["without_optimization"]["time"].append(read_time)

    # Optimized
    opt_block = NodeBlock(
        ledger_id="b_62DKxsTsk7cwGLmO",
        block_height=block_height,
        timestamp=read_time,
        quorum_slice_id="b_62DKxsTsk7cwGLmO",
        consumption_value_hash=data_enc(METER_READING_DATA['value']),
        slab_roots=opt_slab_roots,
        temp_readings=[METER_READING_DATA]
    )
    opt_block.compute_10m_block_hash()

    opt_block.slab_roots['10m'].append(opt_block)

    if len(opt_block.slab_roots["10m"]) >= 2 and opt_block.slab_roots["10m"][-1].timestamp - opt_block.slab_roots["10m"][0].timestamp >= hour_slab_span:
        print(f"********* Hour slab completed")
        opt_block.compute_1h_block_hash()
        opt_slab_roots['1h'].append(opt_block)
        opt_block.slab_roots['10m'] = [opt_block.slab_roots['10m'][-1]]

    # opt_block.print_block()
    
    block_data = json.dumps(block_to_dict(opt_block)).encode('utf-8')
    # print(f"Optimized Block size: {len(block_data)/1024:.2f} KB\n")
    
    comparison_matrix["with_optimization"]["size"].append(len(block_data)/1024)
    comparison_matrix["with_optimization"]["time"].append(read_time)
    
    
    block_height += 1
    time.sleep(_10m_slab_span)



plot_optimization_comparison(comparison_matrix)


