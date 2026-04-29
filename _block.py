from dataclasses import dataclass, field, asdict
from typing import Dict, List
import time
import hashlib
import json
from datetime import datetime
import copy
import math
import sys

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
_10m_slab_span = 0.001 # with respect to the time span
hour_slab_span = 6 # with respect to the 10 mins slab
day_slab_span = 24 # with respect to the hr slab
# week_slab_span = 7 # with respect to the day slab
month_slab_span = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] # with respect to the day slab
year_slab_span = 12 # with respect to the month slab

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
    # print(data)
    with_opt = data.get('with_optimization', {})
    without_opt = data.get('without_optimization', {})

    has_with = with_opt.get('size') and with_opt.get('time')
    has_without = without_opt.get('size') and without_opt.get('time')

    if not has_with and not has_without:
        print("No data available to plot.")
        return

    # Normalize time axis
    all_times = []
    if has_with:
        all_times.extend(with_opt['time'])
    if has_without:
        all_times.extend(without_opt['time'])

    base_time = min(all_times)

    plt.figure(figsize=(9, 5))

    # With optimization (thinner)
    if has_with:
        time_w = [t - base_time for t in with_opt['time']]
        plt.plot(
            time_w,
            with_opt['size'],
            label='With Optimization',
            color='blue',
            linewidth=1.2,
            marker='o',
            markersize=2,
            alpha=0.9
        )

    # Without optimization (thinner)
    if has_without:
        time_wo = [t - base_time for t in without_opt['time']]
        plt.plot(
            time_wo,
            without_opt['size'],
            label='Without Optimization',
            color='red',
            linestyle='--',
            linewidth=1.2,
            marker='s',
            markersize=2,
            alpha=0.9
        )

    # Formatting
    plt.xlabel('Time (Relative 10 mins)', fontsize=11)
    plt.ylabel('Size in Bytes', fontsize=11)
    plt.title('Performance Comparison: Optimization Analysis', fontsize=13)

    plt.legend(frameon=False)
    plt.grid(True, linestyle=':', linewidth=0.6, alpha=0.5)
    plt.tight_layout()

    plt.savefig('optimization_plot.png', dpi=300)
    print("Plot generated successfully.")
# Misc --- END

comparison_matrix = {"with_optimization": {"size":[], "time":[]}, "without_optimization": {"size":[], "time":[]}}
while block_height<=200 and False:
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

# plot_optimization_comparison(comparison_matrix)

# RAM usage
def get_deep_size(obj, seen=None):
    size = sys.getsizeof(obj)
    if seen is None: seen = set()
    obj_id = id(obj)
    if obj_id in seen: return 0
    seen.add(obj_id)

    if isinstance(obj, dict):
        size += sum([get_deep_size(v, seen) + get_deep_size(k, seen) for k, v in obj.items()])
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_deep_size(i, seen) for i in obj])
    return size

basic_ledger = {
    "ledger_id": None,
    "quorum_slice_id": None,
    "block_height": 0,
    "last_timestamp": 0,
    "consumption_value_hash": None,
    "current_10m_hash_value": None,
    "slab_roots": {
        "10mi":[]
    },
    "temp_readings":{}
}

opt_ledger = {
    "ledger_id": None,
    "quorum_slice_id": None,
    "block_height": 0,
    "last_timestamp": 0,
    "consumption_value_hash": None,
    "current_10m_hash_value": None,
    "current_1h_hash_value": None,
    "slab_roots": {
        "10mi":[],
        "1h":[],
        "1d":[],
        "1m":[],
        "1y":[]
    },
    "temp_readings":{}
}

local_ledger = copy.deepcopy(basic_ledger)
local_ledger["ledger_id"]="b_62DKxsTsk7cwGLmO"
local_ledger["quorum_slice_id"]="b_62DKxsTsk7cwGLmO"
prev_10m_block_hash_="0"*64
block_height_ = 0


local_opt_ledger = copy.deepcopy(opt_ledger)
local_opt_ledger["ledger_id"]="b_62DKxsTsk7cwGLmO"
local_opt_ledger["quorum_slice_id"]="b_62DKxsTsk7cwGLmO"
prev_10m_block_hash, prev_1h_block_hash, prev_1d_block_hash, prev_1m_block_hash, prev_1y_block_hash = ["0"*64,"0"*64,"0"*64,"0"*64,"0"*64]
block_height = 0

month_counter = 0
while block_height<10000:
    METER_READING_DATA = read_meter(hw)
    read_time = (datetime.fromisoformat(METER_READING_DATA['timestamp']).timestamp())

    # Operation for basic ledger - START
    block_content={
        "ledger_id": local_ledger["ledger_id"],
        "quorum_slice_id": local_ledger["quorum_slice_id"],
        "block_height": block_height_,
        "timestamp": read_time,
        "consumption_value_hash": data_enc(METER_READING_DATA['value']),
        "prev_10m_block_hash": prev_10m_block_hash_
    }
    prev_10m_block_hash_ = data_enc(block_content)
    local_ledger["slab_roots"]["10mi"].append(block_content)
    # updating the principle values
    block_height_+=1
    local_ledger["block_height"]=block_height_
    local_ledger["last_timestamp"]=read_time
    local_ledger["consumption_value_hash"]=data_enc(METER_READING_DATA['value'])
    local_ledger["current_10m_hash_value"]=prev_10m_block_hash_

    # comparison_matrix["without_optimization"]["size"].append(get_deep_size(local_ledger)) # in bytes
    # comparison_matrix["without_optimization"]["time"].append(read_time*(10/_10m_slab_span))

    # Operation for basic ledger - END

    # Operation for optimized ledger - START
    block_content={
        "ledger_id": local_opt_ledger["ledger_id"],
        "quorum_slice_id": local_opt_ledger["quorum_slice_id"],
        "block_height": block_height,
        "timestamp": read_time,
        "consumption_value_hash": data_enc(METER_READING_DATA['value']), #cumulated consumption balue of the energy
        "prev_10m_block_hash": prev_10m_block_hash
    }
    prev_10m_block_hash = data_enc(block_content)
    local_opt_ledger["slab_roots"]["10mi"].append(block_content)
    # updating the principle values
    block_height+=1
    local_opt_ledger["block_height"]=block_height
    local_opt_ledger["last_timestamp"]=read_time
    local_opt_ledger["consumption_value_hash"]=data_enc(METER_READING_DATA['value'])
    local_opt_ledger["current_10m_hash_value"]=prev_10m_block_hash

    # compute the hour ledger
    if len(local_opt_ledger["slab_roots"]["10mi"]) > 2 and local_opt_ledger["slab_roots"]["10mi"][-1]["timestamp"] - local_opt_ledger["slab_roots"]["10mi"][0]["timestamp"] >= _10m_slab_span*hour_slab_span:
        block_content={
            "ledger_id": local_opt_ledger["ledger_id"],
            "quorum_slice_id": local_opt_ledger["quorum_slice_id"],
            "block_height": block_height,
            "timestamp": read_time,
            "consumption_value_hash": data_enc(METER_READING_DATA['value']),
            "prev_1h_block_hash": prev_1h_block_hash
        }
        prev_1h_block_hash = data_enc(block_content)
        local_opt_ledger["slab_roots"]["1h"].append(block_content)
        local_opt_ledger["current_1h_hash_value"]=prev_1h_block_hash
        local_opt_ledger["slab_roots"]["10mi"] = [local_opt_ledger["slab_roots"]["10mi"][-1]]

    if len(local_opt_ledger["slab_roots"]["1h"]) >= day_slab_span:
        block_content={
            "ledger_id": local_opt_ledger["ledger_id"],
            "quorum_slice_id": local_opt_ledger["quorum_slice_id"],
            "block_height": block_height,
            "timestamp": read_time,
            "consumption_value_hash": data_enc(METER_READING_DATA['value']),
            "prev_1d_block_hash": prev_1d_block_hash
        }
        prev_1d_block_hash = data_enc(block_content)
        local_opt_ledger["slab_roots"]["1d"].append(block_content)
        local_opt_ledger["current_1d_hash_value"]=prev_1d_block_hash
        local_opt_ledger["slab_roots"]["1h"] = [local_opt_ledger["slab_roots"]["1h"][-1]]

    if len(local_opt_ledger["slab_roots"]["1d"]) >= month_slab_span[month_counter%12]:
        block_content={
            "ledger_id": local_opt_ledger["ledger_id"],
            "quorum_slice_id": local_opt_ledger["quorum_slice_id"],
            "block_height": block_height,
            "timestamp": read_time,
            "consumption_value_hash": data_enc(METER_READING_DATA['value']),
            "prev_1m_block_hash": prev_1m_block_hash
        }
        prev_1m_block_hash = data_enc(block_content)
        local_opt_ledger["slab_roots"]["1m"].append(block_content)
        local_opt_ledger["current_1m_hash_value"]=prev_1m_block_hash
        local_opt_ledger["slab_roots"]["1d"] = [local_opt_ledger["slab_roots"]["1d"][-1]]
        month_counter+=1

    # compute the day ledger


    comparison_matrix["with_optimization"]["size"].append(get_deep_size(local_opt_ledger)) # in bytes
    comparison_matrix["with_optimization"]["time"].append(read_time*(10/_10m_slab_span))
    # Operation for optimized ledger - END



    print(local_opt_ledger["block_height"],"\n\n")
    # print(block_height)


    time.sleep(_10m_slab_span)


plot_optimization_comparison(comparison_matrix)












