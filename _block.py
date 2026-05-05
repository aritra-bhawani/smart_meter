import time
# import json  # UNUSED: only needed by commented-out NodeBlock methods
from datetime import datetime
import copy
import sys

from _crypto import data_enc
from _probe import *
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
# 

# defines the state of the node's blockchain at a given point in time
_10m_slab_span = 0.001 # with respect to the time span
hour_slab_span = 6 # with respect to the 10 mins slab
day_slab_span = 24 # with respect to the hr slab
# week_slab_span = 7 # with respect to the day slab
month_slab_span = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] # with respect to the day slab
year_slab_span = 12 # with respect to the month slab

READINGS_PER_DAY = hour_slab_span * day_slab_span  # 144 readings = 1 day

# UNUSED: NodeBlock class — never instantiated; simulation uses plain dicts instead
# @dataclass
# class NodeBlock:
#     ledger_id: str
#     block_height: int
#     timestamp: int = 0
#     quorum_slice_id: str = ""
#     _10m_block_hash: str = "0"*64
#     _1hr_block_hash: str = "0"*64
#     _1day_block_hash: str = "0"*64
#     _1week_block_hash: str = "0"*64
#     _1month_block_hash: str = "0"*64
#     _1year_block_hash: str = "0"*64
#     consumption_value_hash: str = ""
#     slab_roots: Dict[str, list] = field(default_factory=lambda: {"10m": [], "1h": [], "1d": [], "1w": [], "1m": [], "1y": []})
#     temp_readings: List[Dict] = field(default_factory=list)
#
#     def compute_10m_block_hash(self) -> str:
#         block_content = {
#             "ledger_id": self.ledger_id,
#             "block_height": self.block_height,
#             "prev_10m_block_hash": self._10m_block_hash,
#             "quorum_slice_id": self.quorum_slice_id,
#             "timestamp": self.timestamp,
#             "consumption_value_hash": self.consumption_value_hash
#         }
#         block_bytes = json.dumps(block_content, sort_keys=True)
#         self._10m_block_hash = data_enc(block_bytes)
#         return self._10m_block_hash
#
#     def compute_1h_block_hash(self) -> str:
#         block_content = {
#             "prev_1h_block_hash": self._1hr_block_hash,
#             "block_height": self.block_height,
#             "timestamp": self.timestamp,
#             "10m_slab_root_hash": self._10m_block_hash
#         }
#         block_bytes = json.dumps(block_content, sort_keys=True)
#         self._1hr_block_hash = data_enc(block_bytes)
#         return self._1hr_block_hash
#
#     def print_block(self):
#         print(f"Slab Roots: {self.slab_roots}\n\n")

hw = start_meter(base_rate=0.001, variability=0.00003)

block_height = 0
basic_slab_roots = {"10m": []}
opt_slab_roots = {"10m": [], "1h": [], "1d": [], "1w": [], "1m": [], "1y": []}

# Misc --- START
# def block_to_dict(block, seen=None):
#     if seen is None:
#         seen = set()
#     if id(block) in seen:
#         return {
#             "ledger_id": block.ledger_id,
#             "block_height": block.block_height,
#             "timestamp": block.timestamp,
#             "_10m_block_hash": block._10m_block_hash
#         }
#     seen.add(id(block))
#     d = {
#         "ledger_id": block.ledger_id,
#         "block_height": block.block_height,
#         "timestamp": block.timestamp,
#         "quorum_slice_id": block.quorum_slice_id,
#         "_10m_block_hash": block._10m_block_hash,
#         "_1hr_block_hash": block._1hr_block_hash,
#         "_1day_block_hash": block._1day_block_hash,
#         "_1week_block_hash": block._1week_block_hash,
#         "_1month_block_hash": block._1month_block_hash,
#         "_1year_block_hash": block._1year_block_hash,
#         "consumption_value_hash": block.consumption_value_hash,
#         "slab_roots": {},
#         "temp_readings": block.temp_readings,
#     }
#     for slab, blocks in block.slab_roots.items():
#         d['slab_roots'][slab] = [
#             block_to_dict(b, seen) if isinstance(b, NodeBlock) else b for b in blocks
#         ]
#     return d


def plot_optimization_comparison(data):
    with_opt    = data.get('with_optimization', {})
    without_opt = data.get('without_optimization', {})

    has_with    = bool(with_opt.get('size')    and with_opt.get('time'))
    has_without = bool(without_opt.get('size') and without_opt.get('time'))

    if not has_with and not has_without:
        print("No data available to plot.")
        return

    # ── Convert reading index → days, bytes → KB ──────────────────────────
    def to_days(index_list):
        return [i / READINGS_PER_DAY for i in index_list]

    def to_kb(size_list):
        return [s / 1024 for s in size_list]

    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 10,
        "axes.labelsize": 11,
        "axes.titlesize": 11,
        "legend.fontsize": 9,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "axes.linewidth": 0.8,
        "grid.linewidth": 0.5,
    })

    # ══════════════════════════════════════════════════════════════════════
    # PLOT 1
    # ══════════════════════════════════════════════════════════════════════
    fig1, ax = plt.subplots(figsize=(8, 4.5))

    if has_without:
        days_wo = to_days(without_opt['time'])
        size_wo = to_kb(without_opt['size'])
        ax.plot(days_wo, size_wo,
                label='Without optimisation — naive O(N)',
                color='#c0392b', linewidth=1.5, linestyle='-')
        # annotate final value
        ax.annotate(f"{size_wo[-1]:.0f} KB",
                    xy=(days_wo[-1], size_wo[-1]),
                    xytext=(-60, -14), textcoords='offset points',
                    fontsize=8, color='#c0392b',
                    arrowprops=dict(arrowstyle='->', color='#c0392b', lw=0.7))

    if has_with:
        days_w = to_days(with_opt['time'])
        size_w = to_kb(with_opt['size'])
        ax.plot(days_w, size_w,
                label='With optimisation — hierarchical rollup',
                color='#2980b9', linewidth=1.2, linestyle='-')
        # annotate max value
        max_w = max(size_w)
        idx_max = size_w.index(max_w)
        ax.annotate(f"max {max_w:.1f} KB",
                    xy=(days_w[idx_max], max_w),
                    xytext=(6, 6), textcoords='offset points',
                    fontsize=8, color='#2980b9')

    ax.set_yscale('log')
    ax.set_xlabel('Simulated time (days)')
    ax.set_ylabel('Ledger storage (KB, log scale)')
    ax.set_title('Storage growth: naive accumulation vs. hierarchical rollup')
    ax.legend(loc='upper left', frameon=True, framealpha=0.9)
    ax.grid(True, which='both', linestyle=':', linewidth=0.5, alpha=0.7)
    ax.xaxis.set_major_locator(ticker.MultipleLocator(5))
    ax.xaxis.set_minor_locator(ticker.MultipleLocator(1))

    fig1.tight_layout()
    fig1.savefig('optimization_plot_combined.png', dpi=300, bbox_inches='tight')
    print("Plot 1 saved: optimization_plot_combined.png")
    plt.close(fig1)

    # ══════════════════════════════════════════════════════════════════════
    # PLOT 2
    # ══════════════════════════════════════════════════════════════════════
    if not has_with:
        print("No optimised data for Plot 2.")
        return

    fig2, ax2 = plt.subplots(figsize=(8, 4.5))

    days_w = to_days(with_opt['time'])
    size_w = to_kb(with_opt['size'])
    total_days = int(days_w[-1]) + 1

    ax2.plot(days_w, size_w,
             color='#2980b9', linewidth=1.0, linestyle='-')
    ax2.fill_between(days_w, size_w, alpha=0.12, color='#2980b9')

    # draw a dashed vertical line at every 7th day to mark weekly boundaries
    for d in range(7, total_days, 7):
        ax2.axvline(x=d, color='gray', linewidth=0.6,
                    linestyle='--', alpha=0.55)
        ax2.text(d + 0.2, ax2.get_ylim()[1] * 0.92 if ax2.get_ylim()[1] > 0 else max(size_w) * 0.92,
                 f'Day {d}', fontsize=7, color='gray', va='top')

    # annotate the max (peak before first monthly rollup)
    max_w = max(size_w)
    idx_max = size_w.index(max_w)
    ax2.annotate(f"peak {max_w:.1f} KB\n(pre-rollup)",
                 xy=(days_w[idx_max], max_w),
                 xytext=(8, -20), textcoords='offset points',
                 fontsize=8, color='#2980b9',
                 arrowprops=dict(arrowstyle='->', color='#2980b9', lw=0.7))

    # annotate a rollup drop if one exists
    drops = [(i, days_w[i], size_w[i]) for i in range(1, len(size_w))
             if size_w[i] < size_w[i-1] * 0.5]
    if drops:
        i_drop, d_drop, s_drop = drops[0]
        ax2.annotate(f"rollup\n{s_drop:.1f} KB",
                     xy=(d_drop, s_drop),
                     xytext=(8, 10), textcoords='offset points',
                     fontsize=8, color='#27ae60',
                     arrowprops=dict(arrowstyle='->', color='#27ae60', lw=0.7))

    ax2.set_xlabel('Simulated time (days)')
    ax2.set_ylabel('Ledger storage (KB)')
    ax2.set_title('Optimised ledger storage — sawtooth from hierarchical checkpointing')
    ax2.set_xlim(0, total_days)
    ax2.xaxis.set_major_locator(ticker.MultipleLocator(7))
    ax2.xaxis.set_minor_locator(ticker.MultipleLocator(1))
    ax2.grid(True, linestyle=':', linewidth=0.5, alpha=0.7)

    fig2.tight_layout()
    fig2.savefig('optimization_plot_optimized.png', dpi=300, bbox_inches='tight')
    print("Plot 2 saved: optimization_plot_optimized.png")
    plt.close(fig2)

# Misc --- END

comparison_matrix = {"with_optimization": {"size":[], "time":[]}, "without_optimization": {"size":[], "time":[]}}

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
    print(f"Processing reading index: {block_height}") if block_height % 100 == 0 else None

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

    comparison_matrix["without_optimization"]["size"].append(get_deep_size(local_ledger)) # in bytes
    comparison_matrix["without_optimization"]["time"].append(block_height_) # reading index

    # Operation for basic ledger - END

    # Operation for optimized ledger - START
    block_content={
        "ledger_id": local_opt_ledger["ledger_id"],
        "quorum_slice_id": local_opt_ledger["quorum_slice_id"],
        "block_height": block_height,
        "timestamp": read_time,
        "consumption_value_hash": data_enc(METER_READING_DATA['value']),
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
    # if len(local_opt_ledger["slab_roots"]["10mi"]) > 2 and local_opt_ledger["slab_roots"]["10mi"][-1]["timestamp"] - local_opt_ledger["slab_roots"]["10mi"][0]["timestamp"] >= _10m_slab_span*hour_slab_span:
    if len(local_opt_ledger["slab_roots"]["10mi"]) >= hour_slab_span:
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
        # local_opt_ledger["slab_roots"]["10mi"] = [local_opt_ledger["slab_roots"]["10mi"][-1]]
        local_opt_ledger["slab_roots"]["10mi"] = []

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
        # local_opt_ledger["slab_roots"]["1h"] = [local_opt_ledger["slab_roots"]["1h"][-1]]
        local_opt_ledger["slab_roots"]["1h"] = []

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
        # local_opt_ledger["slab_roots"]["1d"] = [local_opt_ledger["slab_roots"]["1d"][-1]]
        local_opt_ledger["slab_roots"]["1d"] = []
        month_counter+=1

    comparison_matrix["with_optimization"]["size"].append(get_deep_size(local_opt_ledger)) # in bytes
    comparison_matrix["with_optimization"]["time"].append(block_height)                     # reading index
    # Operation for optimized ledger - END

    time.sleep(_10m_slab_span)


plot_optimization_comparison(comparison_matrix)
