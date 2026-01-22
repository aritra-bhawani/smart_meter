import threading
import time
import random
from datetime import datetime

meter_states = {}
meter_locks = {}

def generate_hw_address():
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))

def start_meter(base_rate: float = 0.0, variability: float = 0.0002):
    hw_address = generate_hw_address()
    meter_states[hw_address] = 0.0
    meter_locks[hw_address] = threading.Lock()

    def meter_loop():
        while True:
            increment = base_rate + random.uniform(-variability, variability)
            increment = max(increment, 0)
            with meter_locks[hw_address]:
                meter_states[hw_address] += increment
            time.sleep(1)

    thread = threading.Thread(target=meter_loop, daemon=True)
    thread.start()
    return hw_address

def read_meter(hw_address: str):
    with meter_locks[hw_address]:
        value = meter_states[hw_address]
    return {
        "hw_address": hw_address,
        "timestamp": datetime.utcnow().isoformat(),
        "value": round(value, 3)
    }

# if __name__ == "__main__":
#     hw = start_meter(base_rate=0.2, variability=0.1)
#     while True:
#         print(read_meter(hw))
#         time.sleep(1)   