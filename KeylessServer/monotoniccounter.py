import threading
import os

class SecureMonotonicCounter:
    def __init__(self, filepath='counter.txt'):
        self.filepath = filepath
        self._lock = threading.Lock()
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                f.write('0')

    def _read_counter(self):
        with open(self.filepath, 'r') as f:
            return int(f.read().strip())

    def _write_counter(self, value):
        with open(self.filepath, 'w') as f:
            f.write(str(value))

    def increment(self):
        with self._lock:
            current_value = self._read_counter()
            new_value = current_value + 1
            self._write_counter(new_value)
            return new_value

    def get_value(self):
        with self._lock:
            return self._read_counter()
