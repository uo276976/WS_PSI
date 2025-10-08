import time

from Logs import Logs
from Logs.Logs import ThreadData
from Network.collections.DbConstants import VERSION


def log_activity(specific_code):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            print(f"[DEBUG] Entered log_activity decorator for {func.__name__}")
            start_time = time.time()
            thread_data = ThreadData()
            Logs.start_logging(thread_data)

            try:
                result = func(self, *args, **kwargs)
            except Exception as e:
                print(f"[ERROR] {func.__name__} crashed: {e}")
                raise

            if isinstance(result, tuple) and len(result) == 2:
                my_data_size, ciphertext_size = result
            else:
                my_data_size, ciphertext_size = None, None

            elapsed = time.time() - start_time
            if elapsed < 0.6:
                time.sleep(0.6 - elapsed)

            end_time = time.time()
            Logs.stop_logging(thread_data)

            device = args[0] if len(args) > 0 else None
            cs = args[1] if len(args) > 1 else None
            activity_code = func.__name__.upper() + ("_" + cs.imp_name if cs is not None else "") + "_" + specific_code

            print(f"[DEBUG] Before calling Logs.log_activity for {activity_code}")
            try:
                Logs.log_activity(thread_data, activity_code, end_time - start_time,
                                  VERSION, self.id, device, my_data_size,
                                  ciphertext_size,
                                  device_type = getattr(self, "device_type", None) \
                                    or getattr(self, "node_device_type", None) \
                                    or self.devices.get(device, {}).get("device_type") \
                                    or "Unknown")
                print(f"[DEBUG] After calling Logs.log_activity for {activity_code}")
            except Exception as e:
                print(f"[ERROR] Logs.log_activity failed for {activity_code}: {e}")

            print(f"Activity {activity_code} took {end_time - start_time}s")
            return result
        return wrapper
    return decorator
