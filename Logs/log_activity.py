import time
import traceback
from Logs import Logs
from Logs.Logs import ThreadData
from Network.collections.DbConstants import VERSION


def log_activity(specific_code):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            print(f"[DEBUG] Entered log_activity decorator for {func.__name__}")
            start_time = time.perf_counter()
            thread_data = ThreadData()
            Logs.start_logging(thread_data)

            try:
                result = func(self, *args, **kwargs)
            except Exception as e:
                print(f"[ERROR] {func.__name__} crashed: {e}")
                traceback.print_exc()
                raise

            if isinstance(result, tuple) and len(result) == 2:
                my_data_size, ciphertext_size = result
            else:
                my_data_size, ciphertext_size = None, None

            end_time = time.perf_counter()
            Logs.stop_logging(thread_data)

            device = args[0] if len(args) > 0 else None
            cs = args[1] if len(args) > 1 else None
            activity_code = func.__name__.upper() + ("_" + cs.imp_name if cs is not None else "") + "_" + specific_code

            print(f"[DEBUG] Before calling Logs.log_activity for {activity_code}")
            try:
                scheme_name = getattr(cs, "imp_name", "Unknown")
                try:
                    from Crypto.helpers.CryptoImplementation import CryptoImplementation
                    crypto_impl = CryptoImplementation.from_string(scheme_name)
                    category = getattr(crypto_impl, "category", "Unknown")
                except Exception:
                    category = "Unknown"

                log_step = func.__name__.upper()
                peer_type = None
                try:
                    if hasattr(self, "devices") and device in self.devices:
                        peer_type = self.devices[device].get("device_type", "Unknown")
                except Exception:
                    peer_type = "Unknown"

                Logs.log_activity(
                    thread_data,
                    activity_code,
                    end_time - start_time,
                    VERSION,
                    self.id,
                    peer=device,
                    my_data_size=my_data_size,
                    ciphertext_size=ciphertext_size,
                    step=log_step,
                    scheme=scheme_name,
                    category=category,
                    device_type=getattr(self, "device_type", None) or "Unknown",
                    peer_device_type=peer_type,
                )

                print(f"[DEBUG] After calling Logs.log_activity for {activity_code}")
            except Exception as e:
                print(f"[ERROR] Logs.log_activity failed for {activity_code}: {e}")
                traceback.print_exc()

            print(f"Activity {activity_code} took {end_time - start_time:.6f}s")
            return result
        return wrapper
    return decorator
