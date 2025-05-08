import time

from Logs import Logs
from Logs.Logs import ThreadData
from Network.collections.DbConstants import VERSION


def log_activity(specific_code):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            start_time = time.time()  # Tiempo de inicio
            thread_data = ThreadData()
            Logs.start_logging(thread_data)
            
            my_data_size, ciphertext_size = func(self, *args, **kwargs)  # Ejecución de la función
            
            elapsed = time.time() - start_time
            if elapsed < 0.6:
                time.sleep(0.6 - elapsed)
            
            end_time = time.time()  # Tiempo de finalización
            Logs.stop_logging(thread_data)
            device = args[0] if len(args) > 0 else None
            cs = args[1] if len(args) > 1 else None
            activity_code = func.__name__.upper() + ("_" + cs.imp_name if cs is not None else "") + "_" + specific_code
            Logs.log_activity(thread_data, activity_code, end_time - start_time,
                              VERSION, self.id, device, my_data_size if my_data_size is not None else None,
                              ciphertext_size if ciphertext_size is not None else None)
            print(f"Activity {activity_code} took {end_time - start_time}s")
            return
        return wrapper
    return decorator
