import functools
import os
import base64

from flask import Flask, render_template, jsonify, request
from flask.views import MethodView

from Logs import Logs
from Network.Node import Node
from Network.collections import networking
from Network.collections.DbConstants import DEFL_PORT, print_banner
from Network.collections.networking import is_valid_ipv4, is_valid_ipv6
from Crypto.helpers.CryptoImplementation import CryptoImplementation
from Crypto import implementations


def node_wrapper(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        node = Node.getinstance()
        if node is None:
            return jsonify({'status': 'The node is not running. Connect to the network first'})
        return func(node, *args, **kwargs)

    return wrapper


def create_app(test_config=None):
    print("The service is starting...")

    def create_node(port=DEFL_PORT):
        local_ip = networking.get_local_ip()

        old_node = Node.getinstance()
        if old_node is not None:
            try:
                old_node.stop()
            except Exception as e:
                print(f"Warning: old node cleanup failed: {e}")

        node = Node(local_ip, port)
        node.start()
        Logs.setup_logs(node.id, len(node.myData), node.domain, device_type=node.device_type)
        return node

    create_node()
    print_banner()

    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/api/devices', methods=['GET'])
    @node_wrapper
    def api_devices(node):
        node = Node.getinstance()
        if not node:
            return jsonify({"status": "Node not connected"})

        devices = node.get_devices()
        return jsonify(devices)
    
    @app.route('/api/device_type', methods=['GET'])
    @node_wrapper
    def api_device_type(node):
        return jsonify({"device_type": node.device_type})

    @app.route('/api/ping/<device>', methods=['POST'])
    @node_wrapper
    def api_ping(node, device):
        return jsonify({'status': node.ping_device(device)})

    @app.route('/api/port', methods=['GET'])
    @node_wrapper
    def api_port(node):
        if not node.running:
            return jsonify({'port': "Not connected to the network"})
        
        external_port = os.getenv("EXTERNAL_PORT", node.port)
        return jsonify({'port': external_port})

    @app.route('/api/disconnect', methods=['POST'])
    @node_wrapper
    def api_disconnect(node):
        node.stop()
        return jsonify({'status': 'Node destroyed'})

    @app.route('/api/connect', methods=['POST'])
    def api_connect():
        port = request.args.get('port')
        if Node.getinstance() is not None:
            return jsonify({'status': 'Node already connected'})
        if port is None or not port.isdigit():
            create_node()
        else:
            create_node(port)
        return jsonify({'status': 'Node connected using port ' + str(port) if port is not None else
        'Node connected using port ' + str(DEFL_PORT)})

    @app.route('/api/mykeys', methods=['GET'])
    @node_wrapper
    def api_pubkey(node):
        import base64
        pubkeys = {}

        for impl_obj, handler in node.json_handler.CSHandlers.items():
            if not hasattr(handler, "public_key"):
                continue

            pubkey = handler.public_key
            if pubkey is None:
                continue

            if isinstance(pubkey, bytes):
                pubkey_str = base64.b64encode(pubkey).decode("utf-8")
            elif isinstance(pubkey, dict):
                pubkey_str = {
                    k: base64.b64encode(v).decode("utf-8") if isinstance(v, bytes) else str(v)
                    for k, v in pubkey.items()
                }
            elif isinstance(pubkey, str):
                pubkey_str = pubkey
            else:
                pubkey_str = str(pubkey)

            impl_name = getattr(impl_obj, "name", impl_obj)
            pubkeys[impl_name] = {"public_key": pubkey_str}

        for key, value in node.results.items():
            if "SharedKey" in key:
                pubkeys[key] = {"shared_key": value}

        return jsonify(pubkeys)

    @app.route('/api/intersection', methods=['POST'])
    @node_wrapper
    def api_intersection(node):
        data = request.get_json(force=True, silent=True) or {}
        device = data.get('device')
        scheme = data.get('scheme')  # ex: 'Paillier', 'BFV', 'Kyber', ...
        type_  = data.get('type')    # ex: 'PSI-CA', 'OPE', 'NIKE'
        rounds = int(data.get('rounds', 1) or 1)

        if not device or not scheme or not type_:
            return jsonify({'status': 'Invalid parameters'}), 400

        status = node.start_intersection(device, scheme, type_, rounds)
        return jsonify({'status': status})

    @app.route('/api/dataset', methods=['GET'])
    @node_wrapper
    def api_dataset(node):
        return jsonify({'dataset': list(node.myData)})

    @app.route('/api/id', methods=['GET'])
    @node_wrapper
    def api_id(node):
        return jsonify({'id': node.id})

    @app.route('/api/results', methods=['GET'])
    @node_wrapper
    def api_result(node):
        try:
            results = getattr(node, "results", {})
            if not isinstance(results, dict):
                results = {}
                
            if not results:
                return jsonify({'result': {}, 'message': 'No results available yet'})

            safe_results = {}
            for key, val in results.items():
                try:
                    if isinstance(val, bytes):
                        val = val.hex()
                    elif isinstance(val, (set, tuple)):
                        val = list(val)
                    elif not isinstance(val, (dict, list, str, int, float, bool, type(None))):
                        val = str(val)
                    safe_results[key] = val
                except Exception:
                    safe_results[key] = str(val)

            return jsonify({'result': safe_results})
        except Exception as e:
            print(f"[API][ERROR] Failed to serialize results: {e}")
            return jsonify({'error': f'Failed to fetch results: {e}'}), 500

    @app.route('/api/genkeys', methods=['POST'])
    @node_wrapper
    def api_genkeys(node):
        scheme = request.args.get('scheme')
        bit_length = request.args.get('bit_length')
        if scheme is None:
            return jsonify({'status': 'Invalid parameters'})
        if not bit_length.isdigit():
            return jsonify({'status': 'Invalid bit length'})
        return jsonify({'status': node.genkeys(scheme, int(bit_length))})

    @app.route('/api/discover_peers', methods=['POST'])
    @node_wrapper
    def api_discover_peers(node):
        return jsonify({'status': node.discover_peers()})

    @app.route('/api/add', methods=['PUT'])
    @node_wrapper
    def api_add_peer(node):
        peer = request.args.get('peer')
        device_type = request.args.get('device_type', 'Unknown')

        if peer is None:
            return jsonify({'status': 'Invalid parameters - No peer provided'})
        if is_valid_ipv4(peer) or is_valid_ipv6(peer):
            return jsonify({'status': node.new_peer(peer, "Not seen yet", device_type=device_type)})
        return jsonify({'status': 'Invalid IPv4 or IPv6 address'})

    @app.route('/api/logs', methods=['GET'])
    @node_wrapper
    def api_metrics(node):
        id = request.args.get('id')
        if id is not None:
            return jsonify(Logs.get_logs(id))
        return jsonify(Logs.get_logs(node.id))

    @app.route('/api/test', methods=['POST'])
    @node_wrapper
    def api_test(node):
        device = request.args.get('device')
        return jsonify({'status': node.launch_test(device)})
    
    @app.route('/api/test_all', methods=['POST'])
    @node_wrapper
    def test_all(node):
        device = request.args.get('device')
        return jsonify({'status': node.launch_test(device)})

    @app.route('/api/test_psi', methods=['POST'])
    @node_wrapper
    def test_psi(node):
        device = request.args.get('device')
        return jsonify({'status': node.launch_test(device, 'PSI-CA')})

    @app.route('/api/test_ope', methods=['POST'])
    @node_wrapper
    def test_ope(node):
        device = request.args.get('device')
        return jsonify({'status': node.launch_test(device, 'OPE')})

    @app.route('/api/test_nike', methods=['POST'])
    @node_wrapper
    def test_nike(node):
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form or request.args
        device = data.get("device")
        if not device:
            return jsonify({"error": "Missing 'device'"}), 400
        return jsonify({'status': node.launch_test(device, 'NIKE')})

    @app.route('/api/setup', methods=['POST'])
    @node_wrapper
    def api_setup(node):
        domain = request.args.get('domain')
        set_size = request.args.get('set_size')
        if domain is None or set_size is None:
            return jsonify({'status': 'Invalid parameters'})
        res = node.update_setup(domain, set_size)
        if res == "Setup updated":
            Logs.setup_logs(node.id, set_size, domain, device_type=node.device_type)
        return jsonify({'status': res})

    @app.route('/api/check_connection', methods=['GET'])
    @node_wrapper
    def api_check_connection(node):
        return jsonify({'status': "Up and running!"})

    @app.route('/api/tasks', methods=['GET'])
    @node_wrapper
    def api_check_tasks(node):
        node = Node.getinstance()
        if not node:
            return jsonify({'status': ['No node running', 'No node running']})
        return jsonify({'status': node.check_tasks()})
        
    @app.route('/api/summary', methods=['GET'])
    @node_wrapper
    def api_summary(node):
        logs = Logs.get_logs(node.id)
        if not logs:
            return jsonify({"summary": [], "categories": []})

        from collections import defaultdict

        summary = defaultdict(lambda: {
            "times": [],
            "cpus": [],
            "rams": [],
            "category": "Unknown",
            "steps": set(),
            "devices": set()
        })

        for entry in logs.values():
            if not isinstance(entry, dict):
                continue

            scheme = entry.get("scheme")
            if not scheme:
                code = entry.get("activity_code", "")
                parts = code.split("_")
                if len(parts) >= 4:
                    scheme = parts[3]
                else:
                    continue

            time_val = float(entry.get("time", 0))
            cpu_val = float(str(entry.get("Avg_instance_CPU", "0")).replace("%", ""))
            ram_raw = str(entry.get("Avg_instance_RAM", "0"))
            ram_val = 0.0
            if "MB" in ram_raw:
                try:
                    ram_val = float(ram_raw.split("MB")[0].strip())
                except:
                    pass

            category = entry.get("category", "Unknown")
            step = entry.get("step", "Unknown")
            device_type = entry.get("device_type", "Unknown")

            s = summary[scheme]
            s["times"].append(time_val)
            s["cpus"].append(cpu_val)
            s["rams"].append(ram_val)
            s["category"] = category
            s["steps"].add(step)
            s["devices"].add(device_type)

        output = []
        for scheme, vals in summary.items():
            n = max(len(vals["times"]), 1)
            output.append({
                "scheme": scheme,
                "avg_time": round(sum(vals["times"]) / n, 3),
                "avg_cpu": round(sum(vals["cpus"]) / n, 2),
                "avg_ram": round(sum(vals["rams"]) / n, 2),
                "category": vals["category"],
                "steps": sorted(vals["steps"]),
                "devices": sorted(vals["devices"]),
                "count": n
            })

        categories = sorted({v["category"] for v in output})
        return jsonify({
            "summary": output,
            "categories": categories
        })


    # noinspection PyMethodMayBeStatic
    # To be able to use appropriate API methods, GET for status and POST for connect/disconnect
    class FirebaseAPI(MethodView):
        def get(self):
            if Logs.default_app is None:
                return jsonify({'status': 'Firebase not connected - The application will not log data to Firebase'})
            return jsonify({'status': 'Firebase connected'})

        def post(self):
            action = request.args.get('action')
            if action == 'connect':
                return jsonify({'status': Logs.connect_firebase()})
            elif action == 'disconnect':
                return jsonify({'status': Logs.disconnect_firebase()})

    app.add_url_rule('/api/firebase', view_func=FirebaseAPI.as_view('firebase_api'))

    return app
