$(document).ready(function () {
    $('select').formSelect();
    initializeDashboard();
});

const NODE_NOT_CONNECTED = "Node not connected";
const DEVICE_REFRESH_INTERVAL = 10000;
const TASK_REFRESH_INTERVAL = 1000;

function initializeDashboard() {
    getNodeId();
    getNodePort();
    updateDevices();
    checkConnection();
    refreshTasks();

    setInterval(checkConnection, DEVICE_REFRESH_INTERVAL);
    setInterval(updateDevices, DEVICE_REFRESH_INTERVAL);

    $(document).on('click', '.ping-btn', function () {
        pingDevice($(this).data('device'));
    });

    $(document).on('click', '.scheme-btn', function () {
      const $card = $(this).closest('.card');
      const device = $(this).data('device');
      const value = $card.find('select.scheme-selector').val();
      runScheme(device, value);
    });
}

function getNodeId() {
    $.get('/api/id')
        .done(data => $('#id').text(data.id))
        .fail(() => showToast("Failed to retrieve node ID"));
}

function getNodePort() {
    $.get('/api/port')
        .done(data => $('#port').text(data.port))
        .fail(() => showToast("Failed to retrieve port"));
}

function updateDevices() {
  $.getJSON('/api/devices')
    .done(data => {
      const $devices = $('#devices');
      $devices.empty();

      if (data.status === NODE_NOT_CONNECTED) {
        $('#devicesConnected').html('<h2>The node is offline</h2>');
        return;
      }

      if (Object.keys(data).length === 0) {
        $('#devicesConnected').html('<h2>No peers discovered yet</h2>');
        $devices.html('<p class="grey-text">Try clicking <strong>"Discover Peers"</strong> to search for nodes in the network.</p>');
        return;
      }

      $('#devicesConnected').html('<h2>Registered devices</h2>');
      let cardsHTML = '<div class="row">';

      $.each(data, (key, value) => {
        let displayKey = key.replace(/:.*:/, '::');
        let deviceType = value.device_type || "Unknown";

        cardsHTML += `
          <div class="col s12 m6 l4">
            <div class="card z-depth-2 ${deviceType.toLowerCase()}-device" id="card-${key}">
              <div class="card-content">
                <span class="card-title">${displayKey}</span>
                <p><strong>Type:</strong> ${deviceType}</p>
                <p>Last seen: ${value.last_seen || "N/A"}</p>
                <div class="result-message" id="result-${key}" style="margin-top: 10px;"></div>
              </div>
              <div class="card-action">
                <div class="btn-group" style="margin-bottom: 10px;">
                  <a class="btn-small green ping-btn" data-device="${key}">Ping</a>
                  <a class="btn-small orange" data-category="psi" data-device="${key}">Test PSI</a>
                  <a class="btn-small blue" data-category="ope" data-device="${key}">Test OPE</a>
                  <a class="btn-small red" data-category="nike" data-device="${key}">Test NIKE</a>
                  <a class="btn-small light-blue" data-category="all" data-device="${key}">Test All</a>
                </div>
                <div class="input-field">
                  <select class="scheme-selector" data-device="${key}" id="scheme-${key}">
                    <option value="" disabled selected>Select a scheme</option>
                    <option value="Paillier|PSI-CA">Cardinality - Paillier</option>
                    <option value="DamgardJurik|PSI-CA">Cardinality - Damgard-Jurik</option>
                    <option value="BFV|OPE">BFV</option>
                    <option value="Diffie-Hellman|NIKE">NIKE - Diffie-Hellman</option>
                    <option value="Kyber|NIKE">NIKE - Kyber</option>
                    <option value="FrodoKEM|NIKE">NIKE - FrodoKEM</option>
                    <option value="ClassicMcEliece|NIKE">NIKE - McEliece</option>
                    <option value="NTRU|NIKE">NIKE - NTRU</option>
                    <option value="BIKE|NIKE">NIKE - BIKE</option>
                    <option value="HQC|NIKE">NIKE - HQC</option>
                    <option value="X25519|NIKE">NIKE - X25519</option>
                    <option value="P256|NIKE">NIKE - P256</option>
                    <option value="HybridKyberX25519|NIKE">NIKE - HybridKyberX25519</option>
                  </select>
                  <button class="btn-small btn-dark scheme-btn" data-device="${key}">Start</button>
                </div>
              </div>
            </div>
          </div>`;
      });

      cardsHTML += '</div>';
      $devices.html(cardsHTML);
      $('select').formSelect();
    })
    .fail(() => showToast("Failed to load devices"));
}

$(document).on('click', '[data-category]', function () {
  const device = $(this).data('device');
  const category = $(this).data('category'); // 'psi' | 'ope' | 'nike' | 'all'
  testCategory(device, category);
});

function discover_peers() {
  $.post('/api/discover_peers')
    .done(res => {
      showToast(res.status || "Peer discovery started");
      setTimeout(updateDevices, 2000);
    })
    .fail(() => {
      showToast("Failed to start peer discovery");
    })
}

function pingDevice(device) {
    $.post(`/api/ping/${device}`)
        .done(data => {
            showToast(data.status);
            showResult(device, data.status);
        })
        .fail(() => showToast("Ping failed"))
        .always(() => {
            updateDevices();
        });
}

function testCategory(device, category) {
    const endpoint = `/api/test_${category.toLowerCase()}`;
    $.post(`${endpoint}?device=${device}`)
        .done(data => {
            showToast(data.status);
            showResult(device, data.status);
        })
        .fail(() => {
            const error = "Test failed. Check the logs.";
            showToast(error);
            showResult(device, error);
        });
}

function normalizeScheme(s) {
  const map = {
    // PSI / OPE aliases
    'Paillier OPE': 'Paillier',
    'Paillier_OPE': 'Paillier',
    'Paillier PSI-CA OPE': 'Paillier',

    'Damgard-Jurik': 'DamgardJurik',
    'DamgardJurik OPE': 'DamgardJurik',
    'Damgard-Jurik_OPE': 'DamgardJurik',
    'Damgard-Jurik PSI-CA OPE': 'DamgardJurik',

    'BFV_OPE': 'BFV',
    'BFV OPE': 'BFV',
    'CA-OPE': 'CAOPE',
    'CA_OPE': 'CAOPE',

    // NIKE
    'DH': 'Diffie-Hellman',
    'DiffieHellman': 'Diffie-Hellman',
    'Diffie Hellman': 'Diffie-Hellman',
    'Curve25519': 'X25519',
    'X25519': 'X25519',
    'P256': 'P256',
    'Frodo': 'FrodoKEM',
    'FrodoKEM': 'FrodoKEM',
    'Kyber': 'Kyber',
    'BIKE': 'BIKE',
    'HQC': 'HQC',
    'NTRU': 'NTRU',
    'McEliece': 'ClassicMcEliece',
    'Classic McEliece': 'ClassicMcEliece',
    'ClassicMcEliece': 'ClassicMcEliece',
    'HybridKyber_X25519': 'HybridKyberX25519',
    'HybridKyber-X25519': 'HybridKyberX25519',
    'Hybrid Kyber X25519': 'HybridKyberX25519'
  };
  return (map[s] || s).trim();
}

function runScheme(device, value) {
    if (!value || !value.includes('|')) {
        showToast("Invalid scheme. Please select one to continue.");
        showResult(device, `<strong>Error:</strong> No valid scheme selected.`);
        return;
    }

    const [scheme, type] = value.split('|').map(s => s.trim());

    const startMsg = `<div>
        <strong>Starting algorithm:</strong><br>
        <strong>Device:</strong> ${device}<br>
        <strong>Scheme:</strong> ${scheme}<br>
        <strong>Type:</strong> ${type}<br>
        <em>Waiting for response...</em>
    </div>`;
    showResult(device, startMsg);
    showToast(`Starting algorithm for ${scheme} (${device})`);

    const schemeNorm = normalizeScheme(scheme);
    findIntersection(device, schemeNorm, type.toUpperCase(), 1);
}

function findIntersection(device, scheme, type, rounds = 1) {
    $.ajax({
        url: '/api/intersection',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ device, scheme, type, rounds }),
        dataType: 'json'
    })
        .done(response => {
            const message = response.status;
            const successMsg = `<div>
                <strong>Execution finished:</strong><br>
                <strong>Device:</strong> ${device}<br>
                <strong>Scheme:</strong> ${scheme}<br>
                <strong>Type:</strong> ${type}<br>
                <strong>Rounds:</strong> ${rounds}<br>
                <strong>Status:</strong> ${message}
            </div>`;
            showToast(`${scheme} executed on ${device}`);
            showResult(device, successMsg);
        })
        .fail((xhr, status, error) => {
            const errorMsg = `<div>
                <strong>Error during execution</strong><br>
                <strong>Device:</strong> ${device}<br>
                <strong>Scheme:</strong> ${scheme}<br>
                <strong>Type:</strong> ${type}<br>
                <strong>Rounds:</strong> ${rounds}<br>
                <strong>Details:</strong> ${error || "Unknown error"}
            </div>`;
            showToast(`Failed to execute ${scheme} on ${device}`);
            showResult(device, errorMsg);
        });
}

function connect() {
    $.post('/api/connect')
        .done(data => {
            showToast(data.status || "Successfully connected");
            updateDevices();
            getNodePort();
            getNodeId();
            $('#connect').prop('disabled', true);
            $('#disconnect').prop('disabled', false);
        })
        .fail(() => showToast("Failed to connect to node"));
}

function disconnect() {
    $.post('/api/disconnect')
        .done(data => {
            showToast(data.status || "Successfully disconnected");
            updateDevices();
            getNodePort();
            getNodeId();
            $('#connect').prop('disabled', false);
            $('#disconnect').prop('disabled', true);
        })
        .fail(() => showToast("Failed to disconnect from node"));
}

function checkConnection() {
    $.get('/api/check_connection')
        .done(data => {
            $('#connect').prop('disabled', data.status !== NODE_NOT_CONNECTED);
            $('#disconnect').prop('disabled', data.status === NODE_NOT_CONNECTED);
        })
        .fail(() => showToast("Failed to check connection status"));
}

function refreshTasks() {
    setInterval(() => {
        $.get('/api/tasks')
            .done(data => {
                $('#pending_node').text(data.status[0]);
                $('#pending_handler').text(data.status[1]);
            })
            .fail(() => console.warn("Failed to fetch task info"));
    }, TASK_REFRESH_INTERVAL);
}

function showToast(message) {
    if (typeof M !== 'undefined' && M.toast) {
        M.toast({ html: message });
    } else {
        console.log(message);
    }
}

function showResult(device, message) {
    $(`#result-${device}`).html(`<div class="result-block">${message}</div>`);
}

function results() {
  $.get('/api/results', function (data) {
    if (!data || !data.result) {
      showToast("No results available");
      return;
    }

    const results = data.result;
    let structured = {};

    for (const [key, value] of Object.entries(results)) {
      const parts = key.split(" ");
      const device = parts[0] || "Unknown Device";
      const scheme = parts[1] || "Unknown Scheme";
      const type = parts.slice(2).join(" ") || "General";

      if (!structured[device]) structured[device] = {};
      if (!structured[device][scheme]) structured[device][scheme] = {};
      structured[device][scheme][type] = value;
    }

    let html = `
      <html>
        <head>
          <title>PSI Suite - Results</title>
          <link href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css" rel="stylesheet"/>
          <style>
            body { padding: 20px; font-family: Roboto, sans-serif; }
            h3, h4, h5 { margin-top: 1rem; }
            code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
            .scheme-card { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 8px; background: #fafafa; }
            .device-header { background: #2196f3; color: white; padding: 8px; border-radius: 6px; }
          </style>
        </head>
        <body>
          <h3>Computation Results</h3>
          <p>Below are the results grouped by <strong>Device</strong>, <strong>Scheme</strong>, and <strong>Algorithm Type</strong>.</p>
    `;

    for (const [device, schemes] of Object.entries(structured)) {
      html += `<div class="device-header"><h4>Device: ${device}</h4></div>`;

      for (const [scheme, types] of Object.entries(schemes)) {
        html += `<div class="scheme-card"><h5>Scheme: ${scheme}</h5><ul>`;

        for (const [type, value] of Object.entries(types)) {
          let displayValue = value;

          if (typeof displayValue === "string" && displayValue.length > 200) {
            displayValue = displayValue.slice(0, 200) + "...";
          } else if (Array.isArray(displayValue)) {
            displayValue = `[${displayValue.length} elements]`;
          } else if (typeof displayValue === "object") {
            displayValue = JSON.stringify(displayValue, null, 2);
          }

          html += `<li><strong>${type}</strong>: <code>${displayValue}</code></li>`;
        }
        html += `</ul></div>`;
      }
    }

    html += `
        </body>
      </html>
    `;

    const resultWindow = window.open("", "_blank");
    resultWindow.document.write(html);
    resultWindow.document.close();
  }).fail(() => {
    showToast("Failed to load results from the backend");
  });
}
