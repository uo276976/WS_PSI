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
  fetch('/api/devices')
    .then(response => {
      if (!response.ok) throw new Error("Network response was not ok");
      return response.json();
    })
    .then(data => {
      const devicesContainer = document.getElementById('devices');
      const devicesHeader = document.getElementById('devicesConnected');
      devicesContainer.innerHTML = '';

      if (data.status === NODE_NOT_CONNECTED) {
        devicesHeader.textContent = 'El nodo está desconectado';
        return;
      }

      if (Object.keys(data).length === 0) {
        devicesHeader.textContent = 'No se han descubierto pares aún';
        const info = document.createElement('p');
        info.className = 'grey-text';
        info.innerHTML = `Prueba haciendo clic en <strong>"Buscar peers"</strong> para detectar nodos en la red.`;
        devicesContainer.appendChild(info);
        return;
      }

      devicesHeader.textContent = 'Dispositivos registrados';

      const row = document.createElement('div');
      row.className = 'row';

      Object.entries(data).forEach(([key, value]) => {
        const displayKey = key.replace(/:.*:/, '::');
        const deviceType = value.device_type || 'Unknown';
        const lastSeen = value.last_seen || 'N/A';

        // Card structure
        const col = document.createElement('div');
        col.className = 'col s12 m6 l4';

        const card = document.createElement('article');
        card.className = `card z-depth-2 ${deviceType.toLowerCase()}-device`;
        card.id = `card-${key}`;
        card.setAttribute('role', 'region');
        card.setAttribute('aria-label', `Dispositivo ${displayKey}`);

        // Card content
        const content = document.createElement('div');
        content.className = 'card-content';

        const title = document.createElement('h3');
        title.className = 'card-title';
        title.textContent = displayKey;

        const typeInfo = document.createElement('p');
        typeInfo.innerHTML = `<strong>Tipo:</strong> ${deviceType}`;

        const lastSeenInfo = document.createElement('p');
        lastSeenInfo.innerHTML = `<strong>Última conexión:</strong> ${lastSeen}`;

        const resultDiv = document.createElement('div');
        resultDiv.className = 'result-message';
        resultDiv.id = `result-${key}`;

        // Append card content
        content.append(title, typeInfo, lastSeenInfo, resultDiv);

        // Card actions
        const actions = document.createElement('div');
        actions.className = 'card-action';

        const btnGroup = document.createElement('div');
        btnGroup.className = 'btn-group';

        // Buttons with proper semantics and event listeners
        const buttons = [
          { label: 'Ping', color: 'green', category: null, action: () => pingDevice(key) },
          { label: 'Test PSI', color: 'orange', category: 'psi' },
          { label: 'Test OPE', color: 'blue', category: 'ope' },
          { label: 'Test NIKE', color: 'red', category: 'nike' },
          { label: 'Test All', color: 'light-blue', category: 'all' }
        ];

        buttons.forEach(btnData => {
          const btn = document.createElement('button');
          btn.className = `btn-small waves-effect waves-light ${btnData.color}`;
          btn.type = 'button';
          btn.textContent = btnData.label;
          btn.setAttribute('data-device', key);
          btn.setAttribute('aria-label', `${btnData.label} en ${displayKey}`);

          if (btnData.category) {
            btn.dataset.category = btnData.category;
            btn.addEventListener('click', () => testCategory(key, btnData.category));
          } else {
            btn.addEventListener('click', btnData.action);
          }

          btnGroup.appendChild(btn);
        });

        // Scheme selector and Start button
        const schemeField = document.createElement('div');
        schemeField.className = 'input-field flex-row';

        const select = document.createElement('select');
        select.className = 'scheme-selector';
        select.id = `scheme-${key}`;
        select.dataset.device = key;
        select.setAttribute('aria-label', `Seleccionar esquema para ${displayKey}`);

        const schemes = [
          { value: '', text: 'Selecciona un esquema', disabled: true, selected: true },
          { value: 'Paillier|PSI-CA', text: 'Cardinalidad - Paillier' },
          { value: 'DamgardJurik|PSI-CA', text: 'Cardinalidad - Damgard-Jurik' },
          { value: 'BFV|OPE', text: 'BFV' },
          { value: 'Diffie-Hellman|NIKE', text: 'NIKE - Diffie-Hellman' },
          { value: 'Kyber|NIKE', text: 'NIKE - Kyber' },
          { value: 'FrodoKEM|NIKE', text: 'NIKE - FrodoKEM' },
          { value: 'ClassicMcEliece|NIKE', text: 'NIKE - McEliece' },
          { value: 'NTRU|NIKE', text: 'NIKE - NTRU' },
          { value: 'BIKE|NIKE', text: 'NIKE - BIKE' },
          { value: 'HQC|NIKE', text: 'NIKE - HQC' },
          { value: 'X25519|NIKE', text: 'NIKE - X25519' },
          { value: 'P256|NIKE', text: 'NIKE - P256' },
          { value: 'HybridKyberX25519|NIKE', text: 'NIKE - HybridKyberX25519' }
        ];

        schemes.forEach(optData => {
          const opt = document.createElement('option');
          opt.value = optData.value;
          opt.textContent = optData.text;
          if (optData.disabled) opt.disabled = true;
          if (optData.selected) opt.selected = true;
          select.appendChild(opt);
        });

        const startBtn = document.createElement('button');
        startBtn.className = 'btn-small btn-dark scheme-btn';
        startBtn.type = 'button';
        startBtn.textContent = 'Iniciar';
        startBtn.dataset.device = key;
        startBtn.addEventListener('click', () => {
          const selectedValue = select.value;
          runScheme(key, selectedValue);
        });

        schemeField.append(select, startBtn);
        actions.append(btnGroup, schemeField);

        card.append(content, actions);
        col.appendChild(card);
        row.appendChild(col);
      });

      devicesContainer.appendChild(row);

      const selects = devicesContainer.querySelectorAll('select');
      M.FormSelect.init(selects);
    })
    .catch(() => showToast("No se pudieron cargar los dispositivos"));
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
      let device = "Unknown Device";
      let scheme = "Unknown Scheme";
      let type = "General";

      if (/^\d{1,3}(\.\d{1,3}){3}/.test(key)) {
        const parts = key.split(" ");
        device = parts.shift();
        scheme = parts.shift() || "Unknown Scheme";
        type = parts.join(" ") || "General";
      } else {
        const parts = key.split(" ");
        scheme = parts.shift() || "Unknown Scheme";
        type = parts.join(" ") || "General";
      }

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

          if (typeof displayValue === "string" && /^[0-9a-f]+$/i.test(displayValue)) {
            displayValue = displayValue.slice(0, 32) + "..." + displayValue.slice(-8);
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

function mykeys() {
  $.get('/api/mykeys', function(data) {
    const keysHTML = `
      <h4>Claves públicas</h4>
      <h5>Paillier</h5>
      <p><strong>n:</strong> ${data.pubkeyN}</p>
      <p><strong>g:</strong> ${data.pubkeyG}</p>
      <h5>Damgard-Jurik</h5>
      <p><strong>n:</strong> ${data.pubkeyNDJ}</p>
      <p><strong>s:</strong> ${data.pubkeySDJ}</p>
      <p><strong>m:</strong> ${data.pubkeyMDJ}</p>
    `;
    const newWin = window.open("", "_blank");
    newWin.document.write(`<html><body>${keysHTML}</body></html>`);
  });
}

function my_data() {
  $.get('/api/dataset', function(data) {
    const html = `<h4>Dataset</h4><pre>${JSON.stringify(data.dataset, null, 2)}</pre>`;
    const win = window.open("", "_blank");
    win.document.write(`<html><body>${html}</body></html>`);
  });
}

