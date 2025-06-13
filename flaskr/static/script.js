$(document).ready(function(){
    $('select').formSelect();
    update_devices();
    get_port();
    get_id();
    check_connection();
    setInterval(check_connection, 10000);
    setInterval(update_devices, 10000);
    check_tasks();

    // Load saved theme
    if (localStorage.getItem("darkMode") === "true") {
        toggleTheme();
    }
});

let nodeNotConnected = "Node not connected";

function get_id() {
    $.get('/api/id', function(data){
        $('#id').text(data.id);
    });
}

function get_port() {
    $.get('/api/port', function(data){
        $('#port').text(data.port);
    });
}

function loader() {
    $('#devices').html(`
        <div class="preloader-wrapper small active">
            <div class="spinner-layer spinner-green-only">
                <div class="circle-clipper left"><div class="circle"></div></div>
                <div class="gap-patch"><div class="circle"></div></div>
                <div class="circle-clipper right"><div class="circle"></div></div>
            </div>
        </div>`);
}

function update_devices() {
    $.getJSON('/api/devices', function(data){
        const $devices = $('#devices');
        $devices.empty();

        if (data.status === nodeNotConnected) {
            $('#devicesConnected').html('<h2>El nodo está apagado</h2>');
            return;
        }

        $('#devicesConnected').html('<h2>Dispositivos registrados</h2>');

        let cardsHTML = '<div class="row">';

        $.each(data, function(key, value){
            let displayKey = key.replace(/:.*:/, '::');
            let deviceType = value.device_type || "Desconocido";

            let card = `
                <div class="col s12 m6 l4">
                    <div class="card z-depth-2 ${deviceType.toLowerCase()}-device" id="card-${key}">
                        <div class="card-content">
                            <span class="card-title">${displayKey}</span>
                            <p><strong>Tipo:</strong> ${deviceType}</p>
                            <p>Última conexión: ${value.last_seen}</p>
                            <div class="result-message" id="result-${key}" style="margin-top: 10px;"></div>
                        </div>
                        <div class="card-action">
                            <div class="btn-group" style="margin-bottom: 10px;">
                                <a class="btn-small green ping-btn" data-device="${key}">Ping</a>
                                <a class="btn-small orange" onclick="testCategory('${key}', 'psi')">Test PSI</a>
                                <a class="btn-small blue" onclick="testCategory('${key}', 'ope')">Test OPE</a>
                                <a class="btn-small red" onclick="testCategory('${key}', 'nike')">Test NIKE</a>
                                <a class="btn-small light-blue" onclick="testCategory('${key}', 'all')">Test All</a>
                            </div>
                            <div class="input-field">
                                <select class="scheme-selector" data-device="${key}" id="scheme-${key}">
                                    <option value="" disabled selected>Elige un esquema</option>
                                    <option value="Paillier|PSI-CA">Cardinality - Paillier</option>
                                    <option value="DamgardJurik|PSI-CA">Cardinality - Damgard-Jurik</option>
                                    <option value="BFV|OPE">BFV</option>
                                    <option value="Diffie-Hellman|NIKE">NIKE - DH</option>
                                    <option value="Kyber|NIKE">NIKE - Kyber</option>
                                    <option value="CSIDH|NIKE">NIKE - CSIDH</option>
                                    <option value="FrodoKEM|NIKE">NIKE - FrodoKEM</option>
                                    <option value="ClassicMcEliece|NIKE">NIKE - McEliece</option>
                                </select>
                                <button class="btn-small btn-dark scheme-btn" data-device="${key}">Iniciar</button>
                            </div>
                        </div>
                    </div>
                </div>`;
            cardsHTML += card;
        });

        cardsHTML += '</div>';
        $devices.html(cardsHTML);
        $('select').formSelect();
    });
}

$(document).on('click', '.ping-btn', function() {
    const device = $(this).data('device');
    ping(device);
});

$(document).on('click', '.scheme-btn', function() {
    const device = $(this).data('device');
    const value = $(`#scheme-${device}`).val();
    runScheme(device, value);
});

function ping(device) {
    loader();
    $.post('/api/ping/' + device, function(data){
    }).done(function(data){
        const message = data.status;
        showToast(message);
        showResult(device, message);
        update_devices();
    });
}

function test(device) {
    $.post(`/api/test?device=${device}`, function(data){})
    .done(function(data) {
        const message = data.status;
        showToast(message);
        showResult(device, message);
    })
    .fail(function() {
        const error = "Error returned, likely the node threw an exception. Check the logs.";
        showToast(error);
        showResult(device, error);
    });
}

function testCategory(device, category) {
    let endpoint = '/api/test_' + category.toLowerCase();

    $.post(`${endpoint}?device=${device}`, function(data){})
    .done(function(data) {
        const message = data.status;
        showToast(message);
        showResult(device, message);
    })
    .fail(function() {
        const error = "Test failed. Check the logs.";
        showToast(error);
        showResult(device, error);
    });
}

function formatTestResults(data) {
    if (!data.results) return data.status;

    let html = `<strong>${data.status}</strong><ul>`;
    for (const [scheme, result] of Object.entries(data.results)) {
        html += `<li><strong>${scheme}</strong>: ${result}</li>`;
    }
    html += `</ul>`;
    return html;
}

function connect() {
    $.post('/api/connect', function(data){
        const message = data.status;
        showToast(message);
        update_devices();
        get_port();
        get_id();
        $('#connect').prop('disabled', true);
        $('#disconnect').prop('disabled', false);
    });
}

function disconnect() {
    $.post('/api/disconnect', function(data){
        const message = data.status;
        showToast(message);
        update_devices();
        get_port();
        get_id();
        $('#connect').prop('disabled', false);
        $('#disconnect').prop('disabled', true);
    });
}

function FindIntersection(device, scheme, type, rounds = 1) {
    const data = {
        "device": device,
        "scheme": scheme,
        "type": type,
        "rounds": rounds
    };
    $.ajax({
        url: '/api/intersection',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(data),
        dataType: 'json',
        success: function(response) {
            const message = response.status;
            const successMsg = `<div>
                <strong>Ejecución finalizada:</strong><br>
                <strong>Dispositivo:</strong> ${device}<br>
                <strong>Esquema:</strong> ${scheme}<br>
                <strong>Tipo:</strong> ${type}<br>
                <strong>Rondas:</strong> ${rounds}<br>
                <strong>Estado:</strong> ${message}
            </div>`;
            showToast(`${scheme} ejecutado en ${device}`);
            showResult(device, successMsg);
        },
        error: function(xhr, status, error) {
            const errorMsg = `<div>
                <strong>Error durante la ejecución</strong><br>
                <strong>Dispositivo:</strong> ${device}<br>
                <strong>Esquema:</strong> ${scheme}<br>
                <strong>Tipo:</strong> ${type}<br>
                <strong>Rondas:</strong> ${rounds}<br>
                <strong>Detalles:</strong> ${error || "Error desconocido"}
            </div>`;
            showToast(`Error al ejecutar ${scheme} en ${device}`);
            showResult(device, errorMsg);
        }
    });
}

$(document).on('click', '.scheme-btn', function() {
    const device = $(this).data('device');
    const value = $(`.scheme-selector[data-device="${device}"]`).val();
    runScheme(device, value);
});

function runScheme(device, value) {
    if (!value || !value.includes('|')) {
        showToast("⚠️ Esquema no válido. Selecciona uno para continuar.");
        showResult(device, `<strong>Error:</strong> No se seleccionó un esquema válido.`);
        return;
    }

    const [scheme, type] = value.split('|').map(s => s.trim());

    const startMsg = `<div>
        <strong>Iniciando algoritmo:</strong><br>
        <strong>Dispositivo:</strong> ${device}<br>
        <strong>Esquema:</strong> ${scheme}<br>
        <strong>Tipo:</strong> ${type}<br>
        <em>Esperando respuesta...</em>
    </div>`;
    showResult(device, startMsg);
    showToast(`Iniciando algoritmo para ${scheme} (${device})`);

    FindIntersection(device, scheme, type, 1);
}

function showToast(message) {
    if (typeof M !== 'undefined' && M.toast) {
        M.toast({ html: message });
    } else {
        alert(message);
    }
}

function showResult(device, message) {
    $(`#result-${device}`).html(`<div class="result-block">${message}</div>`);
}

function discover_peers() {
    loader();
    $.ajax({
        type: 'POST',
        url: '/api/discover_peers',
        beforeSend: function() {
            $('.preloader-wrapper').show();
        },
        success: function(data) {
            const message = data.status;
            showToast(message);
            setTimeout(function() {
                $('.preloader-wrapper').hide();
                update_devices();
            }, 2000);
        }
    });
}

function mykeys() {
  $.get('/api/mykeys', function(data) {
    let message = "<h3>Claves y claves compartidas</h3>";
    for (const [scheme, keyObj] of Object.entries(data)) {
      if (keyObj.public_key) {
        message += `<h4>${scheme}</h4><pre>${keyObj.public_key}</pre>`;
      } else if (keyObj.shared_key) {
        message += `<h4>${scheme} (shared)</h4><pre>${keyObj.shared_key}</pre>`;
      }
    }

    const win = window.open();
    win.document.write('<html><body>' + message + '</body></html>');
  });
}

function my_data() {
  $.get('/api/dataset', function(data) {
    const dataset = data.dataset;
    const message = `<h3>Mi Dataset</h3><ul>${dataset.map(item => `<li>${item}</li>`).join('')}</ul>`;
    const win = window.open();
    win.document.write('<html><body>' + message + '</body></html>');
  });
}

function results() {
  $.get('/api/results', function(data) {
    const result = data.result;
    let grouped = {};

    for (const [key, value] of Object.entries(result)) {
      const parts = key.split(" ");
      const device = parts[0];
      const rest = parts.slice(1).join(" ");

      if (!grouped[device]) grouped[device] = {};
      grouped[device][rest] = value;
    }

    let message = "<h3>Resultados</h3>";
    for (const [device, entries] of Object.entries(grouped)) {
      message += `<h4>Dispositivo: ${device}</h4><ul>`;
      for (const [desc, value] of Object.entries(entries)) {
        let displayValue = value;
        if (typeof value === "string" && value.length > 50) {
          displayValue = value.slice(0, 50) + "...";
        }
        message += `<li><strong>${desc}</strong>: <code>${displayValue}</code></li>`;
      }
      message += "</ul>";
    }

    const win = window.open();
    win.document.write('<html><body>' + message + '</body></html>');
  });
}

function genkeys(scheme, bitlength) {
  $.post(`/api/genkeys?scheme=${scheme}&bit_length=${bitlength}`, function(data) {
    const message = data.status;
    showToast(`Generación de claves para ${scheme}: ${message}`);
  }).fail(() => {
    showToast(`Error al generar claves para ${scheme}.`);
  });
}

function check_connection() {
    $.get('/api/check_connection', function(data){
        if (data.status === nodeNotConnected) {
            $('#connect').prop('disabled', false);
            $('#disconnect').prop('disabled', true);
        } else {
            $('#connect').prop('disabled', true);
            $('#disconnect').prop('disabled', false);
        }
    });
}

function check_tasks() {
    setInterval(function() {
        $.get('/api/tasks', function(data) {
            let nodeStatus = data.status[0];
            let handlerStatus = data.status[1];
            $('#pending_node').text(nodeStatus);
            $('#pending_handler').text(handlerStatus);
        });
    }, 1000);
}

function toggleTheme() {
    document.body.classList.toggle("dark-mode");
    document.querySelector('.left-menu').classList.toggle("dark-mode");
    document.querySelector('.content').classList.toggle("dark-mode");
    document.querySelectorAll('.card').forEach(card => card.classList.toggle("dark-mode"));

    const isDark = document.body.classList.contains("dark-mode");
    const toggleBtn = document.querySelector('button[onclick="toggleTheme()"]');
    toggleBtn.innerHTML = isDark ? "☀️ Modo Claro" : "🌙 Modo Oscuro";
    localStorage.setItem("darkMode", isDark);
}
