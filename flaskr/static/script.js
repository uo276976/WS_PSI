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
    loader();
    $.getJSON('/api/devices', function(data){
        $('#devices').empty();
        if (data.status === nodeNotConnected) {
            $('#devicesConnected').html('<h2>El nodo está apagado</h2>');
        } else {
            $('#devicesConnected').html('<h2>Dispositivos registrados</h2>');
            $.each(data, function(key, value){
                let displayKey = key;
                if (/:/.test(key)) {
                    displayKey = key.replace(/:.*:/, '::');
                }
                $('#devices').append(`
                    <div class="card blue-grey darken-1" id="card-${key}">
                        <div class="card-content white-text">
                            <span class="card-title">${displayKey}</span>
                            <p>Última conexión: ${value}</p>
                            <div class="result-message" id="result-${key}" style="margin-top: 10px;"></div>
                        </div>
                        <div class="card-action">
                            <a class="btn-small" onclick="ping('${key}')">Ping</a>
                            <a class="btn-small" onclick="test('${key}')">Test</a>
                            <div class="input-field inline">
                                <select id="scheme-${key}">
                                    <option value="Paillier PSI-Domain">Paillier PSI-Domain</option>
                                    <option value="Damgard-Jurik PSI-Domain">Damgard-Jurik PSI-Domain</option>
                                    <option value="Paillier OPE">Paillier OPE</option>
                                    <option value="Damgard-Jurik OPE">Damgard-Jurik OPE</option>
                                    <option value="Paillier PSI-CA OPE">Cardinality - Paillier</option>
                                    <option value="Damgard-Jurik PSI-CA OPE">Cardinality - Damgard-Jurik</option>
                                </select>
                                <button class="btn-small btn-dark" onclick="runScheme('${key}')">Iniciar</button>
                            </div>
                        </div>
                    </div>
                `);                
            });
            $('select').formSelect();
        }
    });
}

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
        success: function(data) {
            const message = data.status;
            showToast(message);
            showResult(device, message);
        }
    });
}

function runScheme(device) {
    const value = $(`#scheme-${device}`).val();
    const [scheme, type] = value.split(' ');
    FindIntersection(device, scheme, type || 'OPE');
}

function showToast(message) {
    M.toast({html: message});
}

function showResult(device, message) {
    $(`#result-${device}`).html(`<span class="green-text text-lighten-4">${message}</span>`);
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
    $.get('/api/mykeys', function(data){
        const message = "Claves públicas: \n\nPaillier\nn: " + data.pubkeyN + "\ng: " + data.pubkeyG +
                        "\n\nDamgard-Jurik\nn: " + data.pubkeyNDJ + "\ns: " + data.pubkeySDJ + "\nm: " + data.pubkeyMDJ;
        window.open().document.write('<pre>' + message + '</pre>');
    });
}

function my_data() {
    $.get('/api/dataset', function(data){
        const message = "Dataset: " + data.dataset;
        window.open().document.write('<pre>' + message + '</pre>');
    });
}

function results() {
    $.get('/api/results', function(data){
        const message = "Result: " + JSON.stringify(data.result, null, 2);
        window.open().document.write('<pre>' + message + '</pre>');
    });
}

function genkeys(scheme, bitlength) {
    $.post(`/api/genkeys?scheme=${scheme}&bit_length=${bitlength}`, function(data){
        const message = data.status;
        showToast(message);
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
