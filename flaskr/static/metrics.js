$(document).ready(function(){
    get_id();
    populate_table();
    drawComparisonChart();

    document.getElementById('download-excel').addEventListener('click', downloadExcel);

    $('#categoryFilter').on('change', function () {
        const selected = $(this).val();
        drawComparisonChart(selected);
    });
});

function get_id() {
    $.get('/api/id', function(data){
        $('#mylogs').text("Logs recuperados de " + data.id);
    });
}

function populate_table() {
    showSpinner();

    $.getJSON('/api/logs', function(data){
        const tbody = $('#logs-body');
        tbody.empty();

        $.each(data, function(_, value){
            tbody.append(`
                <tr>
                    <td>${value['timestamp']}</td>
                    <td>${value['activity_code']}</td>
                    <td>${value['time']}</td>
                    <td>${value['Avg_RAM']}</td>
                    <td>${value['Avg_instance_RAM']}</td>
                    <td>${value['Avg_CPU']}</td>
                    <td>${value['Avg_instance_CPU']}</td>
                </tr>
            `);
        });

        if ($.fn.dataTable.isDataTable('#logs')) {
            $('#logs').DataTable().destroy();
        }

        $('#logs').DataTable({
            pageLength: 10,
            lengthMenu: [5, 10, 25, 50, 100],
            order: [[0, 'desc']],
            dom: 'Bfrtip',
            buttons: [
                'copy', 'csv', 'excel', 'pdf', 'print'
            ],
            language: {
                search: "Buscar:",
                lengthMenu: "Mostrar _MENU_ entradas",
                info: "Mostrando _START_ a _END_ de _TOTAL_ entradas",
                paginate: {
                    next: "Siguiente",
                    previous: "Anterior"
                },
                zeroRecords: "No se encontraron resultados"
            }
        });

        hideSpinner();
    });
}

function showSpinner() {
    $('#loading-spinner').css('display', 'block');
}

function hideSpinner() {
    $('#loading-spinner').css('display', 'none');
}

function drawChart(data) {
    const labels = data.map(d => d.timestamp);
    const cpu = data.map(d => d.Avg_CPU);
    const ram = data.map(d => d.Avg_RAM);

    const ctx = document.getElementById('metricsChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Avg CPU (%)',
                    data: cpu,
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.2
                },
                {
                    label: 'Avg RAM (MB)',
                    data: ram,
                    borderColor: 'rgb(54, 162, 235)',
                    tension: 0.2
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top'
                },
                title: {
                    display: true,
                    text: 'Uso de recursos del nodo'
                }
            }
        }
    });
}

let fullSummaryData = [];

function drawComparisonChart(category = "All") {
    $.getJSON('/api/summary', function(response) {
        const data = response.summary;
        const categories = response.categories;

        // Populate dropdown (once)
        if ($('#categoryFilter option').length <= 1) {
            categories.forEach(cat => {
                $('#categoryFilter').append(`<option value="${cat}">${cat}</option>`);
            });
        }

        const filtered = category === "All"
            ? data
            : data.filter(entry => entry.category === category);

        const labels = filtered.map(entry => entry.scheme);
        const times = filtered.map(entry => entry.avg_time);

        const ctx = document.getElementById('metricsChart').getContext('2d');
        if (window.comparisonChart) window.comparisonChart.destroy();

        window.comparisonChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Tiempo Promedio (s)',
                    data: times,
                    backgroundColor: 'rgba(54, 162, 235, 0.6)'
                }]
            },
            options: {
                plugins: {
                    title: {
                        display: true,
                        text: `Tiempo promedio por esquema${category !== "All" ? " (" + category + ")" : ""}`
                    }
                },
                responsive: true
            }
        });
    });
}

function downloadExcel() {
    const table = document.getElementById('logs');
    // Convertir la tabla a formato de SheetJS
    const ws = XLSX.utils.table_to_sheet(table);
    const wb = XLSX.utils.book_new();
    // Añadir la hoja de cálculo al libro
    XLSX.utils.book_append_sheet(wb, ws, 'Logs');
    // Generar el archivo
    XLSX.writeFile(wb, 'logs.xlsx');
}