$(document).ready(function(){
    get_id();
    populate_table();
    document.getElementById('download-excel').addEventListener('click', downloadExcel);
});

function get_id() {
    $.get('/api/id', function(data){
        $('#mylogs').text("Logs recuperados de " + data.id);
    });
}

function populate_table() {
    $('#loading-spinner').show();
  
    $.getJSON('/api/logs', function(data){
        $('#logs').empty();
  
        $.each(data, function(key, value){
            $('#logs').append('<tr><td>' + value['timestamp'] + '</td><td>' + value['activity_code'] + '</td><td>' + value['time'] + '</td><td>' + value['Avg_RAM'] + '</td><td>' + value['Avg_instance_RAM'] + '</td><td>' + value['Avg_CPU'] + '</td><td>' + value['Avg_instance_CPU'] + '</td></tr>');
        });
  
        drawChart(Object.values(data));
        $('#logs').DataTable();  // Enable search/pagination
    })
    .always(function() {
      $('#loading-spinner').hide();
    });
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