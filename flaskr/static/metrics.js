$(document).ready(function () {
  initPage();
});

function initPage() {
  getNodeId();
  loadLogsTable();
  loadSummaryAndChart();

  $('#download-excel').on('click', downloadExcel);
  $('#categoryFilter').on('change', applyFilters);
  $('#deviceTypeFilter').on('change', applyFilters);
}

function getNodeId() {
  $.get('/api/id', function (data) {
    $('#mylogs').text("Logs recuperados de " + data.id);
  });
}

function loadLogsTable() {
  showSpinner();

  $.getJSON('/api/logs', function (logs) {
    const tbody = $('#logs-body');
    tbody.empty();

    logs.forEach(log => {
      const relCpu = log.Relative_CPU_Load ? `${log.Relative_CPU_Load}` : "N/A";
      const relRam = log.Relative_RAM_Load ? `${log.Relative_RAM_Load}` : "N/A";
      const deviceType = log.device_type || "Unknown";
      const profile = log.Resource_Profile || "";
      const warning = (parseFloat(relCpu) > 90 || parseFloat(relRam) > 90);

      tbody.append(`
        <tr class="${warning ? 'table-danger' : ''}">
          <td>${log.timestamp}</td>
          <td>${log.activity_code}</td>
          <td>${log.time}s</td>
          <td>
            ${log.Avg_RAM}<br>
            <small class="text-muted">Rel: ${relRam}</small>
          </td>
          <td>
            ${log.Avg_instance_RAM}<br>
            <small class="text-muted">Rel: ${relRam}</small>
          </td>
          <td>
            ${log.Avg_CPU}<br>
            <small class="text-muted">Rel: ${relCpu}</small>
          </td>
          <td>
            ${log.Avg_instance_CPU}<br>
            <small class="text-muted">Rel: ${relCpu}</small>
          </td>
          <td>
            <span class="badge bg-${deviceType === 'IoT' ? 'warning' : (deviceType === 'WS' ? 'primary' : 'secondary')}">
              ${deviceType}
            </span>
            <br><small>${profile}</small>
          </td>
        </tr>
      `);
    });

    if ($.fn.dataTable.isDataTable('#log-table')) {
      $('#log-table').DataTable().destroy();
    }

    $('#log-table').DataTable({
      pageLength: 10,
      lengthMenu: [5, 10, 25, 50, 100],
      order: [[0, 'desc']],
      dom: 'Bfrtip',
      buttons: ['copy', 'csv', 'excel', 'pdf', 'print'],
      language: {
        search: "Buscar:",
        lengthMenu: "Mostrar _MENU_ entradas",
        info: "Mostrando _START_ a _END_ de _TOTAL_ entradas",
        paginate: { next: "Siguiente", previous: "Anterior" },
        zeroRecords: "No se encontraron resultados"
      }
    });

    hideSpinner();
  });
}

let globalSummaryData = [];

function loadSummaryAndChart() {
  $.getJSON('/api/summary', function (response) {
    globalSummaryData = response.summary || [];
    renderStats(globalSummaryData);
    drawComparisonChart(globalSummaryData);
  });
}

function applyFilters() {
  const category = $('#categoryFilter').val() || "All";
  const deviceType = $('#deviceTypeFilter').val() || "All";

  let filtered = globalSummaryData;

  if (category !== "All") {
    filtered = filtered.filter(item => item.category === category);
  }
  if (deviceType !== "All") {
    filtered = filtered.filter(item => item.device_type === deviceType);
  }

  renderStats(filtered);
  drawComparisonChart(filtered);
}

function drawComparisonChart(data) {
  const ctx = document.getElementById('metricsChart').getContext('2d');

  if (window.comparisonChart) {
    window.comparisonChart.destroy();
  }

  const labels = data.map(d => d.scheme);
  const times = data.map(d => d.avg_time);
  const cpu = data.map(d => d.avg_cpu);
  const ram = data.map(d => d.avg_ram);

  window.comparisonChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Tiempo Promedio (s)',
          data: times,
          backgroundColor: 'rgba(54, 162, 235, 0.7)',
          yAxisID: 'y1'
        },
        {
          label: 'CPU Promedio (%)',
          data: cpu,
          backgroundColor: 'rgba(255, 99, 132, 0.7)',
          yAxisID: 'y2'
        },
        {
          label: 'RAM Promedio (MB)',
          data: ram,
          backgroundColor: 'rgba(75, 192, 192, 0.7)',
          yAxisID: 'y2'
        }
      ]
    },
    options: {
      responsive: true,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        title: {
          display: true,
          text: 'Comparativa de esquemas y recursos'
        },
        legend: {
          position: 'top'
        }
      },
      scales: {
        y1: {
          type: 'linear',
          position: 'left',
          title: { display: true, text: 'Tiempo (s)' }
        },
        y2: {
          type: 'linear',
          position: 'right',
          title: { display: true, text: 'CPU (%) / RAM (MB)' }
        }
      }
    }
  });
}

function renderStats(data) {
  if (!data.length) {
    $('#stats-cards').html(`<p>No hay datos para mostrar.</p>`);
    return;
  }

  const avgTime = (data.reduce((a, b) => a + b.avg_time, 0) / data.length).toFixed(2);
  const avgCPU = (data.reduce((a, b) => a + b.avg_cpu, 0) / data.length).toFixed(2);
  const avgRAM = (data.reduce((a, b) => a + b.avg_ram, 0) / data.length).toFixed(2);

  $('#stats-cards').html(`
    <div class="col s4"><div class="card"><div class="card-content center-align">
      <h5>${avgTime}s</h5><p>Tiempo promedio</p>
    </div></div></div>
    <div class="col s4"><div class="card"><div class="card-content center-align">
      <h5>${avgCPU}%</h5><p>CPU promedio</p>
    </div></div></div>
    <div class="col s4"><div class="card"><div class="card-content center-align">
      <h5>${avgRAM} MB</h5><p>RAM promedio</p>
    </div></div></div>
  `);
}

function showSpinner() {
  $('#loading-spinner').show();
}

function hideSpinner() {
  $('#loading-spinner').hide();
}

function downloadExcel() {
  const table = document.getElementById('log-table');
  const ws = XLSX.utils.table_to_sheet(table);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Logs');
  XLSX.writeFile(wb, 'logs.xlsx');
}
