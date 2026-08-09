const express = require('express');
const bodyParser = require('body-parser');
const moment = require('moment-timezone');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());

let data = {};

app.post('/data', (req, res) => {
  const { id, bpm } = req.body;
  
  if (!id || bpm === undefined) {
    return res.status(400).json({ message: 'Invalid input. Please provide id and bpm.' });
  }

  const timestamp = moment().tz("Asia/Kolkata").format('DD-MM-YYYY HH:mm:ss');

  if (!data[id]) {
    data[id] = [];
  }

  data[id].push({ id, timestamp, bpm });

  return res.status(201).json({ message: 'Data added successfully.', d: { id, timestamp, bpm } });
});

app.get('/data', (req, res) => {
  return res.status(200).json(data);
});

app.get('/data/:id', (req, res) => {
  const { id } = req.params;

  if (!data[id]) {
    return res.status(404).json({ message: 'Data not found.' });
  }

  return res.status(200).json(data[id]);
});

app.get('/', (req, res) => {
  const htmlContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sensor Data</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f4f7f6;
                display: flex;
                flex-direction: column;
                align-items: center;
                padding: 20px;
            }
            h1 {
                color: #333;
            }
            
            table {
                width: 80%;
                border-collapse: collapse;
                margin-bottom: 20px;
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            table, th, td {
                border: 1px solid #ddd;
            }
            th, td {
                padding: 10px;
                text-align: center;
            }
            th {
                background-color: #4CAF50;
                color: white;
            }
            td {
                background-color: #f9f9f9;
            }

            select {
                padding: 10px;
                margin-top: 20px;
                font-size: 16px;
                border: 1px solid #ccc;
                border-radius: 5px;
            }

            canvas {
                width: 80% !important;
                max-width: 800px;
                height: 400px;
                margin-top: 20px;
                border: 1px solid #ccc;
                border-radius: 5px;
            }

            .table-container {
                max-height: 400px;
                overflow-y: auto;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>

        <h1>Sensor Data</h1>

        <div class="table-container">
            <table id="data-table">
                <thead>
                    <tr>
                        <th>Sensor ID</th>
                        <th>Date (DD/MM/YYYY)</th>
                        <th>Time (HH:MM:SS)</th>
                        <th>BPM</th>
                    </tr>
                </thead>
                <tbody id="table-body">
                    </tbody>
            </table>
        </div>

        <select id="sensor-dropdown">
            <option value="none">None</option>
            <option value="sensor1">Sensor 1</option>
            <option value="sensor2">Sensor 2</option>
        </select>

        <canvas id="sensorGraph"></canvas>

        <script>
            
            fetch('/data')
                .then(response => response.json())
                .then(data => {
                    const tableBody = document.getElementById('table-body');
                    Object.keys(data).forEach(sensor => {
                        data[sensor].forEach(item => {
                            const row = document.createElement('tr');
                            row.innerHTML = \`
                                <td>\${sensor}</td>
                                <td>\${item.timestamp.split(' ')[0]}</td>
                                <td>\${item.timestamp.split(' ')[1]}</td>
                                <td>\${item.bpm}</td>
                            \`;
                            tableBody.appendChild(row);
                        });
                    });
                });

            const sensorDropdown = document.getElementById('sensor-dropdown');
            const sensorGraph = document.getElementById('sensorGraph');
            const chartCtx = sensorGraph.getContext('2d');
            let chart;

            sensorDropdown.addEventListener('change', (event) => {
                const sensorId = event.target.value;

                if (chart) {
                    chart.destroy();
                }

                if (sensorId === 'none') {
                    sensorGraph.style.display = 'none';
                } else {
                    fetch(\`/data/\${sensorId}\`)
                        .then(response => response.json())
                        .then(sensorData => {
                            const labels = sensorData.map(item => item.timestamp);
                            const bpmData = sensorData.map(item => item.bpm);
                            
                            sensorGraph.style.display = 'block';

                            chart = new Chart(chartCtx, {
                                type: 'line',
                                data: {
                                    labels: labels,
                                    datasets: [{
                                        label: 'BPM over Time',
                                        data: bpmData,
                                        borderColor: 'rgba(75, 192, 192, 1)',
                                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                                        fill: true
                                    }]
                                },
                                options: {
                                    scales: {
                                        x: {
                                            title: {
                                                display: true,
                                                text: 'Date and Time (DD/MM/YYYY HH:MM:SS)'
                                            }
                                        },
                                        y: {
                                            title: {
                                                display: true,
                                                text: 'BPM'
                                            }
                                        }
                                    }
                                }
                            });
                        });
                }
            });
        </script>
    </body>
    </html>
  `;

  res.send(htmlContent);
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
