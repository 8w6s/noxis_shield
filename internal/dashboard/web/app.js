// UI Elements
const valRps = document.getElementById('valRps');
const valBlocked = document.getElementById('valBlocked');
const valConns = document.getElementById('valConns');
const valEbpf = document.getElementById('valEbpf');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const bannedCount = document.getElementById('bannedCount');
const eventsBody = document.getElementById('eventsBody');

// Chart Setup with Premium Aesthetics
const ctx = document.getElementById('trafficChart').getContext('2d');

// Gradient for the line fill
let gradientBlue = ctx.createLinearGradient(0, 0, 0, 350);
gradientBlue.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
gradientBlue.addColorStop(1, 'rgba(59, 130, 246, 0.0)');

let gradientRed = ctx.createLinearGradient(0, 0, 0, 350);
gradientRed.addColorStop(0, 'rgba(239, 68, 68, 0.4)');
gradientRed.addColorStop(1, 'rgba(239, 68, 68, 0.0)');

const commonOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
        duration: 400,
        easing: 'easeOutQuart'
    },
    scales: {
        x: {
            display: false, // hide x-axis for a cleaner look
        },
        y: {
            beginAtZero: true,
            grid: {
                color: 'rgba(255, 255, 255, 0.05)',
                drawBorder: false,
            },
            ticks: {
                color: '#94a3b8',
                font: { family: 'Outfit', size: 11 }
            }
        }
    },
    plugins: {
        legend: { display: false },
        tooltip: {
            backgroundColor: 'rgba(13, 15, 26, 0.9)',
            titleFont: { family: 'Outfit', size: 13 },
            bodyFont: { family: 'Outfit', size: 12 },
            padding: 10,
            borderColor: 'rgba(255, 255, 255, 0.1)',
            borderWidth: 1
        }
    },
    elements: {
        point: {
            radius: 0, // hide points by default
            hitRadius: 10,
            hoverRadius: 6
        },
        line: {
            tension: 0.4, // smooth curves
            borderWidth: 3
        }
    }
};

let chartConfig = {
    type: 'line',
    data: {
        labels: Array(60).fill(''), // 60 seconds of data
        datasets: [{
            label: 'Requests Per Second',
            data: Array(60).fill(0),
            borderColor: '#3b82f6',
            backgroundColor: gradientBlue,
            fill: true,
            pointBackgroundColor: '#fff',
            shadowColor: 'rgba(59, 130, 246, 0.5)',
            shadowBlur: 10
        }]
    },
    options: commonOptions
};

const trafficChart = new Chart(ctx, chartConfig);

// WebSocket connection
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // When running locally normally the ws is on the exact same port due to Go HTTP Mux
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        statusDot.className = 'pulse-dot active';
        statusText.textContent = 'Shield Active & Monitoring';
        statusText.style.color = 'var(--text-primary)';
        
        // Clear events dummy
        eventsBody.innerHTML = '';
    };

    ws.onclose = () => {
        statusDot.className = 'pulse-dot';
        statusText.textContent = 'Disconnected. Retrying...';
        statusText.style.color = 'var(--text-muted)';
        setTimeout(connectWebSocket, 2000);
    };

    ws.onerror = (err) => {
        console.error('WebSocket Error:', err);
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            updateDashboard(data);
        } catch (e) {
            console.error("Failed to parse message", e);
        }
    };
}

// Update UI
function updateDashboard(stats) {
    // Top counters
    valRps.innerHTML = `${Math.round(stats.currentRPS)} <span class="unit">req/s</span>`;
    valBlocked.textContent = formatNumber(stats.blocked);
    valConns.textContent = formatNumber(stats.activeConnections);
    valEbpf.textContent = formatNumber(stats.ebpfDrops);
    bannedCount.textContent = `${stats.bannedIPs} banned IPs`;

    // Status Indicator & Graph coloring
    if (stats.status === 'under_attack') {
        statusDot.className = 'pulse-dot danger';
        statusText.textContent = 'UNDER ATTACK - Shield Blocking';
        statusText.style.color = 'var(--accent-red)';
        
        trafficChart.data.datasets[0].borderColor = '#ef4444';
        trafficChart.data.datasets[0].backgroundColor = gradientRed;
    } else {
        statusDot.className = 'pulse-dot active';
        statusText.textContent = 'Traffic Normal';
        statusText.style.color = 'var(--text-primary)';
        
        trafficChart.data.datasets[0].borderColor = '#3b82f6';
        trafficChart.data.datasets[0].backgroundColor = gradientBlue;
    }

    // Update Chart Data (shift left, push new)
    const dataset = trafficChart.data.datasets[0].data;
    dataset.shift();
    dataset.push(stats.currentRPS);
    trafficChart.update('none'); // Update without full animation for performance

    // Update Events Table
    if (stats.recentEvents && stats.recentEvents.length > 0) {
        // Just recreate the HTML for simplicity since it's capped at 50
        eventsBody.innerHTML = stats.recentEvents.slice(0, 10).map(ev => {
            const typeColor = ev.type === 'attack_detected' ? 'color: var(--accent-red); font-weight: 600;' : 
                              (ev.type === 'attack_resolved' ? 'color: var(--accent-green);' : 'color: var(--accent-blue);');
            return `
                <tr>
                    <td style="color: var(--text-muted); font-size: 0.9em;">${ev.time}</td>
                    <td style="${typeColor}">${formatEventType(ev.type)}</td>
                    <td>${ev.detail}</td>
                </tr>
            `;
        }).join('');
    } else if (eventsBody.children.length === 0 || eventsBody.innerHTML.includes('Awaiting stream')) {
        eventsBody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No recent anomalies detected.</td></tr>`;
    }
}

function formatNumber(num) {
    return new Intl.NumberFormat('en-US').format(num);
}

function formatEventType(type) {
    return type.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

// Spark off the connection!
connectWebSocket();
