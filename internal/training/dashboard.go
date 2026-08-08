// internal/training/dashboard.go
// Live training metrics dashboard — serves on localhost:8077
// Reads /tmp/grpo-metrics.log and renders charts via Chart.js
package training

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type MetricPoint struct {
	Step   int     `json:"step"`
	Total  int     `json:"total"`
	Reward float64 `json:"reward"`
	Loss   float64 `json:"loss"`
	Time   string  `json:"time"`
}

var (
	dashboardOnce sync.Once
	metricsPath   = "/tmp/grpo-metrics.log"
)

func parseMetricsLog() []MetricPoint {
	f, err := os.Open(metricsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	re := regexp.MustCompile(`\[grpo\] step (\d+)/(\d+), reward=([\d.]+), loss=([\d.]+)`)
	var points []MetricPoint

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "checkpoint") {
			continue
		}
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		step, _ := strconv.Atoi(m[1])
		total, _ := strconv.Atoi(m[2])
		reward, _ := strconv.ParseFloat(m[3], 64)
		loss, _ := strconv.ParseFloat(m[4], 64)
		points = append(points, MetricPoint{
			Step: step, Total: total, Reward: reward, Loss: loss,
			Time: time.Now().Format("15:04:05"),
		})
	}
	return points
}

func handleMetricsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	points := parseMetricsLog()
	json.NewEncoder(w).Encode(points)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, dashboardHTML)
}

// StartDashboard launches the metrics dashboard server on port 8077.
func StartDashboard() {
	dashboardOnce.Do(func() {
		http.HandleFunc("/", handleDashboard)
		http.HandleFunc("/api/metrics", handleMetricsAPI)
		go func() {
			fmt.Fprintf(os.Stderr, "[dashboard] serving at http://localhost:8077\n")
			http.ListenAndServe(":8077", nil)
		}()
	})
}

const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<title>StreamGRPO Training Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
  h1 { color: #00d4ff; margin-bottom: 5px; }
  .subtitle { color: #888; margin-bottom: 20px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
  .card { background: #16213e; border-radius: 12px; padding: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
  .stat-row { display: flex; justify-content: space-between; gap: 15px; margin-bottom: 20px; }
  .stat { background: #0f3460; border-radius: 8px; padding: 15px 20px; flex: 1; text-align: center; }
  .stat .value { font-size: 2em; font-weight: bold; color: #00d4ff; }
  .stat .label { font-size: 0.85em; color: #888; margin-top: 4px; }
  canvas { max-height: 300px; }
  .status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; }
  .status.active { background: #00ff88; animation: pulse 1.5s infinite; }
  .status.idle { background: #666; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  .log { background: #0a0a1a; border-radius: 8px; padding: 15px; font-family: monospace; font-size: 0.85em; max-height: 200px; overflow-y: auto; white-space: pre-wrap; color: #aaa; }
</style>
</head>
<body>
<h1>StreamGRPO Training Dashboard</h1>
<p class="subtitle"><span class="status" id="statusDot"></span><span id="statusText">Checking...</span></p>

<div class="stat-row">
  <div class="stat"><div class="value" id="stepVal">—</div><div class="label">Step</div></div>
  <div class="stat"><div class="value" id="rewardVal">—</div><div class="label">Reward</div></div>
  <div class="stat"><div class="value" id="lossVal">—</div><div class="label">Loss</div></div>
  <div class="stat"><div class="value" id="etaVal">—</div><div class="label">ETA</div></div>
</div>

<div class="grid">
  <div class="card"><canvas id="rewardChart"></canvas></div>
  <div class="card"><canvas id="lossChart"></canvas></div>
</div>

<div class="card">
  <h3 style="margin-top:0">Training Log</h3>
  <div class="log" id="logArea">Waiting for data...</div>
</div>

<script>
const rewardCtx = document.getElementById('rewardChart').getContext('2d');
const lossCtx = document.getElementById('lossChart').getContext('2d');

const rewardChart = new Chart(rewardCtx, {
  type: 'line',
  data: { labels: [], datasets: [{ label: 'Reward', data: [], borderColor: '#00ff88', backgroundColor: 'rgba(0,255,136,0.1)', fill: true, tension: 0.3 }] },
  options: { plugins: { title: { display: true, text: 'Reward per Step', color: '#eee' } }, scales: { x: { ticks: { color: '#888' } }, y: { ticks: { color: '#888' }, beginAtZero: true } } }
});

const lossChart = new Chart(lossCtx, {
  type: 'line',
  data: { labels: [], datasets: [{ label: 'Loss', data: [], borderColor: '#ff6b6b', backgroundColor: 'rgba(255,107,107,0.1)', fill: true, tension: 0.3 }] },
  options: { plugins: { title: { display: true, text: 'Loss per Step', color: '#eee' } }, scales: { x: { ticks: { color: '#888' } }, y: { ticks: { color: '#888' } } } }
});

let lastLen = 0;

async function refresh() {
  try {
    const resp = await fetch('/api/metrics');
    const data = await resp.json();
    if (!data || data.length === 0) {
      document.getElementById('statusDot').className = 'status idle';
      document.getElementById('statusText').textContent = 'No training data yet';
      return;
    }

    document.getElementById('statusDot').className = 'status active';
    const last = data[data.length - 1];
    document.getElementById('statusText').textContent = 'Training in progress — step ' + last.step + '/' + last.total;
    document.getElementById('stepVal').textContent = last.step + '/' + last.total;
    document.getElementById('rewardVal').textContent = last.reward.toFixed(3);
    document.getElementById('lossVal').textContent = last.loss.toFixed(4);

    // ETA estimate
    if (data.length >= 2) {
      const stepsRemaining = last.total - last.step;
      const avgMinPerStep = 2; // approximate
      const etaMin = stepsRemaining * avgMinPerStep;
      if (etaMin > 60) document.getElementById('etaVal').textContent = (etaMin/60).toFixed(1) + 'h';
      else document.getElementById('etaVal').textContent = etaMin + 'min';
    }

    // Update charts
    const labels = data.map(d => d.step);
    const rewards = data.map(d => d.reward);
    const losses = data.map(d => d.loss);

    rewardChart.data.labels = labels;
    rewardChart.data.datasets[0].data = rewards;
    rewardChart.update();

    lossChart.data.labels = labels;
    lossChart.data.datasets[0].data = losses;
    lossChart.update();

    // Log area
    if (data.length !== lastLen) {
      const logLines = data.map(d => '[step ' + d.step + '] reward=' + d.reward.toFixed(3) + ' loss=' + d.loss.toFixed(4));
      document.getElementById('logArea').textContent = logLines.join('\\n');
      lastLen = data.length;
    }
  } catch (e) {
    document.getElementById('statusDot').className = 'status idle';
    document.getElementById('statusText').textContent = 'Dashboard server error: ' + e.message;
  }
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`
