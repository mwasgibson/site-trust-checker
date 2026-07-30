function scoreColor(score) {
  if (score >= 80) return '#27ae60';
  if (score >= 55) return '#f1c40f';
  if (score >= 30) return '#e67e22';
  return '#c0392b';
}

function renderReport(data) {
  document.getElementById('status').style.display = 'none';

  const scoreContainer = document.getElementById('score-container');
  scoreContainer.style.display = 'flex';

  const scoreEl = document.getElementById('score');
  scoreEl.textContent = data.score;
  scoreEl.style.color = scoreColor(data.score);

  document.getElementById('verdict').innerHTML =
    `<span class="badge" style="background:${scoreColor(data.score)}"></span>${data.verdict}${data.isAdmin ? ' &middot; <b>admin</b>' : ''}`;

  const reasonsEl = document.getElementById('reasons');
  reasonsEl.innerHTML = '';

  if (!data.reasons || data.reasons.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No issues found.';
    reasonsEl.appendChild(li);
    return;
  }

  for (const reason of data.reasons) {
    const li = document.createElement('li');
    li.className = `sev-${reason.severity}`;
    li.textContent = reason.message;
    reasonsEl.appendChild(li);
  }
}

function renderError(message) {
  document.getElementById('status').textContent = `Error: ${message}`;
  document.getElementById('status').style.display = 'block';
}

async function runAnalysis(url, tabId) {
  document.getElementById('status').textContent = 'Analyzing...';
  document.getElementById('status').style.display = 'block';
  document.getElementById('score-container').style.display = 'none';
  document.getElementById('reasons').innerHTML = '';

  chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url, tabId }, (response) => {
    if (chrome.runtime.lastError) {
      renderError(chrome.runtime.lastError.message);
      return;
    }
    if (!response.ok) {
      renderError(response.error);
      return;
    }
    renderReport(response.data);
  });
}

let currentUrl = null;
let currentTabId = null;

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab || !tab.url || !tab.url.startsWith('http')) {
    document.getElementById('url').textContent = 'Not a scannable page';
    document.getElementById('status').textContent = '';
    return;
  }
  currentUrl = tab.url;
  currentTabId = tab.id;
  document.getElementById('url').textContent = tab.url;
  runAnalysis(tab.url, tab.id);
});

document.getElementById('rescan').addEventListener('click', () => {
  if (currentUrl) runAnalysis(currentUrl, currentTabId);
});

// Show the user's ID so they can add it to ADMIN_USER_IDS in the
// backend's .env if they want unlimited access.
chrome.runtime.sendMessage({ type: 'GET_USER_ID' }, (response) => {
  if (response && response.ok) {
    document.getElementById('user-id-row').textContent = `ID: ${response.userId}`;
  }
});
