/* ═══════════════════════════════════════════════════════════
   Risk-Aware Upgrade Orchestrator — Dashboard JavaScript
   ═══════════════════════════════════════════════════════════ */

// ── Tab Navigation ──────────────────────────────────
function switchTab(tabId) {
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`[data-tab="${tabId}"]`)?.classList.add('active');
  document.getElementById(tabId)?.classList.add('active');
  if (tabId === 'tab-graph' && !window._graphRendered) {
    loadGraph();
  }
  if (tabId === 'tab-execution') {
    loadExecutions();
    loadNotifications();
  }
}


// ── Score bar color ─────────────────────────────────
function scoreColor(score) {
  if (score >= 70) return 'var(--critical)';
  if (score >= 50) return 'var(--high)';
  if (score >= 30) return 'var(--medium)';
  return 'var(--low)';
}

function riskBadge(level) {
  return `<span class="badge badge-${level}">${level}</span>`;
}

// ── Detail Panel ────────────────────────────────────
function openDetail(planItem) {
  const overlay = document.getElementById('detail-overlay');
  const panel = document.getElementById('detail-panel');
  const content = document.getElementById('detail-content');

  const exp = planItem.explanation || {};
  const riskFactors = exp.risk_factors || [];
  const mitigating = exp.mitigating_factors || [];

  // Score breakdown colors
  const segments = [
    { label: 'Severity', value: planItem.severity_score, color: '#ef4444' },
    { label: 'Exploitability', value: planItem.exploitability_score, color: '#f97316' },
    { label: 'Business Impact', value: planItem.business_impact_score, color: '#f59e0b' },
    { label: 'Blast Radius', value: planItem.blast_radius_score, color: '#3b82f6' },
  ];
  const totalSegments = segments.reduce((s, x) => s + x.value, 0) || 1;

  content.innerHTML = `
    <div class="detail-header">
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:8px;">
        <span class="badge badge-${planItem.risk_level}">${planItem.risk_level}</span>
        <span style="font-family:var(--font-mono);font-size:13px;color:var(--text-secondary)">
          #${planItem.priority_rank}
        </span>
        ${planItem.match_confidence === 'high' ? '' : `<span class="badge" style="background:rgba(234,179,8,0.12);color:var(--medium);border:1px solid rgba(234,179,8,0.2)">${planItem.match_confidence} confidence</span>`}
      </div>
      <div class="detail-title">${planItem.cve_id}</div>
      <div style="font-size:14px;color:var(--text-secondary)">${planItem.component} → ${planItem.service}</div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Score Breakdown (${planItem.final_score.toFixed(1)}/100)</div>
      <div class="score-breakdown">
        ${segments.map(s => `
          <div class="score-segment" style="flex:${s.value};background:${s.color}" title="${s.label}: ${s.value.toFixed(1)}">
            ${s.value >= 15 ? s.value.toFixed(0) : ''}
          </div>
        `).join('')}
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px">
        ${segments.map(s => `
          <div style="font-size:11px;color:var(--text-muted)">
            <span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${s.color};margin-right:4px"></span>
            ${s.label}: <strong style="color:var(--text)">${s.value.toFixed(1)}</strong>
          </div>
        `).join('')}
      </div>
    </div>

    ${exp.summary ? `
    <div class="explanation-card">
      <div class="explanation-label">AI Recommendation</div>
      <p>${exp.summary}</p>
    </div>` : ''}

    ${exp.technical_reason ? `
    <div class="detail-section">
      <div class="detail-section-title">Technical Analysis</div>
      <p style="font-size:13px;color:var(--text-secondary);line-height:1.6">${exp.technical_reason}</p>
    </div>` : ''}

    ${exp.business_reason ? `
    <div class="detail-section">
      <div class="detail-section-title">Business Impact</div>
      <p style="font-size:13px;color:var(--text-secondary);line-height:1.6">${exp.business_reason}</p>
    </div>` : ''}

    ${exp.operational_reason ? `
    <div class="detail-section">
      <div class="detail-section-title">Operational Context</div>
      <p style="font-size:13px;color:var(--text-secondary);line-height:1.6">${exp.operational_reason}</p>
    </div>` : ''}

    <div class="detail-section">
      <div class="detail-section-title">Upgrade Details</div>
      <div class="detail-row"><span class="detail-row-label">Patch Version</span><span class="detail-row-value" style="font-family:var(--font-mono)">${planItem.patch_version}</span></div>
      <div class="detail-row"><span class="detail-row-label">Owner</span><span class="detail-row-value">${planItem.owner_team}</span></div>
      <div class="detail-row"><span class="detail-row-label">Window</span><span class="detail-row-value">${planItem.recommended_window}</span></div>
      <div class="detail-row"><span class="detail-row-label">Target Date</span><span class="detail-row-value">${planItem.target_date}</span></div>
      <div class="detail-row"><span class="detail-row-label">Rollback</span><span class="detail-row-value">${planItem.rollback_complexity}</span></div>
      <div class="detail-row"><span class="detail-row-label">Approval</span><span class="detail-row-value">${planItem.approval_required ? `<span class="badge badge-${planItem.approval_status === 'approved' ? 'approved' : 'pending'}">${planItem.approval_status}</span>` : '<span class="badge badge-approved">Auto-approved</span>'}</span></div>
      ${planItem.cvss_only_rank ? `<div class="detail-row"><span class="detail-row-label">CVSS-Only Rank</span><span class="detail-row-value">#${planItem.cvss_only_rank} ${planItem.cvss_only_rank !== planItem.priority_rank ? `(${planItem.cvss_only_rank > planItem.priority_rank ? '↑ Elevated' : '↓ Deprioritized'})` : ''}</span></div>` : ''}
    </div>

    ${riskFactors.length > 0 ? `
    <div class="detail-section">
      <div class="detail-section-title">⚠ Risk Factors</div>
      <ul class="detail-list">
        ${riskFactors.map(r => `<li>${r}</li>`).join('')}
      </ul>
    </div>` : ''}

    ${mitigating.length > 0 ? `
    <div class="detail-section">
      <div class="detail-section-title">✓ Mitigating Factors</div>
      <ul class="detail-list">
        ${mitigating.map(m => `<li>${m}</li>`).join('')}
      </ul>
    </div>` : ''}

    ${(planItem.downstream_impact || []).length > 0 ? `
    <div class="detail-section">
      <div class="detail-section-title">Blast Radius — Downstream Services</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        ${planItem.downstream_impact.map(d => `<span class="badge" style="background:rgba(59,130,246,0.1);color:var(--info);border:1px solid rgba(59,130,246,0.2)">${d}</span>`).join('')}
      </div>
    </div>` : ''}

    <div class="detail-section">
      <div class="detail-section-title">Pre-checks</div>
      <ul class="detail-list">${(planItem.prechecks || []).map(s => `<li>${s}</li>`).join('')}</ul>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Execution Steps</div>
      <ul class="detail-list">${(planItem.execution_steps || []).map(s => `<li>${s}</li>`).join('')}</ul>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Rollback Steps</div>
      <ul class="detail-list">${(planItem.rollback_steps || []).map(s => `<li>${s}</li>`).join('')}</ul>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Post-checks</div>
      <ul class="detail-list">${(planItem.postchecks || []).map(s => `<li>${s}</li>`).join('')}</ul>
    </div>

    <div id="ai-explanation-container"></div>

    <div style="margin-top:20px;display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-primary" onclick="getAIExplanation(${planItem.priority_rank})">
        AI Deep Analysis
      </button>
      ${planItem.approval_required && planItem.approval_status === 'pending' ? `
      <button class="btn btn-primary" onclick="approveItem('${planItem.cve_id}','${planItem.service}','approved','${planItem.component}','${planItem.patch_version}')">
        ✓ Approve & Execute
      </button>
      <button class="btn" onclick="approveItem('${planItem.cve_id}','${planItem.service}','rejected','${planItem.component}','${planItem.patch_version}')" style="border-color:var(--critical)">
        ✕ Reject
      </button>` : ''}
    </div>
  `;

  overlay.classList.add('active');
  panel.classList.add('active');
}

function closeDetail() {
  document.getElementById('detail-overlay').classList.remove('active');
  document.getElementById('detail-panel').classList.remove('active');
}

// ── Approval → Auto-Execute Agent ───────────────────
async function approveItem(cveId, service, decision, component, patchVersion) {
  try {
    const resp = await fetch(`/api/approvals/${encodeURIComponent(cveId)}/${encodeURIComponent(service)}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        decision: decision,
        approver: 'demo-judge@harborview.example',
        comment: `${decision} via dashboard during demo`
      })
    });
    if (resp.ok) {
      if (decision === 'approved' && component && patchVersion) {
        // ─── AGENTIC: Auto-trigger execution after approval ───
        showToast(`Approved: ${cveId} — Agent launching autonomous execution...`, 'success');
        closeDetail();

        // Switch to Execution tab
        switchTab('tab-execution');

        // Start the autonomous remediation agent
        const btn = document.getElementById('btn-exec-start');
        if (btn) {
          btn.disabled = true;
          btn.innerHTML = '<span class="spinner"></span> Agent Running...';
        }

        try {
          const execResp = await fetch('/api/execution/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              cve_id: cveId,
              service: service,
              component: component,
              patch_version: patchVersion,
              previous_version: '',
              autonomy_level: 'supervised',
              scenario: 'success',
            }),
          });
          const result = await execResp.json();

          renderTimeline(result);
          loadExecutions();
          loadNotifications();

          // ── Mark as resolved → page reload updates all counters ──
          // completed = patched successfully, rolled_back = still vulnerable (don't remove)
          if (result.status === 'completed') {
            await fetch('/api/resolved', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ cve_id: cveId, service: service }),
            });
            showToast(`Agent completed: ${cveId} patched! Updating dashboard...`, 'success');
            setTimeout(() => location.reload(), 2500);
          } else if (result.status === 'rolled_back') {
            showToast(`Agent rolled back: ${cveId} — still vulnerable, kept in plan`, 'warning');
          } else {
            showToast(`Agent escalated: ${cveId} — kept in plan`, 'error');
          }
        } catch (execErr) {
          showToast(`Agent execution error: ${execErr.message}`, 'error');
        }

        if (btn) {
          btn.disabled = false;
          btn.innerHTML = 'Execute';
        }
      } else {
        // Rejected — remove from active list by recording the rejection decision
        // We do NOT call /api/resolved here because the vulnerability is NOT fixed.
        // The backend _get_active_plan will filter it out based on the approval status.
        showToast(`✕ Rejected: ${cveId} — hidden from plan (risk persists)`);
        closeDetail();
        setTimeout(() => location.reload(), 1200);
      }
    }
  } catch (err) {
    console.error('Approval failed:', err);
    showToast('Approval failed: ' + err.message, 'error');
  }
}

// ── Toast ───────────────────────────────────────────
function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 3000);
}

// ── Re-run Analysis ─────────────────────────────────
async function rerunAnalysis() {
  const btn = document.getElementById('btn-rerun');
  btn.disabled = true;
  btn.innerHTML = '⟳ Running...';
  try {
    const resp = await fetch('/api/analysis/run', { method: 'POST' });
    if (resp.ok) {
      showToast('Analysis pipeline complete — refreshing...');
      setTimeout(() => location.reload(), 800);
    }
  } catch (err) {
    console.error('Analysis failed:', err);
    btn.innerHTML = '⟳ Re-run Analysis';
    btn.disabled = false;
  }
}

// ── Dependency Graph (vis-network) ──────────────────
window._graphRendered = false;

async function loadGraph() {
  try {
    const resp = await fetch('/api/graph');
    const data = await resp.json();
    const container = document.getElementById('graph-container');

    const nodes = new vis.DataSet(data.nodes);
    const edges = new vis.DataSet(data.edges);

    const options = {
      nodes: {
        borderWidth: 2,
        borderWidthSelected: 3,
        shadow: { enabled: true, color: 'rgba(0,0,0,0.3)', size: 10 },
        font: { color: '#1c1108', face: 'Inter' },
      },
      edges: {
        width: 1.5,
        selectionWidth: 2.5,
        smooth: { type: 'curvedCW', roundness: 0.15 },
      },
      physics: {
        forceAtlas2Based: {
          gravitationalConstant: -40,
          centralGravity: 0.008,
          springLength: 140,
          springConstant: 0.04,
          damping: 0.85,
        },
        solver: 'forceAtlas2Based',
        stabilization: { iterations: 120 },
      },
      interaction: {
        hover: true,
        tooltipDelay: 150,
        zoomView: true,
        dragView: true,
      },
      layout: { improvedLayout: true },
    };

    new vis.Network(container, { nodes, edges }, options);
    window._graphRendered = true;
  } catch (err) {
    console.error('Graph load failed:', err);
    document.getElementById('graph-container').innerHTML =
      '<div style="display:grid;place-items:center;height:100%;color:var(--text-muted)">Failed to load graph data</div>';
  }
}

// ── Exports ─────────────────────────────────────────
function exportJSON() {
  window.open('/api/reports/export.json', '_blank');
}
function exportCSV() {
  window.open('/api/reports/export.csv', '_blank');
}

// ── Live Feed Check ─────────────────────────────────
async function checkLiveFeeds() {
  const statusEl = document.getElementById('feed-status');
  if (!statusEl) return;
  statusEl.innerHTML = '<span class="badge" style="background:var(--medium-bg);color:var(--medium)">Checking feeds...</span>';
  try {
    const resp = await fetch('/api/feeds/kev');
    if (resp.ok) {
      const data = await resp.json();
      statusEl.innerHTML = `<span class="badge badge-approved">Live: ${data.count} KEV entries</span>`;
    } else {
      statusEl.innerHTML = '<span class="badge badge-pending">Feed unavailable</span>';
    }
  } catch {
    statusEl.innerHTML = '<span class="badge badge-pending">Offline mode</span>';
  }
}

// ── Init ────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Setup click handlers for plan rows
  document.querySelectorAll('[data-plan-item]').forEach(row => {
    row.addEventListener('click', () => {
      const item = JSON.parse(row.getAttribute('data-plan-item'));
      openDetail(item);
    });
  });

  // Tab click handlers
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  // Close detail panel
  document.getElementById('detail-overlay')?.addEventListener('click', closeDetail);
  document.getElementById('detail-close')?.addEventListener('click', closeDetail);

  // Keyboard shortcut
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDetail();
  });

  // Check live feeds
  checkLiveFeeds();

  // Load agent data
  loadExecutions();
  loadNotifications();
});


// ── AI / LLM Functions (Gemini) ─────────────────────

async function getAIExplanation(rank) {
  const container = document.getElementById('ai-explanation-container');
  if (!container) return;
  container.innerHTML = `
    <div class="explanation-card" style="margin-top:16px">
      <div class="explanation-label" style="display:flex;align-items:center;gap:6px">
        <span class="shimmer" style="display:inline-block;width:16px;height:16px;border-radius:4px"></span>
        Generating AI analysis with Gemini...
      </div>
      <div class="shimmer" style="height:80px;border-radius:8px;margin-top:8px"></div>
    </div>`;

  try {
    const resp = await fetch(`/api/ai/explain/${rank}`, { method: 'POST' });
    if (!resp.ok) {
      const err = await resp.json();
      container.innerHTML = `<div class="explanation-card" style="margin-top:16px;border-color:var(--critical)">
        <div class="explanation-label" style="color:var(--critical)">AI Unavailable</div>
        <p style="font-size:13px;color:var(--text-secondary)">${err.detail || 'Failed to generate AI explanation'}</p>
      </div>`;
      return;
    }
    const data = await resp.json();
    const ai = data.ai_explanation;

    container.innerHTML = `
      <div class="explanation-card" style="margin-top:16px;border-color:rgba(234,88,12,0.25);background:rgba(234,88,12,0.06)">
        <div class="explanation-label" style="color:var(--accent-light);display:flex;align-items:center;gap:6px">
          Gemini AI Analysis
          <span style="font-size:9px;padding:1px 6px;border-radius:3px;background:rgba(234,88,12,0.15);color:var(--accent-light)">AI Generated</span>
        </div>

        ${ai.risk_assessment ? `
        <div style="margin-top:10px">
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);margin-bottom:3px">RISK ASSESSMENT</div>
          <p style="font-size:13px;color:var(--text-secondary);line-height:1.6">${ai.risk_assessment}</p>
        </div>` : ''}

        ${ai.business_impact ? `
        <div style="margin-top:10px">
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);margin-bottom:3px">BUSINESS IMPACT</div>
          <p style="font-size:13px;color:var(--text-secondary);line-height:1.6">${ai.business_impact}</p>
        </div>` : ''}

        ${ai.key_concern ? `
        <div style="margin-top:10px;padding:10px;background:rgba(239,68,68,0.08);border-radius:8px;border-left:3px solid var(--critical)">
          <div style="font-size:11px;font-weight:600;color:var(--critical);margin-bottom:3px">⚠ KEY CONCERN</div>
          <p style="font-size:13px;color:var(--text);line-height:1.6">${ai.key_concern}</p>
        </div>` : ''}

        ${ai.recommended_action ? `
        <div style="margin-top:10px">
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);margin-bottom:3px">RECOMMENDED ACTION</div>
          <p style="font-size:13px;color:var(--accent-light);line-height:1.6">${ai.recommended_action}</p>
        </div>` : ''}

        ${ai.rank_justification ? `
        <div style="margin-top:10px">
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);margin-bottom:3px">RANKING JUSTIFICATION</div>
          <p style="font-size:13px;color:var(--text-secondary);line-height:1.6">${ai.rank_justification}</p>
        </div>` : ''}
      </div>`;
  } catch (err) {
    console.error('AI explanation failed:', err);
    container.innerHTML = `<div class="explanation-card" style="margin-top:16px;border-color:var(--critical)">
      <p style="font-size:13px;color:var(--text-secondary)">AI analysis failed: ${err.message}</p>
    </div>`;
  }
}

async function askAIQuestion() {
  const input = document.getElementById('ai-question-input');
  const container = document.getElementById('ai-chat-messages');
  const question = input.value.trim();
  if (!question) return;

  // Add user message
  container.innerHTML += `
    <div style="display:flex;justify-content:flex-end;margin-bottom:10px">
      <div style="background:rgba(234,88,12,0.12);border:1px solid rgba(234,88,12,0.2);border-radius:12px 12px 2px 12px;padding:10px 14px;max-width:80%;font-size:13px">${question}</div>
    </div>`;
  input.value = '';

  // Add loading indicator
  container.innerHTML += `
    <div id="ai-loading" style="display:flex;margin-bottom:10px">
      <div style="background:rgba(234,88,12,0.08);border:1px solid rgba(234,88,12,0.15);border-radius:12px 12px 12px 2px;padding:10px 14px;max-width:80%">
        <div class="shimmer" style="height:20px;width:200px;border-radius:4px"></div>
      </div>
    </div>`;
  container.scrollTop = container.scrollHeight;

  try {
    const resp = await fetch('/api/ai/query', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ question })
    });
    document.getElementById('ai-loading')?.remove();

    if (resp.ok) {
      const data = await resp.json();
      container.innerHTML += `
        <div style="display:flex;margin-bottom:10px">
          <div style="background:rgba(234,88,12,0.08);border:1px solid rgba(234,88,12,0.15);border-radius:12px 12px 12px 2px;padding:10px 14px;max-width:80%">
            <div style="font-size:10px;color:var(--accent-light);font-weight:600;margin-bottom:4px">GEMINI</div>
            <div style="font-size:13px;color:var(--text-secondary);line-height:1.6">${data.answer}</div>
          </div>
        </div>`;
    } else {
      container.innerHTML += `
        <div style="display:flex;margin-bottom:10px">
          <div style="background:rgba(239,68,68,0.1);border-radius:12px;padding:10px 14px;font-size:13px;color:var(--critical)">AI unavailable. Set GEMINI_API_KEY to enable.</div>
        </div>`;
    }
    container.scrollTop = container.scrollHeight;
  } catch (err) {
    document.getElementById('ai-loading')?.remove();
    container.innerHTML += `<div style="font-size:13px;color:var(--critical);margin-bottom:10px">Error: ${err.message}</div>`;
  }
}

async function generateAISummary() {
  const btn = document.getElementById('btn-ai-summary');
  const container = document.getElementById('ai-summary-output');
  if (!container) return;
  btn.disabled = true;
  btn.innerHTML = 'Generating...';
  container.innerHTML = '<div class="shimmer" style="height:100px;border-radius:8px"></div>';

  try {
    const resp = await fetch('/api/ai/summary', { method: 'POST' });
    if (resp.ok) {
      const data = await resp.json();
      container.innerHTML = `
        <div class="explanation-card" style="border-color:rgba(234,88,12,0.25);background:rgba(234,88,12,0.06)">
          <div class="explanation-label" style="color:var(--accent-light)">AI-Generated Executive Summary</div>
          <p style="font-size:14px;color:var(--text-secondary);line-height:1.7;white-space:pre-wrap">${data.ai_summary}</p>
        </div>`;
    } else {
      container.innerHTML = '<p style="color:var(--critical)">AI summary unavailable. Set GEMINI_API_KEY.</p>';
    }
  } catch (err) {
    container.innerHTML = `<p style="color:var(--critical)">Error: ${err.message}</p>`;
  }
  btn.disabled = false;
  btn.innerHTML = 'Generate AI Summary';
}

// ═══════════════════════════════════════════════════════════
//  AUTONOMOUS EXECUTION — Agent Dashboard
// ═══════════════════════════════════════════════════════════

const STATUS_CONFIG = {
  identified:          { icon: '', color: '#6b7280', label: 'Identified' },
  assessed:            { icon: '', color: '#ea580c', label: 'Assessed' },
  planned:             { icon: '', color: '#ea580c', label: 'Planned' },
  awaiting_approval:   { icon: '', color: '#f59e0b', label: 'Awaiting Approval' },
  auto_approved:       { icon: '', color: '#10b981', label: 'Auto-Approved' },
  approved:            { icon: '', color: '#10b981', label: 'Approved' },
  scheduled:           { icon: '', color: '#3b82f6', label: 'Scheduled' },
  precheck_running:    { icon: '', color: '#06b6d4', label: 'Pre-checks Running' },
  deploying:           { icon: '', color: '#f97316', label: 'Deploying' },
  canary_testing:      { icon: '', color: '#eab308', label: 'Canary Testing' },
  verifying:           { icon: '', color: '#ea580c', label: 'Verifying' },
  completed:           { icon: '', color: '#10b981', label: 'Completed' },
  verification_failed: { icon: '', color: '#ef4444', label: 'Verification Failed' },
  rollback_running:    { icon: '', color: '#ef4444', label: 'Rolling Back' },
  rolled_back:         { icon: '', color: '#f97316', label: 'Rolled Back' },
  escalated:           { icon: '', color: '#ef4444', label: 'Escalated' },
};

async function startExecution() {
  const btn = document.getElementById('btn-exec-start');
  const select = document.getElementById('exec-plan-item');
  const scenario = document.getElementById('exec-scenario').value;
  const autonomy = document.getElementById('exec-autonomy').value;

  if (!select.value) { showToast('Select a plan item first', 'error'); return; }

  const [cve_id, service, component, patch_version] = select.value.split('|');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Agent Running...';

  try {
    const resp = await fetch('/api/execution/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        cve_id, service, component, patch_version,
        previous_version: '',
        autonomy_level: autonomy,
        scenario: scenario,
      }),
    });
    const result = await resp.json();

    renderTimeline(result);
    loadExecutions();
    loadNotifications();

    if (result.status === 'completed') {
      showToast(`Remediation complete: ${cve_id}`, 'success');
    } else if (result.status === 'rolled_back') {
      showToast(`Rolled back: ${cve_id} — health check failed`, 'warning');
    } else {
      showToast(`Escalated: ${cve_id}`, 'error');
    }
  } catch (err) {
    showToast(`Execution error: ${err.message}`, 'error');
  }

  btn.disabled = false;
  btn.innerHTML = 'Execute';
}

function renderTimeline(result) {
  const container = document.getElementById('exec-timeline-container');
  const timeline = document.getElementById('exec-timeline');
  const title = document.getElementById('exec-timeline-title');
  const statusBadge = document.getElementById('exec-status-badge');
  const healthGrid = document.getElementById('exec-health-grid');

  container.style.display = 'block';

  const record = result.record || {};
  const cfg = STATUS_CONFIG[record.status] || { icon: '❓', color: '#6b7280', label: record.status };

  title.innerHTML = `Agent Execution Timeline — <span style="color:${cfg.color}">${cfg.icon} ${cfg.label}</span>`;

  const finalStatus = result.status;
  const badgeColor = finalStatus === 'completed' ? '#10b981' : finalStatus === 'rolled_back' ? '#f97316' : '#ef4444';
  statusBadge.innerHTML = `
    <div style="display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border-radius:8px;
                background:${badgeColor}15;border:1px solid ${badgeColor}40;font-size:13px;font-weight:600;color:${badgeColor}">
      ${cfg.icon} Final Status: ${cfg.label}
      ${record.execution_id ? `<span style="font-weight:400;opacity:0.7;font-size:11px;font-family:var(--font-mono)">${record.execution_id}</span>` : ''}
    </div>`;

  // Render timeline events
  const events = result.timeline || [];
  let html = '';
  events.forEach((evt, i) => {
    const evtCfg = STATUS_CONFIG[evt.step] || { icon: '▸', color: '#6b7280', label: evt.step };
    const isLast = i === events.length - 1;
    const isFail = evt.step.includes('fail') || evt.step.includes('rollback') || evt.step === 'escalated';
    const dotColor = isFail ? '#ef4444' : evtCfg.color;
    const time = evt.duration_ms ? `${Math.round(evt.duration_ms)}ms` : '';

    html += `
      <div style="position:relative;padding-bottom:${isLast ? '0' : '20px'};margin-bottom:${isLast ? '0' : '4px'}">
        <!-- Dot -->
        <div style="position:absolute;left:-26px;top:3px;width:14px;height:14px;border-radius:50%;
                    background:${dotColor};border:2px solid var(--surface-1);z-index:2;
                    box-shadow:0 0 0 3px ${dotColor}30"></div>
        <!-- Line -->
        ${!isLast ? `<div style="position:absolute;left:-20px;top:17px;bottom:0;width:2px;background:var(--border)"></div>` : ''}
        <!-- Content -->
        <div style="display:flex;justify-content:space-between;align-items:flex-start">
          <div>
            <div style="font-size:13px;font-weight:600;color:${dotColor}">
              ${evtCfg.icon} ${evtCfg.label || evt.step}
              <span style="font-size:11px;font-weight:400;color:var(--text-muted);margin-left:6px">${evt.agent || ''}</span>
            </div>
            <div style="font-size:12px;color:var(--text-secondary);margin-top:2px">${evt.detail}</div>
          </div>
          ${time ? `<span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);white-space:nowrap">${time}</span>` : ''}
        </div>
      </div>`;
  });
  timeline.innerHTML = html;

  // Health metrics grid
  const metrics = result.health_metrics || {};
  if (Object.keys(metrics).length > 0) {
    const metricCards = [
      { label: 'Error Rate', value: `${metrics.error_rate_pct || 0}%`, ok: (metrics.error_rate_pct || 0) < 1, threshold: '< 1%' },
      { label: 'P99 Latency', value: `${metrics.latency_p99_ms || 0}ms`, ok: (metrics.latency_p99_ms || 0) < 500, threshold: '< 500ms' },
      { label: 'Success Rate', value: `${metrics.success_rate_pct || 0}%`, ok: (metrics.success_rate_pct || 0) > 99, threshold: '> 99%' },
      { label: 'CPU Utilization', value: `${metrics.cpu_utilization_pct || 0}%`, ok: (metrics.cpu_utilization_pct || 0) < 85, threshold: '< 85%' },
      { label: 'Memory', value: `${metrics.memory_utilization_pct || 0}%`, ok: (metrics.memory_utilization_pct || 0) < 85, threshold: '< 85%' },
      { label: 'RPS', value: `${metrics.requests_per_second || 0}`, ok: true, threshold: 'n/a' },
    ];

    healthGrid.innerHTML = metricCards.map(m => `
      <div class="card" style="padding:16px;border-color:${m.ok ? '#10b98130' : '#ef444430'}">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
          <span style="font-size:11px;color:var(--text-muted)">${m.label}</span>
          <span style="font-size:10px;padding:2px 6px;border-radius:4px;
                       background:${m.ok ? '#10b98120' : '#ef444420'};color:${m.ok ? '#10b981' : '#ef4444'}">
            ${m.ok ? '✓ OK' : '✗ FAIL'}
          </span>
        </div>
        <div style="font-size:22px;font-weight:700;color:${m.ok ? 'var(--text)' : '#ef4444'}">${m.value}</div>
        <div style="font-size:10px;color:var(--text-muted)">threshold: ${m.threshold}</div>
      </div>`).join('');
  } else {
    healthGrid.innerHTML = '';
  }
}

async function loadExecutions() {
  try {
    const resp = await fetch('/api/execution/list');
    const execs = await resp.json();
    const container = document.getElementById('exec-history-list');

    if (!execs.length) {
      container.innerHTML = '<p>No executions yet. Launch one above to see the agent in action.</p>';
      return;
    }

    container.innerHTML = `
      <table class="data-table">
        <thead>
          <tr>
            <th>ID</th><th>CVE</th><th>Service</th><th>Component</th><th>Status</th><th>Created</th>
          </tr>
        </thead>
        <tbody>
          ${execs.map(e => {
            const cfg = STATUS_CONFIG[e.status] || { icon: '❓', color: '#6b7280', label: e.status };
            return `<tr>
              <td style="font-family:var(--font-mono);font-size:11px">${(e.execution_id||'').substring(0, 24)}…</td>
              <td><span class="badge badge-critical">${e.cve_id}</span></td>
              <td>${e.service}</td>
              <td>${e.component}</td>
              <td><span style="color:${cfg.color};font-weight:600">${cfg.icon} ${cfg.label}</span></td>
              <td style="font-size:11px;color:var(--text-muted)">${new Date(e.created_at).toLocaleTimeString()}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>`;
  } catch (err) {
    console.error('Failed to load executions:', err);
  }
}

async function loadNotifications() {
  try {
    const resp = await fetch('/api/notifications');
    const notifs = await resp.json();
    const container = document.getElementById('exec-notifications');

    if (!notifs.length) {
      container.innerHTML = '<p>No notifications.</p>';
      return;
    }

    container.innerHTML = notifs.map(n => {
      const sevColor = n.severity === 'critical' ? '#ef4444' : n.severity === 'warning' ? '#f97316' : n.severity === 'success' ? '#10b981' : '#6b7280';
      return `
        <div style="padding:10px 14px;margin-bottom:8px;border-radius:8px;border:1px solid ${sevColor}30;
                    background:${sevColor}08;display:flex;justify-content:space-between;align-items:center">
          <div>
            <span style="color:${sevColor};font-weight:600;font-size:12px">${n.severity?.toUpperCase()}</span>
            <span style="margin-left:8px;font-size:13px">${n.message}</span>
            <span style="margin-left:8px;font-size:11px;color:var(--text-muted)">${n.service}</span>
          </div>
          <span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono)">${n.channel || ''}</span>
        </div>`;
    }).join('');
  } catch (err) {
    console.error('Failed to load notifications:', err);
  }
}

async function resetExecutions() {
  if (!confirm('Reset all execution state and notifications?')) return;
  try {
    await fetch('/api/execution/reset', { method: 'POST' });
    document.getElementById('exec-timeline-container').style.display = 'none';
    document.getElementById('exec-history-list').innerHTML = '<p>No executions yet. Launch one above to see the agent in action.</p>';
    document.getElementById('exec-notifications').innerHTML = '<p>No notifications.</p>';
    showToast('Execution state reset', 'info');
  } catch (err) {
    showToast('Reset failed: ' + err.message, 'error');
  }
}

function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.className = 'toast show';
  if (type === 'error') toast.style.background = '#ef4444';
  else if (type === 'warning') toast.style.background = '#f97316';
  else if (type === 'success') toast.style.background = '#10b981';
  else toast.style.background = '#3b82f6';
  setTimeout(() => { toast.className = 'toast'; }, 4000);
}

// ── Reset Demo ──────────────────────────────────────
async function resetDemo() {
  if (!confirm('This will clear all processed items and reset the demo to Rank #1. Proceed?')) return;
  try {
    const resp = await fetch('/api/execution/reset', { method: 'POST' });
    if (resp.ok) {
        showToast('Demo state reset successfully. Refreshing...', 'success');
        setTimeout(() => location.reload(), 1000);
    } else {
        showToast('Reset failed on server', 'error');
    }
  } catch (err) {
    showToast('Reset failed: ' + err.message, 'error');
  }
}
