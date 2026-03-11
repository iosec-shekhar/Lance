/**
 * LANCE UI — Shared JS v0.5.0
 * lance.iosec.in
 */

// ── Chart.js defaults ─────────────────────────────────────────────────────────
if (typeof Chart !== 'undefined') {
  const mono = "'Space Mono', monospace";
  Chart.defaults.font.family = mono;
  Chart.defaults.font.size   = 10;
  Chart.defaults.color       = '#8B8FA8';
  Chart.defaults.plugins.tooltip.cornerRadius = 3;
  Chart.defaults.plugins.tooltip.padding      = 10;
}

// ── Sidebar toggle (mobile) ───────────────────────────────────────────────────
document.addEventListener('click', e => {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  const menu = e.target.closest('.tb-menu');
  if (!menu && !sidebar.contains(e.target) && sidebar.classList.contains('open')) {
    sidebar.classList.remove('open');
  }
});

// ── Auto-highlight active nav link ────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const path = location.pathname;
  document.querySelectorAll('.sb-link').forEach(a => {
    if (a.getAttribute('href') === path) a.classList.add('active');
  });

  // Animate stat numbers counting up
  document.querySelectorAll('.sc-n[data-target]').forEach(el => {
    const target = parseInt(el.dataset.target, 10);
    if (isNaN(target)) return;
    let current = 0;
    const step  = Math.ceil(target / 30);
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      el.textContent = current;
      if (current >= target) clearInterval(timer);
    }, 30);
  });
});

// ── Utility: format risk score colour class ───────────────────────────────────
function riskClass(score) {
  if (score >= 7) return 'risk-high';
  if (score >= 4) return 'risk-med';
  return 'risk-low';
}

// ── Utility: relative time ────────────────────────────────────────────────────
function relTime(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)   return 'just now';
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ── Auto-refresh running campaigns on dashboard ───────────────────────────────
(function autoRefreshRunning() {
  const hasRunning = document.querySelector('.badge-running');
  if (!hasRunning) return;

  // Soft refresh — just reload the page every 8s if there's a running campaign
  setTimeout(() => location.reload(), 8000);
})();
