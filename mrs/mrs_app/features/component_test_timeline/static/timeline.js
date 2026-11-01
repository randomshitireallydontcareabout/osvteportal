(() => {
  const panel = document.getElementById('componentTestDurationPanel');
  if (!panel) return;

  const form = document.getElementById('ctdControls');
  const stockSelects = [...panel.querySelectorAll('.ctd-stock')];
  const modeInputs = [...panel.querySelectorAll('input[name="ctdMode"]')];
  const stockGroup = panel.querySelector('.ctd-stock-group');
  const brandGroup = panel.querySelector('.ctd-brand-group');
  const brandSelect = panel.querySelector('#ctdBrandPick');
  const compTypeSelect = panel.querySelector('#ctdCompTypePick');
  const brandSummary = panel.querySelector('#ctdBrandSummary');
  const fromInput = document.getElementById('ctdFrom');
  const toInput = document.getElementById('ctdTo');
  const errorEl = document.getElementById('ctdError');
  const legend = document.getElementById('ctdLegend');
  const summary = document.getElementById('ctdSummary');
  const corr = document.getElementById('ctdCorrelation');
  const canvas = document.getElementById('ctdCanvas');
  const tip = document.getElementById('ctdTooltip');
  const ctx = canvas.getContext('2d');

  let payload = null;
  let hits = [];
  const hiddenStocks = new Set();

  const esc = s => String(s ?? '').replace(/[&<>"']/g,
    c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  const PALETTE = [
    '#4f8cff', '#22c55e', '#a78bfa', '#f59e0b', '#06b6d4',
    '#ec4899', '#10b981', '#8b5cf6', '#f97316', '#eab308',
    '#14b8a6', '#d946ef', '#84cc16', '#0ea5e9', '#ef4444',
    '#64748b', '#f472b6', '#fb923c', '#a3e635', '#2dd4bf'
  ];

  function getMode() {
    const checked = modeInputs.find(r => r.checked);
    return checked ? checked.value : 'stock';
  }

  function updateModeVisibility() {
    const mode = getMode();
    if (stockGroup) stockGroup.style.display = mode === 'stock' ? 'flex' : 'none';
    if (brandGroup) brandGroup.style.display = mode === 'brand' ? 'flex' : 'none';
  }

  function resolveBrandStockCodes() {
    const meta = (payload && payload.metadata) || {};
    const brand = (brandSelect && brandSelect.value || '').toLowerCase();
    const compType = (compTypeSelect && compTypeSelect.value || '').toLowerCase();
    const codes = [];
    if (!brand) return codes;
    for (const [stock, m] of Object.entries(meta)) {
      if ((m.brand || '').toLowerCase() !== brand) continue;
      if (compType && (m.component_type || '').toLowerCase() !== compType) continue;
      codes.push(stock);
    }
    codes.sort((a, b) => a.localeCompare(b));
    return codes;
  }

  function populateBrandSelect() {
    if (!brandSelect) return;
    const brands = (payload && payload.available_brands) || [];
    brandSelect.innerHTML = '<option value="">Select brand</option>' +
      brands.map(b => `<option value="${esc(b)}">${esc(b)}</option>`).join('');
    if (compTypeSelect) {
      compTypeSelect.innerHTML = '<option value="">All component types</option>';
    }
    updateBrandSummary();
  }

  function populateCompTypeSelect() {
    if (!compTypeSelect) return;
    const meta = (payload && payload.metadata) || {};
    const brand = (brandSelect && brandSelect.value || '').toLowerCase();
    const types = new Set();
    if (brand) {
      for (const m of Object.values(meta)) {
        if ((m.brand || '').toLowerCase() === brand && m.component_type) {
          types.add(m.component_type);
        }
      }
    }
    const sorted = [...types].sort((a, b) => a.localeCompare(b));
    compTypeSelect.innerHTML = '<option value="">All component types</option>' +
      sorted.map(t => `<option value="${esc(t)}">${esc(t)}</option>`).join('');
    updateBrandSummary();
  }

  function updateBrandSummary() {
    if (!brandSummary) return;
    if (getMode() !== 'brand') { brandSummary.textContent = ''; return; }
    if (!brandSelect || !brandSelect.value) {
      brandSummary.textContent = '';
      return;
    }
    const codes = resolveBrandStockCodes();
    if (codes.length === 0) {
      brandSummary.textContent = 'No stock codes match this selection';
    } else {
      brandSummary.textContent = `${codes.length} stock code${codes.length !== 1 ? 's' : ''} on graph`;
    }
  }

  if (brandSelect) {
    brandSelect.addEventListener('change', () => {
      populateCompTypeSelect();
      hiddenStocks.clear();
      load(false);
    });
  }
  if (compTypeSelect) {
    compTypeSelect.addEventListener('change', () => {
      updateBrandSummary();
      hiddenStocks.clear();
      load(false);
    });
  }

  modeInputs.forEach(r => r.addEventListener('change', () => {
    updateModeVisibility();
    hiddenStocks.clear();
    load(false);
  }));

  function params() {
    const p = new URLSearchParams();
    const mode = getMode();
    if (mode === 'stock') {
      p.set('mode', 'stock');
      stockSelects.forEach(s => { if (s.value) p.append('stock', s.value); });
    } else {
      // Brand mode resolves to concrete stock codes; the API is called in
      // stock mode with every matching stock code.
      p.set('mode', 'stock');
      resolveBrandStockCodes().forEach(c => p.append('stock', c));
    }
    if (fromInput.value) p.set('from', fromInput.value);
    if (toInput.value)   p.set('to', toInput.value);
    return p;
  }

  async function load(initial = false) {
    errorEl.textContent = '';
    const mode = getMode();

    // Skip fetching in brand mode when no brand has been picked yet (unless
    // this is the initial bootstrap, in which case we need the metadata).
    if (!initial && mode === 'brand' && brandSelect && !brandSelect.value) {
      if (payload) {
        payload.series = [];
        payload.correlations = [];
      }
      render();
      return;
    }

    try {
      const r = await fetch('/api/component-test-duration?' + params());
      if (!r.ok) throw new Error('Unable to load duration data.');
      payload = await r.json();

      if (initial) {
        stockSelects.forEach((s, i) => {
          s.innerHTML = '<option value="">' + (i ? 'None' : 'Select stock code') + '</option>' +
            payload.available.map(x => '<option value="' + esc(x) + '">' + esc(x) + '</option>').join('');
        });
        populateBrandSelect();
        fromInput.value = payload.from;
        toInput.value = payload.to;
        if (payload.available.length) stockSelects[0].value = payload.available[0];
        return load(false);
      }

      // Assign palette colors to each series (brand mode can return many).
      if (payload.series) {
        payload.series.forEach((s, i) => {
          s.color = PALETTE[i % PALETTE.length];
        });
      }
      render();
    } catch (e) {
      errorEl.textContent = e.message;
    }
  }

  function render() {
    if (!payload) {
      legend.innerHTML = '';
      summary.innerHTML = '';
      corr.innerHTML = '';
      draw();
      return;
    }

    // Legend items toggle their corresponding series on / off.
    legend.innerHTML = payload.series.map(s => {
      const hidden = hiddenStocks.has(s.stock);
      const style = hidden
        ? 'opacity:.35;text-decoration:line-through;'
        : '';
      return `<span class="ctd-legend-item" data-stock="${esc(s.stock)}" ` +
             `style="cursor:pointer;user-select:none;${style}">` +
             `<i style="background:${s.color}"></i>${esc(s.stock)}</span>`;
    }).join('') +
      '<span><i style="background:#f59e0b"></i>4-day warning</span>' +
      '<span><i style="background:#ef4444"></i>5-day limit</span>';

    legend.querySelectorAll('.ctd-legend-item').forEach(el => {
      el.addEventListener('click', () => {
        const stock = el.getAttribute('data-stock');
        if (hiddenStocks.has(stock)) hiddenStocks.delete(stock);
        else hiddenStocks.add(stock);
        render();
      });
    });

    summary.innerHTML = payload.series.map(s => {
      const hidden = hiddenStocks.has(s.stock);
      const opacity = hidden ? '0.4' : '1';
      const codes = (s.stock_codes && s.stock_codes.length)
        ? '<small style="display:block;margin-top:4px;color:#94a3b8;">Stock codes: ' +
          esc(s.stock_codes.join(', ')) + '</small>'
        : '';
      return '<article style="border-top:3px solid ' + s.color + ';opacity:' + opacity + '">' +
        '<b>' + esc(s.stock) + '</b>' +
        '<strong>' + (s.average ?? '—') + ' days average</strong>' +
        '<small>' + s.count + ' tests · Median ' + (s.median ?? '—') +
        ' · Min ' + (s.minimum ?? '—') + ' · Max ' + (s.maximum ?? '—') + '</small>' +
        codes + '</article>';
    }).join('');

    corr.innerHTML = payload.correlations.map(c =>
      '<article><b>' + esc(c.left) + ' ↔ ' + esc(c.right) + '</b>' +
      '<strong>' + (c.value ?? 'N/A') + '</strong>' +
      '<small>Pearson correlation · ' + c.samples + ' matching dates</small></article>'
    ).join('');

    updateBrandSummary();
    draw();
  }

  function draw() {
    const w = canvas.clientWidth, h = 400, dpr = devicePixelRatio || 1;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    if (!payload || !payload.series || !payload.series.length) {
      ctx.fillStyle = '#8ea1c2'; ctx.textAlign = 'center'; ctx.font = '13px Segoe UI';
      const msg = getMode() === 'brand' && (!brandSelect || !brandSelect.value)
        ? 'Select a brand to plot its stock codes.'
        : 'No completed duration data for the selected range.';
      ctx.fillText(msg, w / 2, h / 2);
      hits = [];
      return;
    }

    const pad = { l: 55, r: 24, t: 18, b: 42 };
    const cw = w - pad.l - pad.r, ch = h - pad.t - pad.b;

    const allForDates = payload.series.flatMap(s => s.daily);
    if (!allForDates.length) {
      ctx.fillStyle = '#8ea1c2'; ctx.textAlign = 'center'; ctx.font = '13px Segoe UI';
      ctx.fillText('No completed duration data for the selected range.', w / 2, h / 2);
      hits = [];
      return;
    }

    const visibleSeries = payload.series.filter(s => !hiddenStocks.has(s.stock));
    const dates = [...new Set(allForDates.map(p => p.date))].sort();
    const maxAll = Math.max(5.5, ...allForDates.map(p => p.days)) * 1.08;
    const x = d => pad.l + (dates.length === 1 ? cw / 2 : dates.indexOf(d) / (dates.length - 1) * cw);
    const y = v => pad.t + ch - v / maxAll * ch;

    // Grid
    ctx.font = '10px Segoe UI';
    for (let i = 0; i <= 6; i++) {
      const val = maxAll * i / 6, yy = y(val);
      ctx.strokeStyle = '#20304d'; ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(pad.l, yy); ctx.lineTo(w - pad.r, yy); ctx.stroke();
      ctx.fillStyle = '#8ea1c2'; ctx.textAlign = 'right';
      ctx.fillText(val.toFixed(1) + 'd', pad.l - 7, yy + 3);
    }
    ctx.setLineDash([]);

    // Thresholds
    function threshold(v, color, label) {
      const yy = y(v);
      ctx.setLineDash([8, 5]); ctx.strokeStyle = color; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.moveTo(pad.l, yy); ctx.lineTo(w - pad.r, yy); ctx.stroke();
      ctx.fillStyle = color; ctx.textAlign = 'left'; ctx.fillText(label, w - pad.r - 88, yy - 5);
    }
    threshold(4, '#f59e0b', '4-day warning');
    threshold(5, '#ef4444', '5-day limit');
    ctx.setLineDash([]);

    // Series
    hits = [];
    visibleSeries.forEach(s => {
      ctx.strokeStyle = s.color; ctx.lineWidth = 2.5; ctx.beginPath();
      s.daily.forEach((p, i) => {
        i ? ctx.lineTo(x(p.date), y(p.days)) : ctx.moveTo(x(p.date), y(p.days));
      });
      ctx.stroke();
      s.daily.forEach(p => {
        const px = x(p.date), py = y(p.days);
        ctx.fillStyle = s.color;
        ctx.beginPath(); ctx.arc(px, py, 4, 0, Math.PI * 2); ctx.fill();
        hits.push({ x: px, y: py, stock: s.stock, ...p });
      });
    });

    // X axis labels
    ctx.fillStyle = '#8ea1c2'; ctx.textAlign = 'center';
    [...new Set([0, Math.floor((dates.length - 1) / 2), dates.length - 1])].forEach(i => {
      ctx.fillText(dates[i], x(dates[i]), h - 13);
    });
  }

  form.addEventListener('submit', e => { e.preventDefault(); load(false); });

  canvas.addEventListener('mousemove', e => {
    const r = canvas.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    const p = hits.find(q => Math.hypot(q.x - mx, q.y - my) < 9);
    if (!p) { tip.hidden = true; return; }
    tip.hidden = false;
    tip.innerHTML = '<b>' + esc(p.stock) + '</b><br>' + p.date + '<br>' +
      p.days + ' days<br><em style="color:#94a3b8;font-size:10px;">Click to hide</em>';
    tip.style.left = Math.min(mx + 16, r.width - 130) + 'px';
    tip.style.top  = Math.max(25, my - 55) + 'px';
  });
  canvas.addEventListener('mouseleave', () => tip.hidden = true);

  // Click on a data point to toggle that stock on / off.
  canvas.addEventListener('click', e => {
    const r = canvas.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    const p = hits.find(q => Math.hypot(q.x - mx, q.y - my) < 9);
    if (!p) return;
    if (hiddenStocks.has(p.stock)) hiddenStocks.delete(p.stock);
    else hiddenStocks.add(p.stock);
    render();
  });

  addEventListener('resize', draw);

  updateModeVisibility();
  load(true);
})();