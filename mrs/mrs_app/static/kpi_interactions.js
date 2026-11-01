(function () {
  'use strict';
  const modal = document.getElementById('kpiChartModal');
  const modalTitle = document.getElementById('kpiChartModalTitle');
  const modalBody = document.getElementById('kpiChartModalBody');
  const closeButton = document.getElementById('closeKpiChartModal');
  let focusedCard = null;
  let placeholder = null;

  function closeModal() {
    if (!modal) return;
    if (focusedCard && placeholder && placeholder.parentNode) {
      focusedCard.classList.remove('kpi-focused');
      placeholder.parentNode.replaceChild(focusedCard, placeholder);
    }
    focusedCard = null;
    placeholder = null;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
    modalBody.replaceChildren();
    document.body.style.overflow = '';
  }

  function openModal(card) {
    if (!modal || !card || focusedCard) return;
    placeholder = document.createComment('KPI chart container position');
    card.parentNode.replaceChild(placeholder, card);
    focusedCard = card;
    focusedCard.classList.add('kpi-focused');
    modalBody.replaceChildren(focusedCard);
    modalTitle.textContent = card.dataset.chartTitle || 'Focused KPI Graph';
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    modalBody.scrollTop = 0;
  }

  document.querySelectorAll('.kpi-expandable').forEach(function (card) {
    card.setAttribute('role', 'button');
    card.setAttribute('tabindex', '0');
    card.setAttribute('aria-label', 'Focus entire ' + (card.dataset.chartTitle || 'KPI chart container'));
    card.addEventListener('click', function (event) {
      if (card.classList.contains('kpi-focused')) return;
      if (event.target.closest('input, select, textarea, button, a, details, summary')) return;
      openModal(card);
    });
    card.addEventListener('keydown', function (event) {
      if (card.classList.contains('kpi-focused')) return;
      if ((event.key === 'Enter' || event.key === ' ') && event.target === card) {
        event.preventDefault();
        openModal(card);
      }
    });
  });

  if (closeButton) closeButton.addEventListener('click', closeModal);
  if (modal) modal.addEventListener('click', function (event) { if (event.target === modal) closeModal(); });
  document.addEventListener('keydown', function (event) { if (event.key === 'Escape') closeModal(); });

  const exportLink = document.getElementById('kpiPdfExport');
  if (exportLink) {
    exportLink.addEventListener('click', function (event) {
      event.preventDefault();
      const form = document.createElement('form');
      form.method = 'post';
      form.action = exportLink.href;
      form.target = '_blank';
      document.querySelectorAll('.kpi-temp-comment').forEach(function (field) {
        const value = field.value.trim();
        if (!value) return;
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = field.name;
        input.value = value;
        form.appendChild(input);
      });
      document.body.appendChild(form);
      form.submit();
      form.remove();
    });
  }

  function clearTemporaryComments() {
    document.querySelectorAll('.kpi-temp-comment').forEach(function (field) { field.value = ''; });
  }
  window.addEventListener('pagehide', clearTemporaryComments);
})();
