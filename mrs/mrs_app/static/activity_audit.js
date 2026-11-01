(() => {
  const endpoint = "/audit/client-event";
  const clean = (value, max = 240) => String(value || "").replace(/\s+/g, " ").trim().slice(0, max);
  const send = (payload) => {
    const body = JSON.stringify({ ...payload, page: location.pathname });
    try {
      if (navigator.sendBeacon) {
        navigator.sendBeacon(endpoint, new Blob([body], { type: "application/json" }));
      } else {
        fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body, keepalive: true, credentials: "same-origin" });
      }
    } catch (_) {}
  };

  document.addEventListener("click", (event) => {
    const target = event.target.closest("a,button,input[type=submit],input[type=button],[role=button]");
    if (!target) return;
    send({
      event_type: target.tagName === "A" ? "NAVIGATION" : "CLICK",
      label: clean(target.innerText || target.value || target.getAttribute("aria-label") || target.title),
      element: target.tagName.toLowerCase(),
      element_id: clean(target.id, 100),
      href: target.tagName === "A" ? clean(target.getAttribute("href"), 500) : ""
    });
  }, true);

  document.addEventListener("submit", (event) => {
    const form = event.target;
    send({ event_type: "FORM_SUBMIT", label: clean(form.getAttribute("aria-label") || form.action || "form"), element: "form", element_id: clean(form.id, 100) });
  }, true);

  document.addEventListener("change", (event) => {
    const field = event.target;
    if (!field.matches("select,input[type=checkbox],input[type=radio],input[type=file]")) return;
    send({
      event_type: "FIELD_CHANGE",
      label: clean(field.labels && field.labels[0] ? field.labels[0].innerText : field.name),
      element: field.tagName.toLowerCase(),
      element_id: clean(field.id, 100),
      field: clean(field.name, 120)
    });
  }, true);
})();
