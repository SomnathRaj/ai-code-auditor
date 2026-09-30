// Single-series time line chart (SVG, no library). Follows the dataviz method: one series in the
// accent colour (no legend — the card title names it), 2px line, 8px markers, recessive grid,
// crosshair + tooltip that snaps to the nearest point, keyboard focus, and a table view.
// All labels are set with textContent (values come from the API).
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const M = { top: 12, right: 16, bottom: 26, left: 40 };
  const HEIGHT = 190;

  function svg(tag, attrs) {
    const node = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
    return node;
  }

  function niceMax(v) {
    if (v <= 5) return 5;
    const pow = 10 ** Math.floor(Math.log10(v));
    const n = v / pow;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * pow;
  }

  // Dates for spans of days; times when everything happened within ~2 days.
  function fmtTick(d, spanMs) {
    if (spanMs < 3600000) return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    if (spanMs < 2 * 86400000) return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    return d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
  }

  // points: [{ at: Date, value: number, title: string, rows: [[label, value], ...] }]
  function lineChart(container, points, { valueLabel, yMax = null, formatValue = (v) => String(v) }) {
    let active = points.length - 1;
    const tooltip = document.createElement("div");
    tooltip.className = "chart-tooltip";
    tooltip.hidden = true;
    tooltip.setAttribute("role", "status");

    function draw() {
      const width = Math.max(280, container.clientWidth);
      const w = width - M.left - M.right;
      const h = HEIGHT - M.top - M.bottom;
      const t0 = points[0].at.getTime();
      const t1 = points[points.length - 1].at.getTime();
      const span = Math.max(t1 - t0, 1);
      const max = yMax ?? niceMax(Math.max(...points.map((p) => p.value), 1));
      const x = (p) => M.left + (points.length === 1 ? w / 2 : ((p.at.getTime() - t0) / span) * w);
      const y = (v) => M.top + h - (v / max) * h;

      const root = svg("svg", { viewBox: `0 0 ${width} ${HEIGHT}`, width, height: HEIGHT, class: "chart-svg",
        role: "img", "aria-label": `${valueLabel} over time` });
      // Grid + y labels (recessive). Whole-number steps: 10 → 0,2,4,…; 100 → 0,25,50,…
      const steps = max % 4 === 0 ? 4 : 5;
      for (let i = 0; i <= steps; i++) {
        const v = (max / steps) * i;
        root.append(svg("line", { x1: M.left, x2: M.left + w, y1: y(v), y2: y(v), class: i ? "chart-grid" : "chart-axis" }));
        const label = svg("text", { x: M.left - 8, y: y(v) + 4, "text-anchor": "end", class: "chart-label" });
        label.textContent = formatValue(Math.round(v));
        root.append(label);
      }
      // X ticks: first, last and up to 3 in between.
      const tickIdx = [...new Set([0, Math.round((points.length - 1) / 2), points.length - 1])];
      let previousTick = null;
      for (const i of tickIdx) {
        if (fmtTick(points[i].at, span) === previousTick) continue;  // never print the same tick twice
        previousTick = fmtTick(points[i].at, span);
        const label = svg("text", { x: x(points[i]), y: HEIGHT - 6, "text-anchor": i === 0 && points.length > 1 ? "start"
          : i === points.length - 1 && points.length > 1 ? "end" : "middle", class: "chart-label" });
        label.textContent = fmtTick(points[i].at, span);
        root.append(label);
      }
      // Line + markers.
      if (points.length > 1) {
        root.append(svg("path", { d: points.map((p, i) => `${i ? "L" : "M"}${x(p)},${y(p.value)}`).join(""), class: "chart-line" }));
      }
      if (points.length <= 60) {
        for (const p of points) root.append(svg("circle", { cx: x(p), cy: y(p.value), r: 4, class: "chart-dot" }));
      }
      // Crosshair + focused marker.
      const cross = svg("line", { y1: M.top, y2: M.top + h, class: "chart-cross", visibility: "hidden" });
      const focus = svg("circle", { r: 5, class: "chart-focus", visibility: "hidden" });
      root.append(cross, focus);
      // Hit area covering the plot: the reader aims at a date, not a 2px line.
      const hit = svg("rect", { x: M.left - 8, y: M.top, width: w + 16, height: h, fill: "transparent" });
      root.append(hit);

      function show(i) {
        active = i;
        const p = points[i];
        cross.setAttribute("x1", x(p)); cross.setAttribute("x2", x(p)); cross.setAttribute("visibility", "visible");
        focus.setAttribute("cx", x(p)); focus.setAttribute("cy", y(p.value)); focus.setAttribute("visibility", "visible");
        tooltip.replaceChildren();
        const value = document.createElement("strong");
        value.textContent = `${formatValue(p.value)} ${valueLabel}`;
        const title = document.createElement("div");
        title.className = "muted small";
        title.textContent = `${p.title} · ${p.at.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}`;
        tooltip.append(value, title);
        for (const [label, v] of p.rows || []) {
          const row = document.createElement("div");
          row.className = "small";
          row.textContent = `${label}: ${v}`;
          tooltip.append(row);
        }
        tooltip.hidden = false;
        const left = Math.min(Math.max(x(p) + 12, 0), width - 200);
        tooltip.style.left = `${left}px`;
        tooltip.style.top = `${Math.max(y(p.value) - 20, 0)}px`;
      }
      function hide() {
        cross.setAttribute("visibility", "hidden");
        focus.setAttribute("visibility", "hidden");
        tooltip.hidden = true;
      }
      function nearest(clientX) {
        const box = root.getBoundingClientRect();
        const px = ((clientX - box.left) / box.width) * width;
        let best = 0;
        points.forEach((p, i) => { if (Math.abs(x(p) - px) < Math.abs(x(points[best]) - px)) best = i; });
        return best;
      }
      hit.addEventListener("pointermove", (e) => show(nearest(e.clientX)));
      hit.addEventListener("pointerleave", hide);
      container.onkeydown = (e) => {
        if (e.key === "ArrowLeft") { show(Math.max(0, active - 1)); e.preventDefault(); }
        if (e.key === "ArrowRight") { show(Math.min(points.length - 1, active + 1)); e.preventDefault(); }
      };
      container.onfocus = () => show(active);
      container.onblur = hide;
      container.replaceChildren(root, tooltip);
    }

    container.classList.add("chart");
    container.tabIndex = 0;
    container.setAttribute("aria-label", `${valueLabel} chart. Use left and right arrow keys to read values.`);
    draw();
    if (window.ResizeObserver) {
      let last = container.clientWidth;
      new ResizeObserver(() => {
        if (Math.abs(container.clientWidth - last) > 4) { last = container.clientWidth; draw(); }
      }).observe(container);
    }
  }

  window.Charts = { lineChart };
})();
