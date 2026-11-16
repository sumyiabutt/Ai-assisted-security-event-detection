# Screenshot checklist

All images in this folder were captured from the running project. Retake them whenever the
theme or page layout changes.

| File | Page | Viewport | What to show |
| --- | --- | --- | --- |
| `dashboard.png` | `/dashboard` | 1440 px, full page | Four stat cards, 8.6% donut, hourly chart, suspicious sources, suspicious logins, recent alerts |
| `alerts.png` | `/alerts` | 1440 px, full page | Search + severity/source filters, 12 alerts with severity pills, sources and MITRE codes |
| `analyze.png` | `/analyze` | 1440 px, full page | Drag-and-drop upload, sample dataset panel, required CSV format table |
| `analyze-preview.png` | `/analyze/preview` (sample) | 1440 px, full page | Validation summary (2,000 valid, 0 rejected), first eight rows, rejected-row section |
| `analyze-result.png` | `/analyze?run_id=1` | 1440 px, full page | Analysis-complete banner, 12 alerts, severity mix, links to dashboard and alerts |
| `mobile-dashboard.png` | `/dashboard` | 390 px, full page | Single-column cards, stacked tables with labels, no horizontal page scroll |
| `mobile-alerts.png` | `/alerts` | 390 px, full page | Stacked alert cards, filters stacked vertically |

## How to retake

1. Start the app with `python app.py` and open <http://127.0.0.1:5000>.
2. For desktop shots use a browser window at 1440 px wide.
3. For a fresh dashboard, delete `cyberfox.db` and restart so the bundled sample is analysed
   again.
4. On `/analyze`, click **Load sample dataset** for the preview shot. Open
   `/analyze?run_id=1` for the result shot.
5. For mobile shots use the browser device toolbar at 390 × 844 (iPhone 12/13 width) and
   confirm the page does not scroll sideways.

## Visual checks

- Severity colours: Critical `#ff4d6a`, High `#ff7a2f`, Medium `#ffc24a`, Low `#5aa9ff`.
- Header shows the fox-shield logo, three navigation links and the defensive-mode chip.
- Keyboard focus shows a cyan 2 px outline (`Tab` through the page).
- In the mobile view, tables turn into labelled cards rather than clipping at the edge.
