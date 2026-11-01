import datetime
import math
import statistics
from flask import Blueprint, jsonify, request

bp = Blueprint("component_test_timeline", __name__, static_folder="static",
               static_url_path="/component-test-duration-assets")


def _dt(value):
    if value is None: return None
    text = str(value).strip()
    if not text: return None
    try:
        serial = float(text)
        if 1 <= serial <= 100000:
            return datetime.datetime(1899, 12, 30) + datetime.timedelta(days=serial)
    except (ValueError, TypeError, OverflowError):
        pass
    clean = text.replace("T", " ").replace("Z", "").strip()
    for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %I:%M %p","%Y/%m/%d %H:%M:%S","%Y/%m/%d %H:%M","%Y/%m/%d",
                "%Y-%m-%d %I:%M:%S %p","%Y-%m-%d %I:%M %p","%Y-%m-%d %H:%M:%S.%f","%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M","%Y-%m-%d","%m/%d/%Y %I:%M:%S %p","%m/%d/%Y %I:%M %p",
                "%m/%d/%Y %H:%M:%S","%m/%d/%Y %H:%M","%m/%d/%Y"):
        try: return datetime.datetime.strptime(clean, fmt)
        except ValueError: pass
    try: return datetime.datetime.fromisoformat(clean)
    except (ValueError, TypeError): return None


def _date(value, default):
    try: return datetime.datetime.strptime((value or "").strip(), "%Y-%m-%d").date()
    except ValueError: return default


def _pearson(a, b):
    if len(a) < 2 or len(a) != len(b): return None
    ma = sum(a) / len(a); mb = sum(b) / len(b)
    top = sum((x - ma) * (y - mb) for x, y in zip(a, b))
    bottom = math.sqrt(sum((x - ma) ** 2 for x in a) * sum((y - mb) ** 2 for y in b))
    return round(top / bottom, 3) if bottom else None


def _avg_daily(grouped_series, codes, chosen_label):
    """Aggregate daily averages across a set of stock codes for a brand."""
    daily = {}
    for code in codes:
        for point in grouped_series.get(code, []):
            daily.setdefault(point["date"], []).append(point["days"])
    return {d: round(sum(v) / len(v), 3) for d, v in daily.items()}


COLOR_PALETTE = [
    "#4f8cff", "#22c55e", "#a78bfa", "#f59e0b", "#06b6d4",
    "#ec4899", "#10b981", "#8b5cf6", "#f97316", "#eab308",
    "#14b8a6", "#d946ef", "#84cc16", "#0ea5e9", "#ef4444",
    "#64748b", "#f472b6", "#fb923c", "#a3e635", "#2dd4bf",
]

# Max stock codes the API will return in a single request.
# Brand mode resolves to all matching stock codes, so this needs to be
# generous enough to cover real-world brand/component groupings.
MAX_STOCKS_PER_REQUEST = 100


def register(app):
    if bp.name in app.blueprints:
        return
    core = __import__(app.import_name, fromlist=["get_db", "permission_required"])

    @bp.get("/api/component-test-duration")
    @core.permission_required("kpi")
    def data():
        db = core.get_db()
        today = datetime.date.today()
        start_default = today - datetime.timedelta(days=90)
        start = _date(request.args.get("from"), start_default)
        end = _date(request.args.get("to"), today)
        if start > end:
            start, end = end, start

        mode = (request.args.get("mode") or "stock").strip().lower()
        if mode not in ("stock", "brand"):
            mode = "stock"

        available = [r["stock_code"] for r in db.execute(
            "SELECT DISTINCT TRIM(stock_code) stock_code FROM tickets "
            "WHERE stock_code IS NOT NULL AND TRIM(stock_code)!='' "
            "ORDER BY stock_code COLLATE NOCASE"
        ).fetchall()]

        # Distinct brands + which stock codes belong to each brand
        brand_rows = db.execute(
            "SELECT LOWER(TRIM(brand)) AS brand_key, TRIM(brand) AS brand, TRIM(stock_code) AS stock_code "
            "FROM stockcode_metadata WHERE brand IS NOT NULL AND TRIM(brand) != '' "
            "ORDER BY brand COLLATE NOCASE, stock_code COLLATE NOCASE"
        ).fetchall()
        brand_map = {}
        brand_display = {}
        for r in brand_rows:
            key = r["brand_key"]; display = r["brand"]
            brand_display.setdefault(key, display)
            brand_map.setdefault(display, []).append(r["stock_code"])
        available_brands = sorted(brand_map.keys(), key=lambda s: s.casefold())

        selected_stocks, selected_brands = [], []
        if mode == "stock":
            for item in request.args.getlist("stock"):
                item = item.strip()
                if item in available and item not in selected_stocks:
                    selected_stocks.append(item)
                if len(selected_stocks) >= MAX_STOCKS_PER_REQUEST:
                    break
        else:
            for item in request.args.getlist("brand"):
                item = item.strip()
                if item in brand_map and item not in selected_brands:
                    selected_brands.append(item)
                if len(selected_brands) >= 3:
                    break

        relevant_codes = set(selected_stocks)
        for b in selected_brands:
            relevant_codes.update(brand_map.get(b, []))
        relevant_codes = [c for c in relevant_codes if c]

        result = []
        daily_maps = {}

        if relevant_codes:
            marks = ",".join("?" for _ in relevant_codes)
            rows = db.execute(
                f"SELECT stock_code, mrs_ticket, serial_number, test_started_at, assigned_at, "
                f"created_at, completed_at FROM tickets "
                f"WHERE stock_code IN ({marks}) AND completed_at IS NOT NULL "
                f"ORDER BY completed_at", relevant_codes).fetchall()
            grouped = {code: [] for code in relevant_codes}
            for row in rows:
                began = (_dt(row["test_started_at"]) or _dt(row["assigned_at"]) or _dt(row["created_at"]))
                finished = _dt(row["completed_at"])
                if not began or not finished or finished < began:
                    continue
                if not (start <= finished.date() <= end):
                    continue
                days = round((finished - began).total_seconds() / 86400, 3)
                grouped[row["stock_code"]].append({
                    "date": finished.date().isoformat(),
                    "days": days,
                    "ticket": row["mrs_ticket"] or "",
                    "serial": row["serial_number"] or "",
                })

        if mode == "stock":
            series_labels = selected_stocks
            for i, stock in enumerate(series_labels):
                points = grouped.get(stock, [])
                daily = {}
                for p in points:
                    daily.setdefault(p["date"], []).append(p["days"])
                daily = {d: round(sum(v) / len(v), 3) for d, v in daily.items()}
                daily_maps[stock] = daily
                vals = [p["days"] for p in points]
                result.append({
                    "stock": stock,
                    "color": COLOR_PALETTE[i % len(COLOR_PALETTE)],
                    "daily": [{"date": d, "days": daily[d]} for d in sorted(daily)],
                    "count": len(vals),
                    "average": round(sum(vals) / len(vals), 2) if vals else None,
                    "median": round(statistics.median(vals), 2) if vals else None,
                    "minimum": round(min(vals), 2) if vals else None,
                    "maximum": round(max(vals), 2) if vals else None,
                })
        else:
            for i, brand in enumerate(selected_brands):
                codes = brand_map.get(brand, [])
                daily = _avg_daily(grouped, codes, brand)
                daily_maps[brand] = daily
                total_count = 0
                all_days = []
                for c in codes:
                    pts = grouped.get(c, [])
                    total_count += len(pts)
                    all_days.extend(p["days"] for p in pts)
                result.append({
                    "stock": f"Brand: {brand}",
                    "color": COLOR_PALETTE[i % len(COLOR_PALETTE)],
                    "daily": [{"date": d, "days": daily[d]} for d in sorted(daily)],
                    "count": total_count,
                    "average": round(sum(all_days) / len(all_days), 2) if all_days else None,
                    "median": round(statistics.median(all_days), 2) if all_days else None,
                    "minimum": round(min(all_days), 2) if all_days else None,
                    "maximum": round(max(all_days), 2) if all_days else None,
                    "stock_codes": codes,
                })

        corr = []
        labels = [s["stock"] for s in result]
        for i in range(len(labels)):
            for j in range(i + 1, len(labels)):
                a, b = labels[i], labels[j]
                common = sorted(set(daily_maps.get(a, {})) & set(daily_maps.get(b, {})))
                corr.append({
                    "left": a, "right": b,
                    "value": _pearson([daily_maps[a][d] for d in common],
                                       [daily_maps[b][d] for d in common]),
                    "samples": len(common),
                })

        # Metadata map used by the Brand -> Component Type -> Stock Code UI
        metadata = {}
        for row in db.execute(
            "SELECT TRIM(stock_code) AS stock_code, TRIM(brand) AS brand, "
            "TRIM(component_type) AS component_type "
            "FROM stockcode_metadata WHERE stock_code IS NOT NULL AND TRIM(stock_code) != ''"
        ).fetchall():
            sc = row["stock_code"]
            if sc and sc not in metadata:
                metadata[sc] = {
                    "brand": row["brand"] or "",
                    "component_type": row["component_type"] or "",
                }

        return jsonify({
            "available": available,
            "available_brands": available_brands,
            "metadata": metadata,
            "mode": mode,
            "selected": selected_stocks,
            "selected_brands": selected_brands,
            "from": start.isoformat(),
            "to": end.isoformat(),
            "series": result,
            "correlations": corr,
            "warning_days": 4,
            "limit_days": 5,
        })

    app.register_blueprint(bp)