from flask import Flask, render_template, request, redirect, url_for
import pandas as pd
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)
DB_FILE = "vulnlite.db"

# Veritabanı hazırlama
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT,
                    risk TEXT,
                    cve TEXT,
                    cvss TEXT,
                    name TEXT,
                    fix_date TEXT
                )''')
    conn.commit()
    conn.close()

init_db()

# Ana sayfa (CSV yükleme)
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
            # Kolon isimlerini normalize et
            col_map = {
                'Risk Factor': 'risk',
                'CVE': 'cve',
                'CVSS v2.0 Base Score': 'cvss',
                'Name': 'name',
                'Host': 'host'
            }
            df = df.rename(columns=col_map)
            df_show = df[['host', 'risk', 'cve', 'cvss', 'name']].fillna('-')

            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            for _, row in df_show.iterrows():
                c.execute("INSERT INTO vulnerabilities (host, risk, cve, cvss, name, fix_date) VALUES (?, ?, ?, ?, ?, ?)",
                          (row['host'], row['risk'], row['cve'], str(row['cvss']), row['name'], None))
            conn.commit()
            conn.close()
            return redirect(url_for('results'))
    return render_template('index.html')

@app.route('/results', methods=['GET', 'POST'])
def results():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    if request.method == 'POST':
        vuln_id = request.form['id']
        fix_date = request.form['fix_date']
        c.execute("UPDATE vulnerabilities SET fix_date=? WHERE id=?", (fix_date, vuln_id))
        conn.commit()

    # Checkbox kontrolü
    show_none = request.args.get('show_none', 'off')

    # Sıralama parametreleri
    sort_by = request.args.get('sort', 'id')
    order = request.args.get('order', 'asc')

    query = "SELECT * FROM vulnerabilities"
    if show_none != 'on':
        query += " WHERE risk != 'None' AND risk != '-'"

    if sort_by == 'risk':
        query += (
            " ORDER BY CASE risk "
            "WHEN 'Critical' THEN 1 "
            "WHEN 'High' THEN 2 "
            "WHEN 'Medium' THEN 3 "
            "WHEN 'Low' THEN 4 "
            "ELSE 5 END"
        )
    elif sort_by == 'cvss':
        query += f" ORDER BY CAST(cvss AS FLOAT) {order.upper()}"
    else:
        query += f" ORDER BY id {order.upper()}"

    df = pd.read_sql_query(query, conn)
    conn.close()

    # Deadline kontrolü
    today = datetime.today().date()
    warnings = {}
    for _, row in df.iterrows():
        if row['fix_date']:
            try:
                due = datetime.strptime(row['fix_date'], "%Y-%m-%d").date()
                if due < today:
                    warnings[row['id']] = "overdue"
                elif due <= today + timedelta(days=3):
                    warnings[row['id']] = "soon"
            except:
                continue

    # Risk dağılımı (özet tablo için)
    if not df.empty:
        risk_counts = df['risk'].replace(['None', '-'], 'Info').value_counts().to_dict()
        order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        risk_counts = {k: risk_counts.get(k, 0) for k in order if k in risk_counts}
    else:
        risk_counts = {}

    return render_template(
        'results.html',
        data=df.to_dict(orient='records'),
        risk_counts=risk_counts,
        warnings=warnings
    )

if __name__ == '__main__':
    app.run(debug=True)
