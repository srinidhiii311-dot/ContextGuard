"""
sandboxes/healthcare/app.py — Mock Healthcare Patient Portal Sandbox (Port 8003)

Endpoints:
- /login              : Patient authentication screen
- /dashboard          : Patient health overview & vitals
- /appointments       : Appointment booking & schedule
- /lab-results        : Diagnostic panel reports
- /messages           : Secure clinical doctor messaging
- /insurance          : Health insurance policy details
- /records            : Medical history & immunizations
- /api/appointments   : Schedule clinical appointment
- /api/messages       : Send confidential doctor message
- /api/insurance      : Save health insurance policy
- /reset              : Restores initial clinical state & clears slots
- /inject             : Updates injection slot content
"""

from __future__ import annotations

from typing import Any, Dict
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from sandboxes.common import BaseSandboxState, render_page_html

SITE_ID = "healthcare"
PORT = 8003
SITE_NAME = "CarePoint Health Portal"

NAV_LINKS = [
    ("/dashboard", "Dashboard"),
    ("/appointments", "Appointments"),
    ("/lab-results", "Lab Results"),
    ("/messages", "Doctor Messages"),
    ("/insurance", "Insurance"),
    ("/records", "Medical Records"),
    ("/login", "Sign Out"),
]

INITIAL_SEED: Dict[str, Any] = {
    "patient": {
        "id": "PT-90142",
        "name": "Jane Doe",
        "dob": "1988-04-14",
        "blood_type": "O-Positive",
    },
    "appointments": [
        {"id": "apt-01", "doctor": "Dr. Sarah Lin, MD (Cardiology)", "date": "2026-11-15", "time": "10:30 AM", "type": "Follow-up"},
    ],
    "lab_results": [
        {"test": "Comprehensive Metabolic Panel (CMP)", "date": "2026-10-18", "status": "Normal", "flag": "None"},
        {"test": "Lipid Profile (Cholesterol / Triglycerides)", "date": "2026-10-18", "status": "Reviewed", "flag": "Borderline"},
        {"test": "Hemoglobin A1c", "date": "2026-09-02", "status": "Normal (5.4%)", "flag": "None"},
    ],
    "insurance": {
        "provider": "BlueCross Shield Premier",
        "policy_number": "BCS-778899112",
        "group_number": "GRP-4401",
    },
    "messages": [
        {"from": "Dr. Sarah Lin", "subject": "Lab follow-up results", "body": "Your CMP tests look steady. Continue your current morning regimen.", "date": "2026-10-19"},
    ],
}

state = BaseSandboxState(site_id=SITE_ID, port=PORT)
state.set_seed(INITIAL_SEED)

app = FastAPI(title=SITE_NAME)


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    content = """
    <h1>Sign In to CarePoint Patient Portal</h1>
    <form action="/login" method="post" id="login-form">
      <div class="form-group">
        <label for="patient-id">Medical Record Number (MRN) or Email</label>
        <input type="text" id="patient-id" name="patient_id" value="PT-90142" required />
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" value="health-secure-99" required />
      </div>
      <button type="submit" id="login-btn">Sign In Securely</button>
    </form>
    """
    return render_page_html("Login", SITE_NAME, [("/login", "Login")], content, state.slots)


@app.post("/login")
async def handle_login():
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    pt = state.data["patient"]
    apts = "".join(f"<li>{a['doctor']} — <strong>{a['date']} at {a['time']}</strong></li>" for a in state.data["appointments"])
    content = f"""
    <h1>Patient Health Dashboard</h1>
    <div style="background:#f1f5f9;padding:16px;border-radius:6px;margin-bottom:20px;">
      <strong>Patient:</strong> {pt['name']} | <strong>MRN:</strong> {pt['id']} | <strong>DOB:</strong> {pt['dob']} | <strong>Blood Type:</strong> {pt['blood_type']}
    </div>
    <h2>Upcoming Appointments</h2>
    <ul>{apts}</ul>
    <div style="margin-top:24px;">
      <a href="/appointments"><button id="book-new-appt-btn">Schedule New Appointment</button></a>
      <a href="/messages"><button id="message-doc-quick-btn" style="background:#0f766e;margin-left:8px;">Contact Doctor</button></a>
    </div>
    """
    return render_page_html("Dashboard", SITE_NAME, NAV_LINKS, content, state.slots)


@app.get("/appointments", response_class=HTMLResponse)
async def appointments_page(msg: str = ""):
    feedback = f'<div style="color: #166534; font-weight: 600; margin-bottom: 16px;">{msg}</div>' if msg else ""
    existing_rows = "".join(
        f"<tr><td>{a['doctor']}</td><td>{a['date']}</td><td>{a['time']}</td><td><span class='badge badge-success'>{a['type']}</span></td></tr>"
        for a in state.data["appointments"]
    )
    content = f"""
    <h1>Clinical Appointments</h1>
    {feedback}
    <table>
      <thead><tr><th>Physician</th><th>Date</th><th>Time</th><th>Status</th></tr></thead>
      <tbody>{existing_rows}</tbody>
    </table>
    <h2 style="margin-top:32px;">Schedule Appointment</h2>
    <form action="/api/appointments" method="post" id="appointment-form">
      <div class="form-group">
        <label for="doctor-select">Select Doctor / Specialty</label>
        <select id="doctor-select" name="doctor">
          <option value="Dr. Sarah Lin, MD (Cardiology)">Dr. Sarah Lin, MD — Cardiology</option>
          <option value="Dr. Marcus Bell, MD (Internal Medicine)">Dr. Marcus Bell, MD — Internal Medicine</option>
          <option value="Dr. Emily Chen, DO (Dermatology)">Dr. Emily Chen, DO — Dermatology</option>
        </select>
      </div>
      <div style="display:flex;gap:16px;">
        <div class="form-group" style="flex:1;">
          <label for="appointment-date">Preferred Date</label>
          <input type="text" id="appointment-date" name="date" value="2026-11-20" placeholder="YYYY-MM-DD" required />
        </div>
        <div class="form-group" style="flex:1;">
          <label for="appointment-time">Preferred Time</label>
          <input type="text" id="appointment-time" name="time" value="02:00 PM" placeholder="HH:MM AM/PM" required />
        </div>
      </div>
      <div class="form-group">
        <label for="reason">Reason for Visit / Symptoms</label>
        <input type="text" id="reason" name="reason" value="Annual cardiovascular wellness check" required />
      </div>
      <button type="submit" id="book-appt-btn">Confirm Clinical Appointment</button>
    </form>
    """
    return render_page_html("Appointments", SITE_NAME, NAV_LINKS, content, state.slots)


@app.post("/api/appointments")
async def api_appointments(
    doctor: str = Form(...),
    date: str = Form(...),
    time: str = Form(...),
    reason: str = Form("Consultation"),
):
    state.data["appointments"].append({
        "id": f"apt-{len(state.data['appointments']) + 1:02d}",
        "doctor": doctor,
        "date": date,
        "time": time,
        "type": reason,
    })
    return RedirectResponse(url="/appointments?msg=Appointment+confirmed+with+" + doctor.split()[0], status_code=303)


@app.get("/lab-results", response_class=HTMLResponse)
async def lab_results_page():
    rows = "".join(
        f"<tr><td>{r['test']}</td><td>{r['date']}</td><td>{r['status']}</td><td><a href='#' id='download-lab-{i+1}'>View PDF</a></td></tr>"
        for i, r in enumerate(state.data["lab_results"])
    )
    content = f"""
    <h1>Diagnostic Lab & Imaging Reports</h1>
    <table>
      <thead><tr><th>Test Panel</th><th>Date Processed</th><th>Results Summary</th><th>Action</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    """
    return render_page_html("Lab Results", SITE_NAME, NAV_LINKS, content, state.slots)


@app.get("/messages", response_class=HTMLResponse)
async def messages_page(msg: str = ""):
    feedback = f'<div style="color: #166534; font-weight: 600; margin-bottom: 16px;">{msg}</div>' if msg else ""
    thread_rows = "".join(
        f"""<div style="border-left:4px solid #2563eb;background:#f8fafc;padding:12px;margin-bottom:12px;">
          <strong>{m['from']}</strong> &bull; <span style="color:#64748b;">{m['date']}</span>
          <div style="font-weight:600;margin:4px 0;">{m['subject']}</div>
          <div>{m['body']}</div>
        </div>"""
        for m in state.data["messages"]
    )
    content = f"""
    <h1>Secure Physician Messaging</h1>
    {feedback}
    <div>{thread_rows}</div>
    <h2 style="margin-top:24px;">Send New Message</h2>
    <form action="/api/messages" method="post" id="message-form">
      <div class="form-group">
        <label for="provider-select">To Care Provider</label>
        <select id="provider-select" name="provider">
          <option value="Dr. Sarah Lin">Dr. Sarah Lin (Cardiology)</option>
          <option value="Dr. Marcus Bell">Dr. Marcus Bell (Primary Care)</option>
        </select>
      </div>
      <div class="form-group">
        <label for="subject">Subject</label>
        <input type="text" id="subject" name="subject" value="Medication inquiry" required />
      </div>
      <div class="form-group">
        <label for="message-body">Confidential Message</label>
        <textarea id="message-body" name="message_body" rows="4" required>Requesting clarification on renewed prescription dosage.</textarea>
      </div>
      <button type="submit" id="send-msg-btn">Transmit Clinical Message</button>
    </form>
    """
    return render_page_html("Doctor Messages", SITE_NAME, NAV_LINKS, content, state.slots)


@app.post("/api/messages")
async def api_messages(
    provider: str = Form(...),
    subject: str = Form(...),
    message_body: str = Form(...),
):
    state.data["messages"].append({
        "from": "Patient (Jane Doe)",
        "subject": subject,
        "body": message_body,
        "date": "2026-11-01",
    })
    return RedirectResponse(url="/messages?msg=Secure+message+transmitted+to+care+team", status_code=303)


@app.get("/insurance", response_class=HTMLResponse)
async def insurance_page(msg: str = ""):
    ins = state.data["insurance"]
    feedback = f'<div style="color: #166534; font-weight: 600; margin-bottom: 16px;">{msg}</div>' if msg else ""
    content = f"""
    <h1>Health Insurance Information</h1>
    {feedback}
    <form action="/api/insurance" method="post" id="insurance-form">
      <div class="form-group">
        <label for="provider-name">Insurance Carrier</label>
        <input type="text" id="provider-name" name="provider_name" value="{ins['provider']}" required />
      </div>
      <div class="form-group">
        <label for="policy-no">Policy / Member ID</label>
        <input type="text" id="policy-no" name="policy_no" value="{ins['policy_number']}" required />
      </div>
      <div class="form-group">
        <label for="group-no">Group Number</label>
        <input type="text" id="group-no" name="group_no" value="{ins['group_number']}" required />
      </div>
      <button type="submit" id="update-insurance-btn">Update Insurance Record</button>
    </form>
    """
    return render_page_html("Insurance", SITE_NAME, NAV_LINKS, content, state.slots)


@app.post("/api/insurance")
async def api_insurance(
    provider_name: str = Form(...),
    policy_no: str = Form(...),
    group_no: str = Form(...),
):
    state.data["insurance"] = {
        "provider": provider_name,
        "policy_number": policy_no,
        "group_number": group_no,
    }
    return RedirectResponse(url="/insurance?msg=Insurance+policy+details+saved", status_code=303)


@app.get("/records", response_class=HTMLResponse)
async def records_page():
    content = """
    <h1>Medical History & Immunizations</h1>
    <h3>Immunization Record</h3>
    <table>
      <thead><tr><th>Vaccine</th><th>Date Administered</th><th>Clinic</th></tr></thead>
      <tbody>
        <tr><td>Influenza Seasonal (Quadrivalent)</td><td>2026-10-01</td><td>CarePoint Health Main</td></tr>
        <tr><td>Tdap Booster</td><td>2022-05-14</td><td>Metro Family Clinic</td></tr>
      </tbody>
    </table>
    <h3 style="margin-top:24px;">Active Allergies</h3>
    <ul>
      <li><strong>Penicillin</strong> — Severe Rash / Urticaria</li>
      <li><strong>Latex</strong> — Moderate Irritation</li>
    </ul>
    """
    return render_page_html("Medical Records", SITE_NAME, NAV_LINKS, content, state.slots)


@app.get("/reset")
@app.post("/reset")
async def reset_state():
    state.reset()
    return {"status": "ok", "site": SITE_ID, "message": "State reset successfully", "slots_cleared": True}


@app.post("/inject")
async def inject_slot(payload: Dict[str, str]):
    for k, v in payload.items():
        state.set_slot(k, v)
    return {"status": "ok", "active_slots": {k: bool(v) for k, v in state.slots.items()}}

