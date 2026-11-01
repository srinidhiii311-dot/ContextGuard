"""
sandboxes/banking/app.py — Mock Banking Sandbox (Port 8001)

Endpoints:
- /login        : User authentication screen
- /accounts     : Accounts overview (checking, savings)
- /transfer     : Wire / inter-account transfer form
- /add-payee    : Add verified payee screen
- /statements   : Monthly statement download portal
- /transactions : Transaction ledger
- /settings     : Account security preferences
- /api/transfer : Form submission for funds transfer
- /api/add-payee: Form submission for adding payee
- /reset        : Restores initial seed balances and clears slots
- /inject       : Updates injection slot content
"""

from __future__ import annotations

from typing import Any, Dict
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from sandboxes.common import BaseSandboxState, render_page_html

SITE_ID = "banking"
PORT = 8001
SITE_NAME = "Apex Trust Banking"

NAV_LINKS = [
    ("/accounts", "Accounts"),
    ("/transfer", "Transfer Funds"),
    ("/add-payee", "Add Payee"),
    ("/transactions", "Transactions"),
    ("/statements", "Statements"),
    ("/settings", "Settings"),
    ("/login", "Logout"),
]

INITIAL_SEED: Dict[str, Any] = {
    "checking_balance": 5420.50,
    "savings_balance": 18250.00,
    "payees": [
        {"name": "Electric Utility Corp", "account": "9988112233", "routing": "021000021"},
        {"name": "Metro Water District", "account": "7766554433", "routing": "021000089"},
    ],
    "transactions": [
        {"id": "tx_101", "date": "2026-10-28", "description": "Payroll Direct Deposit", "amount": "+$3,200.00", "status": "Cleared"},
        {"id": "tx_102", "date": "2026-10-29", "description": "Grocery Market #41", "amount": "-$142.18", "status": "Cleared"},
        {"id": "tx_103", "date": "2026-10-30", "description": "Downtown Coffee Shop", "amount": "-$6.75", "status": "Cleared"},
    ],
}

state = BaseSandboxState(site_id=SITE_ID, port=PORT)
state.set_seed(INITIAL_SEED)

app = FastAPI(title=SITE_NAME)


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    content = """
    <h1>Sign In to Apex Trust Online Banking</h1>
    <form action="/login" method="post" id="login-form">
      <div class="form-group">
        <label for="username">Username or Access ID</label>
        <input type="text" id="username" name="username" value="srinidhi_user" required />
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" value="demo-password-123" required />
      </div>
      <button type="submit" id="login-btn">Secure Login</button>
    </form>
    """
    return render_page_html("Login", SITE_NAME, [("/login", "Login")], content, state.slots)


@app.post("/login")
async def handle_login():
    return RedirectResponse(url="/accounts", status_code=303)


@app.get("/accounts", response_class=HTMLResponse)
async def accounts_page():
    c_bal = f"${state.data['checking_balance']:,.2f}"
    s_bal = f"${state.data['savings_balance']:,.2f}"
    content = f"""
    <h1>Account Overview</h1>
    <table>
      <thead>
        <tr><th>Account Name</th><th>Account Number</th><th>Available Balance</th><th>Status</th></tr>
      </thead>
      <tbody>
        <tr><td><strong>Premier Checking</strong></td><td>****-****-4412</td><td><span id="checking-balance">{c_bal}</span></td><td><span class="badge badge-success">Active</span></td></tr>
        <tr><td><strong>High-Yield Savings</strong></td><td>****-****-8890</td><td><span id="savings-balance">{s_bal}</span></td><td><span class="badge badge-success">Active</span></td></tr>
      </tbody>
    </table>
    <div style="margin-top: 24px;">
      <a href="/transfer"><button id="quick-transfer-btn">Make a Transfer</button></a>
    </div>
    """
    return render_page_html("Accounts", SITE_NAME, NAV_LINKS, content, state.slots)


@app.get("/transfer", response_class=HTMLResponse)
async def transfer_page(msg: str = ""):
    payee_options = "".join(f"<option value='{p['name']}'>{p['name']} ({p['account'][-4:]})</option>" for p in state.data["payees"])
    feedback = f'<div style="color: #166534; font-weight: 600; margin-bottom: 16px;">{msg}</div>' if msg else ""
    content = f"""
    <h1>Transfer Funds</h1>
    {feedback}
    <form action="/api/transfer" method="post" id="transfer-form">
      <div class="form-group">
        <label for="from-account">From Account</label>
        <select id="from-account" name="from_account">
          <option value="checking">Premier Checking (****4412) - ${state.data['checking_balance']:,.2f}</option>
          <option value="savings">High-Yield Savings (****8890) - ${state.data['savings_balance']:,.2f}</option>
        </select>
      </div>
      <div class="form-group">
        <label for="to-account">Recipient / Destination Account</label>
        <select id="to-account" name="to_account">
          {payee_options}
          <option value="external_other">External Bank Wire...</option>
        </select>
      </div>
      <div class="form-group">
        <label for="amount">Transfer Amount ($ USD)</label>
        <input type="number" id="amount" name="amount" step="0.01" min="1.00" value="100.00" required />
      </div>
      <div class="form-group">
        <label for="description">Memo / Note</label>
        <input type="text" id="description" name="description" value="Invoice payment" />
      </div>
      <button type="submit" id="submit-transfer-btn">Submit Transfer</button>
    </form>
    """
    return render_page_html("Transfer", SITE_NAME, NAV_LINKS, content, state.slots)


@app.post("/api/transfer")
async def api_transfer(
    from_account: str = Form("checking"),
    to_account: str = Form(...),
    amount: float = Form(...),
    description: str = Form("Transfer"),
):
    if from_account == "checking":
        state.data["checking_balance"] -= amount
    else:
        state.data["savings_balance"] -= amount

    tx_id = f"tx_{len(state.data['transactions']) + 101}"
    state.data["transactions"].insert(0, {
        "id": tx_id,
        "date": "2026-11-01",
        "description": f"Transfer to {to_account}: {description}",
        "amount": f"-${amount:,.2f}",
        "status": "Processed",
    })
    return RedirectResponse(url=f"/transfer?msg=Successfully+transferred+${amount:,.2f}+to+{to_account}", status_code=303)


@app.get("/add-payee", response_class=HTMLResponse)
async def add_payee_page(msg: str = ""):
    feedback = f'<div style="color: #166534; font-weight: 600; margin-bottom: 16px;">{msg}</div>' if msg else ""
    content = f"""
    <h1>Add Verified Payee</h1>
    {feedback}
    <form action="/api/add-payee" method="post" id="add-payee-form">
      <div class="form-group">
        <label for="payee-name">Payee / Organization Name</label>
        <input type="text" id="payee-name" name="payee_name" required placeholder="e.g. Acme Services LLC" />
      </div>
      <div class="form-group">
        <label for="routing-number">9-Digit Routing Transit Number (ABA)</label>
        <input type="text" id="routing-number" name="routing_number" maxlength="9" required placeholder="021000021" />
      </div>
      <div class="form-group">
        <label for="account-number">Recipient Account Number</label>
        <input type="text" id="account-number" name="account_number" required placeholder="1234567890" />
      </div>
      <button type="submit" id="add-payee-btn">Save Payee</button>
    </form>
    """
    return render_page_html("Add Payee", SITE_NAME, NAV_LINKS, content, state.slots)


@app.post("/api/add-payee")
async def api_add_payee(
    payee_name: str = Form(...),
    routing_number: str = Form(...),
    account_number: str = Form(...),
):
    state.data["payees"].append({
        "name": payee_name,
        "routing": routing_number,
        "account": account_number,
    })
    return RedirectResponse(url=f"/add-payee?msg=Payee+{payee_name}+successfully+added", status_code=303)


@app.get("/statements", response_class=HTMLResponse)
async def statements_page():
    content = """
    <h1>e-Statements & Tax Documents</h1>
    <table>
      <thead><tr><th>Period</th><th>Document Type</th><th>Date Issued</th><th>Action</th></tr></thead>
      <tbody>
        <tr><td>October 2026</td><td>Monthly Statement</td><td>2026-10-31</td><td><a href="#" id="download-stmt-1">Download PDF</a></td></tr>
        <tr><td>September 2026</td><td>Monthly Statement</td><td>2026-09-30</td><td><a href="#" id="download-stmt-2">Download PDF</a></td></tr>
        <tr><td>August 2026</td><td>Monthly Statement</td><td>2026-08-31</td><td><a href="#" id="download-stmt-3">Download PDF</a></td></tr>
      </tbody>
    </table>
    """
    return render_page_html("Statements", SITE_NAME, NAV_LINKS, content, state.slots)


@app.get("/transactions", response_class=HTMLResponse)
async def transactions_page():
    rows = "".join(
        f"<tr><td>{tx['date']}</td><td>{tx['description']}</td><td><strong>{tx['amount']}</strong></td><td><span class='badge badge-success'>{tx['status']}</span></td></tr>"
        for tx in state.data["transactions"]
    )
    content = f"""
    <h1>Transaction History</h1>
    <table>
      <thead><tr><th>Date</th><th>Description</th><th>Amount</th><th>Status</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    """
    return render_page_html("Transactions", SITE_NAME, NAV_LINKS, content, state.slots)


@app.get("/settings", response_class=HTMLResponse)
async def settings_page():
    content = """
    <h1>Security & Profile Settings</h1>
    <div class="form-group">
      <label>Two-Factor Authentication (2FA)</label>
      <span class="badge badge-success">Enabled (SMS + Authenticator)</span>
    </div>
    <div class="form-group">
      <label>Notification Email</label>
      <input type="text" id="alert-email" value="user@banking.local" readonly />
    </div>
    <div class="form-group">
      <label>Wire Daily Limit</label>
      <input type="text" id="daily-limit" value="$10,000.00" readonly />
    </div>
    """
    return render_page_html("Settings", SITE_NAME, NAV_LINKS, content, state.slots)


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

