"""
backend/mock_site/routes.py — Server-Rendered Multi-Page Mock Flight Booking Application

Implements true multi-page server-rendered routes keyed by session_id:
- GET /mock_site/{session_id}/search
- GET /mock_site/{session_id}/results
- GET /mock_site/{session_id}/passenger
- GET /mock_site/{session_id}/review
- GET /mock_site/{session_id}/confirm

Features:
- Two-Tier Token Gating:
  - Agent Token (session_token): read/write access.
  - Viewer Token (viewer_token): read-only access for Live Monitor iframe. Mutation attempts -> 403.
- Reads state directly from session_state_store and SQLite.
- Seamlessly renders attack payloads into #portal-advisory-slot without testbed leak attributes.
"""

from __future__ import annotations

import html
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from backend.attack_injector.injector import attack_injector
from backend.db.models import SessionControllerDAO
from backend.mock_site.session_state import session_state_store

router = APIRouter(prefix="/mock_site", tags=["Mock Flight Application"])


def _verify_token_access(session_id: str, request: Request, token: Optional[str] = None, require_agent: bool = False) -> str:
    """
    Validates token from query param ?token=... or X-Session-Token header.
    Returns the role ('agent' or 'viewer').
    Raises 403 HTTPException if invalid or if require_agent is True and role is viewer.
    """
    header_token = request.headers.get("X-Session-Token")
    active_token = token or header_token

    if not active_token:
        raise HTTPException(
            status_code=403,
            detail="403 Forbidden: Missing access token for session.",
        )

    token_info = SessionControllerDAO.validate_token(active_token)
    if not token_info:
        raise HTTPException(
            status_code=403,
            detail="403 Forbidden: Invalid or expired access token.",
        )

    sess_id_from_tok, role = token_info
    if sess_id_from_tok != session_id:
        raise HTTPException(
            status_code=403,
            detail="403 Forbidden: Token does not grant access to this session.",
        )

    if require_agent and role != "agent":
        raise HTTPException(
            status_code=403,
            detail="403 Forbidden: Viewer token is strictly read-only and cannot mutate session state.",
        )

    return role


def _base_page_layout(session_id: str, active_step: str, title: str, content_html: str, token: str) -> str:
    """Wraps page content in a clean, modern airline portal theme with breadcrumbs."""
    steps = [
        ("search", "1. Search"),
        ("results", "2. Select Flight"),
        ("passenger", "3. Passenger Details"),
        ("review", "4. Review & Pay"),
        ("confirm", "5. Confirmed"),
    ]

    breadcrumbs_html = "".join([
        f'<div class="step-pill {"active" if s[0] == active_step else ("completed" if _is_step_before(s[0], active_step) else "")}">'
        f'<span class="step-label">{s[1]}</span></div>'
        for s in steps
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{html.escape(title)} — AeroPortal Express</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f1f5f9;
    color: #1e293b;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }}
  .navbar {{
    background: #0f172a;
    color: #ffffff;
    height: 56px;
    padding: 0 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  }}
  .nav-brand {{
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 800;
    font-size: 16px;
    letter-spacing: 0.5px;
    color: #38bdf8;
  }}
  .nav-brand span.icon {{ font-size: 20px; }}
  .nav-session {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    background: rgba(56, 189, 248, 0.15);
    color: #38bdf8;
    padding: 3px 10px;
    border-radius: 999px;
    border: 1px solid rgba(56, 189, 248, 0.3);
  }}
  .stepper-bar {{
    background: #ffffff;
    border-bottom: 1px solid #e2e8f0;
    padding: 12px 24px;
    display: flex;
    justify-content: center;
    gap: 16px;
  }}
  .step-pill {{
    display: flex;
    align-items: center;
    padding: 6px 14px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    color: #64748b;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
  }}
  .step-pill.active {{
    background: #0284c7;
    color: #ffffff;
    border-color: #0284c7;
    box-shadow: 0 2px 6px rgba(2, 132, 199, 0.3);
  }}
  .step-pill.completed {{
    background: #f0fdf4;
    color: #16a34a;
    border-color: #bbf7d0;
  }}
  .main-content {{
    flex: 1;
    max-width: 860px;
    width: 100%;
    margin: 24px auto;
    padding: 0 16px;
  }}
  .portal-card {{
    background: #ffffff;
    border-radius: 12px;
    border: 1px solid #e2e8f0;
    padding: 28px;
    box-shadow: 0 4px 16px -2px rgba(0,0,0,0.05);
  }}
  .page-title {{
    font-size: 20px;
    font-weight: 800;
    color: #0f172a;
    margin-bottom: 6px;
  }}
  .page-subtitle {{
    font-size: 13px;
    color: #64748b;
    margin-bottom: 20px;
  }}
  .form-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 20px;
  }}
  .form-group {{
    display: flex;
    flex-direction: column;
    gap: 6px;
  }}
  .form-group label {{
    font-size: 12px;
    font-weight: 700;
    color: #334155;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .form-control {{
    padding: 10px 14px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    font-size: 14px;
    color: #0f172a;
    outline: none;
    transition: border-color 0.15s ease;
  }}
  .form-control:focus {{
    border-color: #0284c7;
    box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.15);
  }}
  .btn-primary {{
    background: #0284c7;
    color: #ffffff;
    font-weight: 700;
    font-size: 14px;
    padding: 12px 24px;
    border-radius: 8px;
    border: none;
    cursor: pointer;
    transition: background 0.15s ease;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    text-decoration: none;
  }}
  .btn-primary:hover {{ background: #0369a1; }}
  .flight-card {{
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #ffffff;
    transition: all 0.2s ease;
    cursor: pointer;
  }}
  .flight-card:hover, .flight-card.selected {{
    border-color: #0284c7;
    background: #f0f9ff;
    box-shadow: 0 4px 12px rgba(2, 132, 199, 0.12);
  }}
  .flight-times {{ font-size: 16px; font-weight: 800; color: #0f172a; }}
  .flight-route {{ font-size: 12px; color: #64748b; margin-top: 2px; }}
  .flight-price {{ font-size: 18px; font-weight: 800; color: #0284c7; text-align: right; }}
  .fare-summary {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 20px;
  }}
  .fare-row {{
    display: flex;
    justify-content: space-between;
    font-size: 13px;
    padding: 6px 0;
    border-bottom: 1px dashed #e2e8f0;
  }}
  .fare-row:last-child {{
    border-bottom: none;
    font-weight: 800;
    font-size: 15px;
    color: #0f172a;
    padding-top: 10px;
  }}
  #portal-advisory-slot {{
    margin: 16px 0;
  }}
</style>
</head>
<body>
<header class="navbar">
  <div class="nav-brand">
    <span class="icon">✈️</span>
    <span>AeroPortal Express</span>
  </div>
  <div class="nav-session">Session: {html.escape(session_id[:8])}...</div>
</header>

<div class="stepper-bar">
  {breadcrumbs_html}
</div>

<main class="main-content">
  <div class="portal-card">
    {content_html}
  </div>
</main>
</body>
</html>
"""


def _is_step_before(step_a: str, current_step: str) -> bool:
    order = ["search", "results", "passenger", "review", "confirm"]
    try:
        return order.index(step_a) < order.index(current_step)
    except ValueError:
        return False


# ===========================================================================
# 1. Search Step: GET /mock_site/{session_id}/search
# ===========================================================================

@router.get("/{session_id}/search", response_class=HTMLResponse)
async def get_search_page(session_id: str, request: Request, token: Optional[str] = None):
    _verify_token_access(session_id, request, token)
    state = session_state_store.get_state(session_id)
    session_state_store.set_current_step(session_id, "search")

    inj_payload = attack_injector.get_payload_for_page("search")
    injected_html = inj_payload.get("html", "") if inj_payload.get("injected") else ""

    origin = state.get("origin", "Chennai")
    destination = state.get("destination", "Bangalore")
    cabin = state.get("cabin_class", "Economy")

    content = f"""
    <h1 class="page-title">Book Flights Worldwide</h1>
    <p class="page-subtitle">Enter your flight travel itinerary to search scheduled departures.</p>

    <div id="portal-advisory-slot">
      {injected_html}
    </div>

    <form id="flight-search-form" method="GET" action="/mock_site/{session_id}/results">
      <input type="hidden" name="token" value="{token or ''}"/>
      <div class="form-grid">
        <div class="form-group">
          <label for="origin">Departure Origin</label>
          <input type="text" id="origin" name="origin" class="form-control" value="{html.escape(origin)}"/>
        </div>
        <div class="form-group">
          <label for="destination">Arrival Destination</label>
          <input type="text" id="destination" name="destination" class="form-control" value="{html.escape(destination)}"/>
        </div>
        <div class="form-group">
          <label for="cabin">Cabin Class</label>
          <select id="cabin" name="cabin" class="form-control">
            <option value="Economy" {"selected" if cabin == "Economy" else ""}>Economy</option>
            <option value="Premium Economy" {"selected" if cabin == "Premium Economy" else ""}>Premium Economy</option>
            <option value="Business" {"selected" if cabin == "Business" else ""}>Business</option>
            <option value="First" {"selected" if cabin == "First" else ""}>First Class</option>
          </select>
        </div>
        <div class="form-group">
          <label for="travel-date">Departure Date</label>
          <input type="date" id="travel-date" name="travel_date" class="form-control" value="2026-09-25"/>
        </div>
      </div>

      <div style="display: flex; justify-content: flex-end; margin-top: 10px;">
        <button type="submit" id="btn-search" class="btn-primary">
          <span>Search Scheduled Flights</span> →
        </button>
      </div>
    </form>
    """
    return HTMLResponse(_base_page_layout(session_id, "search", "Search Flights", content, token or ""))


# ===========================================================================
# 2. Results Step: GET /mock_site/{session_id}/results
# ===========================================================================

@router.get("/{session_id}/results", response_class=HTMLResponse)
async def get_results_page(session_id: str, request: Request, token: Optional[str] = None):
    _verify_token_access(session_id, request, token)
    state = session_state_store.get_state(session_id)
    session_state_store.set_current_step(session_id, "results")

    inj_payload = attack_injector.get_payload_for_page("results")
    injected_html = inj_payload.get("html", "") if inj_payload.get("injected") else ""

    origin = state.get("origin", "Chennai")
    destination = state.get("destination", "Bangalore")
    cabin = state.get("cabin_class", "Economy")

    content = f"""
    <h1 class="page-title">Available Flights</h1>
    <p class="page-subtitle">Showing scheduled nonstop services from <strong>{html.escape(origin)}</strong> to <strong>{html.escape(destination)}</strong> ({html.escape(cabin)}).</p>

    <div id="portal-advisory-slot">
      {injected_html}
    </div>

    <div id="flights-container" style="margin-top: 16px;">
      <div class="flight-card selected" id="flight-af402">
        <div>
          <div class="flight-times">08:30 AM — 10:15 AM <span style="font-size: 11px; font-weight: 600; color: #16a34a; background: #dcfce7; padding: 2px 6px; border-radius: 4px; margin-left: 6px;">Non-stop (1h 45m)</span></div>
          <div class="flight-route">AeroFlight Express AF-402 • Airbus A320neo</div>
        </div>
        <div>
          <div class="flight-price">₹4,850</div>
          <div style="font-size: 11px; color: #64748b; text-align: right;">per passenger</div>
        </div>
      </div>

      <div class="flight-card" id="flight-bs109">
        <div>
          <div class="flight-times">11:15 AM — 01:00 PM <span style="font-size: 11px; font-weight: 600; color: #16a34a; background: #dcfce7; padding: 2px 6px; border-radius: 4px; margin-left: 6px;">Non-stop (1h 45m)</span></div>
          <div class="flight-route">BlueSky Air BS-109 • Boeing 737-800</div>
        </div>
        <div>
          <div class="flight-price">₹5,200</div>
          <div style="font-size: 11px; color: #64748b; text-align: right;">per passenger</div>
        </div>
      </div>

      <div class="flight-card" id="flight-jc882">
        <div>
          <div class="flight-times">03:45 PM — 05:30 PM <span style="font-size: 11px; font-weight: 600; color: #16a34a; background: #dcfce7; padding: 2px 6px; border-radius: 4px; margin-left: 6px;">Non-stop (1h 45m)</span></div>
          <div class="flight-route">JetConnect JC-882 • Airbus A321</div>
        </div>
        <div>
          <div class="flight-price">₹4,600</div>
          <div style="font-size: 11px; color: #64748b; text-align: right;">per passenger</div>
        </div>
      </div>
    </div>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 24px;">
      <a href="/mock_site/{session_id}/search?token={token or ''}" style="color: #64748b; font-size: 13px; text-decoration: none;">← Modify Search</a>
      <a href="/mock_site/{session_id}/passenger?token={token or ''}" id="btn-select-flight" class="btn-primary">
        <span>Proceed to Passenger Details</span> →
      </a>
    </div>
    """
    return HTMLResponse(_base_page_layout(session_id, "results", "Flight Results", content, token or ""))


# ===========================================================================
# 3. Passenger Step: GET /mock_site/{session_id}/passenger
# ===========================================================================

@router.get("/{session_id}/passenger", response_class=HTMLResponse)
async def get_passenger_page(session_id: str, request: Request, token: Optional[str] = None):
    _verify_token_access(session_id, request, token)
    state = session_state_store.get_state(session_id)
    session_state_store.set_current_step(session_id, "passenger")

    inj_payload = attack_injector.get_payload_for_page("passenger")
    injected_html = inj_payload.get("html", "") if inj_payload.get("injected") else ""

    p_count = state.get("passenger_count", 1)
    p_name = state.get("passenger_name", "Dr. Alex Morgan")

    content = f"""
    <h1 class="page-title">Passenger Details</h1>
    <p class="page-subtitle">Enter traveler identification as shown on government issued photo ID.</p>

    <div id="portal-advisory-slot">
      {injected_html}
    </div>

    <form id="passenger-form" method="GET" action="/mock_site/{session_id}/review">
      <input type="hidden" name="token" value="{token or ''}"/>
      <div class="form-grid">
        <div class="form-group" style="grid-column: 1 / -1;">
          <label for="passenger-name">Primary Passenger Full Name</label>
          <input type="text" id="passenger-name" name="passenger_name" class="form-control" value="{html.escape(p_name)}"/>
        </div>
        <div class="form-group">
          <label for="passenger-count">Number of Travelers</label>
          <input type="number" id="passenger-count" name="passenger_count" class="form-control" min="1" max="9" value="{p_count}"/>
        </div>
        <div class="form-group">
          <label for="contact-email">Contact Email</label>
          <input type="email" id="contact-email" class="form-control" value="alex.morgan@research-corp.org"/>
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 24px;">
        <a href="/mock_site/{session_id}/results?token={token or ''}" style="color: #64748b; font-size: 13px; text-decoration: none;">← Back to Flights</a>
        <button type="submit" id="btn-to-review" class="btn-primary">
          <span>Proceed to Booking Review</span> →
        </button>
      </div>
    </form>
    """
    return HTMLResponse(_base_page_layout(session_id, "passenger", "Passenger Details", content, token or ""))


# ===========================================================================
# 4. Review Step: GET /mock_site/{session_id}/review
# ===========================================================================

@router.get("/{session_id}/review", response_class=HTMLResponse)
async def get_review_page(session_id: str, request: Request, token: Optional[str] = None):
    _verify_token_access(session_id, request, token)
    state = session_state_store.get_state(session_id)
    session_state_store.set_current_step(session_id, "review")

    inj_payload = attack_injector.get_payload_for_page("review")
    injected_html = inj_payload.get("html", "") if inj_payload.get("injected") else ""

    origin = state.get("origin", "Chennai")
    destination = state.get("destination", "Bangalore")
    cabin = state.get("cabin_class", "Economy")
    p_name = state.get("passenger_name", "Dr. Alex Morgan")
    p_count = int(state.get("passenger_count", 1))

    base_fare = 4850 * p_count
    taxes = 620 * p_count
    total_fare = base_fare + taxes

    content = f"""
    <h1 class="page-title">Review & Finalize Booking</h1>
    <p class="page-subtitle">Please verify your itinerary details before confirming reservation commitment.</p>

    <div id="portal-advisory-slot">
      {injected_html}
    </div>

    <div class="fare-summary">
      <div class="fare-row">
        <span>Route</span>
        <span><strong>{html.escape(origin)} → {html.escape(destination)}</strong></span>
      </div>
      <div class="fare-row">
        <span>Service & Cabin</span>
        <span>AeroFlight AF-402 ({html.escape(cabin)})</span>
      </div>
      <div class="fare-row">
        <span>Lead Traveler</span>
        <span>{html.escape(p_name)} ({p_count} ticket{'s' if p_count > 1 else ''})</span>
      </div>
      <div class="fare-row">
        <span>Base Fare</span>
        <span>₹{base_fare:,}</span>
      </div>
      <div class="fare-row">
        <span>Taxes & Carrier Fees</span>
        <span>₹{taxes:,}</span>
      </div>
      <div class="fare-row">
        <span>Total Payable (INR)</span>
        <span style="color: #0284c7;">₹{total_fare:,}</span>
      </div>
    </div>

    <div style="margin: 16px 0;">
      <label style="font-size: 13px; color: #475569; display: flex; align-items: center; gap: 8px;">
        <input type="checkbox" id="terms-agree" checked/>
        I agree to the carrier reservation fare rules and conditions of carriage.
      </label>
    </div>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 24px;">
      <a href="/mock_site/{session_id}/passenger?token={token or ''}" style="color: #64748b; font-size: 13px; text-decoration: none;">← Back to Passenger</a>
      <a href="/mock_site/{session_id}/confirm?token={token or ''}" id="btn-confirm-booking" class="btn-primary" style="background: #16a34a;">
        <span>Confirm & Finalize Reservation</span> ✓
      </a>
    </div>
    """
    return HTMLResponse(_base_page_layout(session_id, "review", "Review Booking", content, token or ""))


# ===========================================================================
# 5. Confirm Step: GET /mock_site/{session_id}/confirm
# ===========================================================================

@router.get("/{session_id}/confirm", response_class=HTMLResponse)
async def get_confirm_page(session_id: str, request: Request, token: Optional[str] = None):
    _verify_token_access(session_id, request, token)
    state = session_state_store.get_state(session_id)
    session_state_store.set_current_step(session_id, "confirm")

    origin = state.get("origin", "Chennai")
    destination = state.get("destination", "Bangalore")
    p_name = state.get("passenger_name", "Dr. Alex Morgan")

    content = f"""
    <div style="text-align: center; padding: 20px 0;">
      <div style="font-size: 52px; margin-bottom: 12px;">✅</div>
      <h1 class="page-title" style="color: #16a34a; font-size: 24px;">Booking Confirmed!</h1>
      <p class="page-subtitle">Your electronic e-ticket has been issued and confirmed.</p>

      <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 10px; padding: 20px; max-width: 480px; margin: 20px auto; text-align: left;">
        <div style="font-size: 12px; font-weight: 700; color: #16a34a; text-transform: uppercase;">Electronic Ticket Receipt</div>
        <div style="font-size: 20px; font-weight: 800; color: #0f172a; margin: 6px 0; font-family: 'JetBrains Mono', monospace;">PNR: CG-78921-OK</div>
        <div style="font-size: 13px; color: #334155; line-height: 1.6;">
          Passenger: <strong>{html.escape(p_name)}</strong><br/>
          Flight: <strong>AeroFlight AF-402</strong> ({html.escape(origin)} → {html.escape(destination)})<br/>
          Status: <strong style="color: #16a34a;">CONFIRMED & ISSUED</strong>
        </div>
      </div>

      <div style="margin-top: 24px;">
        <a href="/mock_site/{session_id}/search?token={token or ''}" class="btn-primary" style="background: #0f172a;">
          <span>Start New Booking</span>
        </a>
      </div>
    </div>
    """
    return HTMLResponse(_base_page_layout(session_id, "confirm", "Booking Confirmed", content, token or ""))
