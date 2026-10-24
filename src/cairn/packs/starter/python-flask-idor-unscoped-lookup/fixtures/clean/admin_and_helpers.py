from flask import Blueprint, jsonify
from flask_login import login_required

from .auth import admin_required
from .models import Invoice, Plan

bp = Blueprint("admin", __name__)


@bp.get("/admin/invoices/<int:invoice_id>")
@login_required
@admin_required
def admin_get_invoice(invoice_id):
    # Admin-only route: unscoped lookup is intended.
    invoice = Invoice.query.get_or_404(invoice_id)
    return jsonify(invoice.to_dict())


@bp.get("/api/plans/<slug>")
def public_plan(slug):
    # Public catalogue, no ownership.
    plan = Plan.query.filter_by(slug=slug).first_or_404()
    return jsonify(plan.to_dict())


def load_invoice_for_job(invoice_id):
    # Not a request handler; called by a background worker.
    return Invoice.query.get(invoice_id)
