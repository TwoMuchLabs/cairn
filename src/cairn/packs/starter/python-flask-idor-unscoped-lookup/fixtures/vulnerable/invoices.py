from flask import Blueprint, jsonify
from flask_login import login_required, current_user

from .models import Invoice, Receipt

bp = Blueprint("billing", __name__)


@bp.get("/api/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    # Any logged-in user can read any invoice by guessing its ID.
    invoice = Invoice.query.get_or_404(invoice_id)  # cairn-expect
    return jsonify(invoice.to_dict())


@bp.delete("/api/receipts/<int:receipt_id>")
@login_required
def delete_receipt(receipt_id):
    receipt = Receipt.query.get(receipt_id)  # cairn-expect
    receipt.delete()
    return "", 204
