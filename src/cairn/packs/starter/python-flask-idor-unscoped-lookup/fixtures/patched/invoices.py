from flask import Blueprint, jsonify
from flask_login import login_required, current_user

from .models import Invoice, Receipt

bp = Blueprint("billing", __name__)


@bp.get("/api/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.filter_by(id=invoice_id, owner_id=current_user.id).first_or_404()
    return jsonify(invoice.to_dict())


@bp.delete("/api/receipts/<int:receipt_id>")
@login_required
def delete_receipt(receipt_id):
    receipt = Receipt.query.filter_by(id=receipt_id, owner_id=current_user.id).first_or_404()
    receipt.delete()
    return "", 204
