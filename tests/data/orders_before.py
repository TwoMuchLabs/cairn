from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from .models import Order, Address

bp = Blueprint("orders", __name__)


@bp.get("/api/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())


@bp.put("/api/addresses/<int:address_id>")
@login_required
def update_address(address_id):
    address = Address.query.get(address_id)
    address.update(request.json)
    return jsonify(address.to_dict())
