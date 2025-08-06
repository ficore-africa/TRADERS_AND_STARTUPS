from flask import Blueprint, render_template, flash, session
from flask_login import login_required, current_user
from translations import trans
import utils
from utils import format_date
from bson import ObjectId
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import logging

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

@dashboard_bp.route('/')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def index():
    """Display the user's dashboard with recent activity and role-specific content."""
    # Initialize data containers with defaults
    recent_creditors = []
    recent_debtors = []
    recent_payments = []
    recent_receipts = []
    recent_funds = []
    stats = {
        'total_debtors': 0,
        'total_creditors': 0,
        'total_payments': 0,
        'total_receipts': 0,
        'total_funds': 0,
        'total_debtors_amount': 0,
        'total_creditors_amount': 0,
        'total_payments_amount': 0,
        'total_receipts_amount': 0,
        'total_funds_amount': 0,
        'total_forecasts': 0,  # Added for forecasts count
        'total_forecasts_amount': 0  # Added for forecasts amount
    }
    can_interact = False

    try:
        db = utils.get_mongo_db()
        query = {'user_id': str(current_user.id)}

        # Fetch recent data with error handling
        try:
            recent_creditors = list(db.records.find({**query, 'type': 'creditor'}).sort('created_at', -1).limit(5))
            recent_debtors = list(db.records.find({**query, 'type': 'debtor'}).sort('created_at', -1).limit(5))
            recent_payments = list(db.cashflows.find({**query, 'type': 'payment'}).sort('created_at', -1).limit(5))
            recent_receipts = list(db.cashflows.find({**query, 'type': 'receipt'}).sort('created_at', -1).limit(5))
            recent_funds = list(db.records.find({**query, 'type': 'fund'}).sort('created_at', -1).limit(5))  # Updated to use records collection
        except Exception as e:
            logger.error(f"Error querying MongoDB for dashboard data: {str(e)}", 
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('dashboard_load_error', default='Failed to load some dashboard data. Displaying available information.'), 'warning')

        # Sanitize and convert datetimes
        for item in recent_creditors + recent_debtors:
            try:
                if item.get('created_at') and item['created_at'].tzinfo is None:
                    item['created_at'] = item['created_at'].replace(tzinfo=ZoneInfo("UTC"))
                if item.get('reminder_date') and item['reminder_date'].tzinfo is None:
                    item['reminder_date'] = item['reminder_date'].replace(tzinfo=ZoneInfo("UTC"))
                item['name'] = utils.sanitize_input(item.get('name', ''), max_length=100)
                item['description'] = utils.sanitize_input(item.get('description', 'No description provided'), max_length=500)
                item['contact'] = utils.sanitize_input(item.get('contact', 'N/A'), max_length=50)
                item['_id'] = str(item['_id'])
            except Exception as e:
                logger.warning(f"Error processing creditor/debtor item {item.get('_id')}: {str(e)}")
                continue

        for item in recent_payments + recent_receipts:
            try:
                if item.get('created_at') and item['created_at'].tzinfo is None:
                    item['created_at'] = item['created_at'].replace(tzinfo=ZoneInfo("UTC"))
                item['description'] = utils.sanitize_input(item.get('description', 'No description provided'), max_length=500)
                item['_id'] = str(item['_id'])
            except Exception as e:
                logger.warning(f"Error processing payment/receipt item {item.get('_id')}: {str(e)}")
                continue

        for item in recent_funds:
            try:
                if item.get('created_at') and item['created_at'].tzinfo is None:
                    item['created_at'] = item['created_at'].replace(tzinfo=ZoneInfo("UTC"))
                item['name'] = utils.sanitize_input(item.get('name', ''), max_length=100)
                item['description'] = utils.sanitize_input(item.get('description', 'No description provided'), max_length=500)
                item['_id'] = str(item['_id'])
            except Exception as e:
                logger.warning(f"Error processing fund item {item.get('_id')}: {str(e)}")
                continue

        # Calculate stats with safe access
        try:
            stats.update({
                'total_debtors': db.records.count_documents({**query, 'type': 'debtor'}),
                'total_creditors': db.records.count_documents({**query, 'type': 'creditor'}),
                'total_payments': db.cashflows.count_documents({**query, 'type': 'payment'}),
                'total_receipts': db.cashflows.count_documents({**query, 'type': 'receipt'}),
                'total_funds': db.records.count_documents({**query, 'type': 'fund'}),
                'total_debtors_amount': sum(doc.get('amount_owed', 0) for doc in db.records.find({**query, 'type': 'debtor'})),
                'total_creditors_amount': sum(doc.get('amount_owed', 0) for doc in db.records.find({**query, 'type': 'creditor'})),
                'total_payments_amount': sum(doc.get('amount', 0) for doc in db.cashflows.find({**query, 'type': 'payment'})),
                'total_receipts_amount': sum(doc.get('amount', 0) for doc in db.cashflows.find({**query, 'type': 'receipt'})),
                'total_funds_amount': sum(doc.get('amount', 0) for doc in db.records.find({**query, 'type': 'fund'})),
                'total_forecasts': db.records.count_documents({**query, 'type': 'forecast'}),
                'total_forecasts_amount': sum(doc.get('projected_revenue', 0) for doc in db.records.find({**query, 'type': 'forecast'}))
            })
        except Exception as e:
            logger.error(f"Error calculating stats for dashboard: {str(e)}", 
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('dashboard_stats_error', default='Unable to calculate dashboard statistics. Displaying defaults.'), 'warning')

        # Check subscription status
        try:
            can_interact = utils.can_user_interact(current_user)
        except Exception as e:
            logger.error(f"Error checking user interaction status: {str(e)}", 
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('interaction_check_error', default='Unable to verify interaction status.'), 'warning')

        # Render dashboard with available data
        return render_template(
            'dashboard/index.html',
            recent_creditors=recent_creditors,
            recent_debtors=recent_debtors,
            recent_payments=recent_payments,
            recent_receipts=recent_receipts,
            recent_funds=recent_funds,
            stats=stats,
            can_interact=can_interact
        )

    except Exception as e:
        # Fallback for critical errors
        logger.critical(f"Critical error in dashboard route: {str(e)}", 
                       extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('dashboard_critical_error', default='An error occurred while loading the dashboard. Please try again later.'), 'danger')
        return render_template('dashboard/index.html', 
                             recent_creditors=[], recent_debtors=[], recent_payments=[], 
                             recent_receipts=[], recent_funds=[], stats=stats, can_interact=False)
