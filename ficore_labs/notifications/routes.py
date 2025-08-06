from flask import Blueprint, jsonify, session, request
from flask_login import login_required, current_user
from utils import get_mongo_db, logger, requires_role, get_limiter
from translations import trans
import utils  # <-- Added import for utils

notifications = Blueprint('notifications', __name__, url_prefix='/notifications')

@notifications.route('/count', methods=['GET'])
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
@utils.limiter.limit('10 per minute')
def count():
    """Fetch the count of unread notifications for the authenticated user."""
    try:
        db = get_mongo_db()
        user_id = str(current_user.id)
        
        # Query the notifications collection for unread notifications
        unread_count = db.notifications.count_documents({
            'user_id': user_id,
            'read': False
        })
        
        logger.info(
            f"Fetched notification count for user {user_id}: {unread_count}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': user_id}
        )
        
        return jsonify({'count': unread_count})
    except Exception as e:
        logger.error(
            f"Error fetching notification count for user {user_id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': user_id}
        )
        return jsonify({'error': trans('notification_count_error', default='Error fetching notification count', lang=session.get('lang', 'en'))}), 500
