from flask import Blueprint, render_template, redirect, url_for, flash, session, request, jsonify, make_response
from flask_login import login_required, current_user
from flask_wtf.csrf import CSRFError
from translations import trans
from jinja2.exceptions import TemplateNotFound
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from models import create_feedback, get_mongo_db, get_user
from flask import current_app
import utils
from users.routes import get_post_login_redirect  # Import the redirect helper

# Use the existing limiter from utils
from utils import limiter, TRADER_TOOLS, STARTUP_TOOLS, ADMIN_TOOLS

# Exempt crawlers from rate limiting
def exempt_crawlers():
    user_agent = request.user_agent.string
    return user_agent.startswith("facebookexternalhit") or \
           user_agent.startswith("Mozilla/5.0+(compatible; UptimeRobot")

general_bp = Blueprint('general_bp', __name__, url_prefix='/general')

@general_bp.route('/landing')
@limiter.limit("500 per minute", exempt_when=exempt_crawlers)
def landing():
    """Render the public landing page."""
    if current_user.is_authenticated:
        try:
            return redirect(get_post_login_redirect(current_user.role))
        except Exception as e:
            current_app.logger.error(
                f"Error redirecting authenticated user from landing: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('general_error', default='An error occurred. Please try again.'), 'danger')
            return redirect(url_for('users.login')), 500
    try:
        current_app.logger.info(
            f"Accessing general.landing - User: {current_user.id if current_user.is_authenticated else 'anonymous'}, Authenticated: {current_user.is_authenticated}, Session: {dict(session)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        explore_features = utils.get_explore_features()
        response = make_response(render_template(
            'general/landingpage.html',
            title=trans('general_welcome', lang=session.get('lang', 'en'), default='Welcome'),
            explore_features_for_template=explore_features
        ))
        # Enable caching for unauthenticated users (public landing page)
        response.headers['Cache-Control'] = 'public, max-age=300'  # Cache for 5 minutes
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except TemplateNotFound as e:
        current_app.logger.error(
            f"Template not found: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        flash(trans('general_error', default='An error occurred'), 'danger')
        response = make_response(render_template(
            'error/404.html',
            error_message="Unable to load the landing page due to a missing template.",
            title=trans('general_welcome', lang=session.get('lang', 'en'), default='Welcome')
        ), 404)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response
    except Exception as e:
        current_app.logger.error(
            f"Error rendering landing page: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        flash(trans('general_error', default='An error occurred'), 'danger')
        response = make_response(render_template(
            'error/500.html',
            error_message="Unable to load the landing page due to an internal error.",
            title=trans('general_welcome', lang=session.get('lang', 'en'), default='Welcome')
        ), 500)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response

@general_bp.route('/home')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def home():
    """Trader homepage with trial/subscription check."""
    try:
        user = get_user(get_mongo_db(), current_user.id)
        if not user.is_trial_active():
            flash(trans('general_subscription_required', default='Your trial has expired. Please subscribe to continue.'), 'warning')
            return redirect(url_for('subscribe_bp.subscribe'))
        
        # Convert naive trial_end to timezone-aware
        if user.trial_end and user.trial_end.tzinfo is None:
            user.trial_end = user.trial_end.replace(tzinfo=ZoneInfo("UTC"))

        # Provide all variables needed by the template, with sensible defaults
        total_i_owe = getattr(user, "total_i_owe", 0) or 0
        total_i_am_owed = getattr(user, "total_i_am_owed", 0) or 0
        net_cashflow = getattr(user, "net_cashflow", 0) or 0
        total_receipts = getattr(user, "total_receipts", 0) or 0
        total_payments = getattr(user, "total_payments", 0) or 0
        tools_for_template = STARTUP_TOOLS if user.role == "startup" else TRADER_TOOLS if user.role == "trader" else ADMIN_TOOLS
        
        # Assign role-specific explore features
        if user.role == "trader":
            # Select specific trader tools for explore features
            trader_feature_keys = ["debtors_dashboard", "receipts_dashboard", "business_reports"]
            explore_features_for_template = [
                {
                    "label_key": tool["label_key"],
                    "description_key": tool["description_key"],
                    "label": tool["label"],
                    "description": tool.get("description", "Description not available"),
                    "url": tool["url"],
                    "icon": tool["icon"]
                }
                for tool in TRADER_TOOLS if tool["label_key"] in trader_feature_keys
            ]
        else:
            # Use all startup/admin tools for explore features
            tool_list = STARTUP_TOOLS if user.role == "startup" else ADMIN_TOOLS
            explore_features_for_template = [
                {
                    "label_key": tool["label_key"],
                    "description_key": tool["description_key"],
                    "label": tool["label"],
                    "description": tool.get("description", "Description not available"),
                    "url": tool["url"],
                    "icon": tool["icon"]
                }
                for tool in tool_list
            ]
        is_read_only = False

        return render_template(
            'general/home.html',
            title=trans('general_business_home', lang=session.get('lang', 'en'), default='Business Dashboard'),
            is_trial=user.is_trial,
            trial_end=user.trial_end,
            total_i_owe=total_i_owe,
            total_i_am_owed=total_i_am_owed,
            net_cashflow=net_cashflow,
            total_receipts=total_receipts,
            total_payments=total_payments,
            tools_for_template=tools_for_template,
            explore_features_for_template=explore_features_for_template,
            is_read_only=is_read_only
        )
    except Exception as e:
        current_app.logger.error(
            f"Error rendering home page for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('general_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@general_bp.route('/about')
def about():
    """Public about page."""
    try:
        return render_template(
            'general/about.html',
            title=trans('general_about', lang=session.get('lang', 'en'), default='About Us')
        )
    except TemplateNotFound as e:
        current_app.logger.error(
            f"Template not found: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        return render_template(
            'error/404.html',
            error=str(e),
            title=trans('general_about', lang=session.get('lang', 'en'), default='About Us')
        ), 404

@general_bp.route('/contact')
def contact():
    """Public contact page."""
    try:
        return render_template(
            'general/contact.html',
            title=trans('general_contact', lang=session.get('lang', 'en'), default='Contact Us')
        )
    except TemplateNotFound as e:
        current_app.logger.error(
            f"Template not found: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        return render_template(
            'error/404.html',
            error=str(e),
            title=trans('general_contact', lang=session.get('lang', 'en'), default='Contact Us')
        ), 404

@general_bp.route('/privacy')
def privacy():
    """Public privacy policy page."""
    lang = session.get('lang', 'en')
    try:
        return render_template(
            'general/privacy.html',
            title=trans('general_privacy', lang=lang, default='Privacy Policy')
        )
    except TemplateNotFound as e:
        current_app.logger.error(
            f"Template not found: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        return render_template(
            'error/404.html',
            error=str(e),
            title=trans('general_privacy', lang=lang, default='Privacy Policy')
        ), 404

@general_bp.route('/terms')
def terms():
    """Public terms of service page."""
    lang = session.get('lang', 'en')
    try:
        return render_template(
            'general/terms.html',
            title=trans('general_terms', lang=lang, default='Terms of Service')
        )
    except TemplateNotFound as e:
        current_app.logger.error(
            f"Template not found: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        return render_template(
            'error/404.html',
            error=str(e),
            title=trans('general_terms', lang=lang, default='Terms of Service')
        ), 404

@general_bp.route('/business-finance-tips')
def business_finance_tips():
    """Public business finance tips page."""
    lang = session.get('lang', 'en')
    try:
        return render_template(
            'general/business_finance_tips.html',
            title=trans('business_finance_tips_title', lang=lang, default='Business Finance Tips')
        )
    except TemplateNotFound as e:
        current_app.logger.error(
            f"Template not found: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'}
        )
        return render_template(
            'error/404.html',
            error=str(e),
            title=trans('business_finance_tips_title', lang=lang, default='Business Finance Tips')
        ), 404

@general_bp.route('/feedback', methods=['GET', 'POST'])
@utils.limiter.limit('10 per minute')
def feedback():
    """Public feedback page for core business finance features."""
    lang = session.get('lang', 'en')
    current_app.logger.info(
        'Handling feedback',
        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous', 'ip_address': request.remote_addr}
    )

    # Updated tool options to reflect only core business finance modules
    tool_options = [
        ['profile', trans('general_profile', default='Profile')],
        ['debtors', trans('debtors_dashboard', default='Debtors')],
        ['creditors', trans('creditors_dashboard', default='Creditors')],
        ['receipts', trans('receipts_dashboard', default='Receipts')],
        ['payment', trans('payments_dashboard', default='Payments')],
        ['report', trans('reports_dashboard', default='Business Reports')],
        ['fund', trans('fund_tracking', default='Fund Tracking')],
        ['investor_report', trans('investor_reports', default='Investor Reports')],
        ['forecast', trans('forecast_scenario', default='Forecast & Scenario')]
    ]

    if request.method == 'POST':
        try:
            tool_name = request.form.get('tool_name')
            rating = request.form.get('rating')
            comment = utils.sanitize_input(request.form.get('comment', '').strip(), max_length=1000)

            valid_tools = [option[0] for option in tool_options]
            
            # Validate inputs
            if not tool_name or tool_name not in valid_tools:
                current_app.logger.error(
                    f'Invalid feedback tool: {tool_name}',
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous', 'ip_address': request.remote_addr}
                )
                flash(trans('general_invalid_input', default='Please select a valid tool'), 'danger')
                return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang))
            
            if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
                current_app.logger.error(
                    f'Invalid rating: {rating}',
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous', 'ip_address': request.remote_addr}
                )
                flash(trans('general_invalid_input', default='Please provide a rating between 1 and 5'), 'danger')
                return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang))
            
            # Check trial/subscription status for authenticated users
            if current_user.is_authenticated:
                user = get_user(get_mongo_db(), current_user.id)
                if not user.is_trial_active():
                    flash(trans('general_subscription_required', default='Your trial has expired. Please subscribe to submit feedback.'), 'warning')
                    return redirect(url_for('subscribe_bp.subscribe'))
            
            # Store feedback
            with current_app.app_context():
                db = get_mongo_db()
                feedback_entry = {
                    'user_id': str(current_user.id) if current_user.is_authenticated else None,
                    'session_id': session.get('sid', 'no-session-id'),
                    'tool_name': tool_name,
                    'rating': int(rating),
                    'comment': comment or None,
                    'timestamp': datetime.now(timezone.utc)
                }
                create_feedback(db, feedback_entry)
                
                # Log audit entry
                db.audit_logs.insert_one({
                    'admin_id': 'system',
                    'action': 'submit_feedback',
                    'details': {
                        'user_id': str(current_user.id) if current_user.is_authenticated else None,
                        'tool_name': tool_name,
                        'rating': int(rating)
                    },
                    'timestamp': datetime.now(timezone.utc)
                })
            
            current_app.logger.info(
                f'Feedback submitted: tool={tool_name}, rating={rating}',
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous', 'ip_address': request.remote_addr}
            )
            flash(trans('general_thank_you', default='Thank you for your feedback!'), 'success')
            return redirect(url_for('general_bp.home'))
        
        except CSRFError as e:
            current_app.logger.error(
                f'CSRF error in feedback submission: {str(e)}',
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous', 'ip_address': request.remote_addr}
            )
            flash(trans('general_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
            return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang)), 400
        except ValueError as e:
            current_app.logger.error(
                f'Error processing feedback: {str(e)}',
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous', 'ip_address': request.remote_addr}
            )
            flash(trans('general_error', default='Error occurred during feedback submission'), 'danger')
            return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang)), 400
        except TemplateNotFound as e:
            current_app.logger.error(
                f"Template not found: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous', 'ip_address': request.remote_addr}
            )
            return render_template(
                'error/404.html',
                error=str(e),
                title=trans('general_feedback', lang=lang)
            ), 404
        except Exception as e:
            current_app.logger.error(
                f'Error processing feedback: {str(e)}',
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous', 'ip_address': request.remote_addr}
            )
            flash(trans('general_error', default='Error occurred during feedback submission'), 'danger')
            return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang)), 500
    
    # Handle GET request
    return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang))
