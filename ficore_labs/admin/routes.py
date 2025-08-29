import logging
from bson import ObjectId, errors
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, Response, send_file
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, SelectField, SubmitField, DateField, validators
from wtforms.validators import DataRequired, NumberRange
from translations import trans
import utils
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from io import BytesIO
import csv
from models import get_records, get_cashflows, get_feedback, to_dict_feedback, get_waitlist_entries, to_dict_waitlist

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, template_folder='templates/admin')

# Error Handler
@admin_bp.app_errorhandler(500)
def error_500(error):
    """Handle 500 Internal Server Error."""
    logger.error(f"500 Internal Server Error: {str(error)}",
                 extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id if current_user.is_authenticated else 'anonymous'})
    flash(trans('admin_server_error', default='An unexpected error occurred. Please try again later.'), 'danger')
    return render_template('error/500.html'), 500

# Form Definitions
class RoleForm(FlaskForm):
    role = SelectField(trans('user_role', default='Role'), choices=[('trader', 'Trader'), ('startup', 'Startup'), ('admin', 'Admin')], validators=[DataRequired()], render_kw={'class': 'form-select'})
    submit = SubmitField(trans('user_update_role', default='Update Role'), render_kw={'class': 'btn btn-primary'})

class SubscriptionForm(FlaskForm):
    is_subscribed = SelectField(trans('subscription_status', default='Subscription Status'), choices=[('True', 'Subscribed'), ('False', 'Not Subscribed')], validators=[DataRequired()], render_kw={'class': 'form-select'})
    subscription_plan = SelectField(trans('subscription_plan', default='Subscription Plan'), choices=[('', 'None'), ('monthly', 'Monthly (₦1k)'), ('yearly', 'Yearly (₦10k)')], render_kw={'class': 'form-select'})
    subscription_end = DateField(trans('subscription_end', default='Subscription End Date'), format='%Y-%m-%d', validators=[validators.Optional()], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('subscription_update', default='Update Subscription'), render_kw={'class': 'btn btn-primary'})

class TrialForm(FlaskForm):
    is_trial = SelectField(trans('trial_status', default='Trial Status'), choices=[('True', 'Active Trial'), ('False', 'No Trial')], validators=[DataRequired()], render_kw={'class': 'form-select'})
    trial_end = DateField(trans('trial_end', default='Trial End Date'), format='%Y-%m-%d', validators=[validators.Optional()], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('trial_update', default='Update Trial'), render_kw={'class': 'btn btn-primary'})
    bulk_trial_days = SelectField(trans('bulk_trial_days', default='Extend Trial for New Users'), choices=[('', 'Select Days'), ('30', '30 Days'), ('60', '60 Days'), ('90', '90 Days')], validators=[validators.Optional()], render_kw={'class': 'form-select'})
    bulk_trial_start = DateField(trans('bulk_trial_start', default='Registration Start Date'), format='%Y-%m-%d', validators=[validators.Optional()], render_kw={'class': 'form-control'})
    bulk_trial_end = DateField(trans('bulk_trial_end', default='Registration End Date'), format='%Y-%m-%d', validators=[validators.Optional()], render_kw={'class': 'form-control'})
    bulk_submit = SubmitField(trans('bulk_trial_update', default='Apply Bulk Trial'), render_kw={'class': 'btn btn-primary'})

class DebtorForm(FlaskForm):
    name = StringField(trans('debtor_name', default='Debtor Name'), validators=[DataRequired(), validators.Length(min=2, max=100)], render_kw={'class': 'form-control'})
    amount = FloatField(trans('debtor_amount', default='Amount Owed'), validators=[DataRequired(), NumberRange(min=0)], render_kw={'class': 'form-control'})
    due_date = DateField(trans('debtor_due_date', default='Due Date'), validators=[DataRequired()], format='%Y-%m-%d', render_kw={'class': 'form-control'})
    submit = SubmitField(trans('debtor_add', default='Add Debtor'), render_kw={'class': 'btn btn-primary'})

class CreditorForm(FlaskForm):
    name = StringField(trans('creditor_name', default='Creditor Name'), validators=[DataRequired(), validators.Length(min=2, max=100)], render_kw={'class': 'form-control'})
    amount = FloatField(trans('creditor_amount', default='Amount Owed'), validators=[DataRequired(), NumberRange(min=0)], render_kw={'class': 'form-control'})
    due_date = DateField(trans('creditor_due_date', default='Due Date'), validators=[DataRequired()], format='%Y-%m-%d', render_kw={'class': 'form-control'})
    submit = SubmitField(trans('creditor_add', default='Add Creditor'), render_kw={'class': 'btn btn-primary'})

class FundForm(FlaskForm):
    source = StringField(trans('fund_source', default='Funding Source'), validators=[DataRequired(), validators.Length(min=2, max=100)], render_kw={'class': 'form-control'})
    amount = FloatField(trans('fund_amount', default='Amount'), validators=[DataRequired(), NumberRange(min=0)], render_kw={'class': 'form-control'})
    received_date = DateField(trans('fund_received_date', default='Received Date'), validators=[DataRequired()], format='%Y-%m-%d', render_kw={'class': 'form-control'})
    submit = SubmitField(trans('fund_add', default='Add Fund'), render_kw={'class': 'btn btn-primary'})

class FeedbackFilterForm(FlaskForm):
    tool_name = SelectField(trans('general_select_tool', default='Select Tool'), 
                           choices=[('', trans('general_all_tools', default='All Tools')),
                                    ('profile', trans('general_profile', default='Profile')),
                                    ('debtors', trans('debtors_dashboard', default='Debtors')),
                                    ('creditors', trans('creditors_dashboard', default='Creditors')),
                                    ('receipts', trans('receipts_dashboard', default='Receipts')),
                                    ('payment', trans('payments_dashboard', default='Payments')),
                                    ('report', trans('reports_dashboard', default='Business Reports')),
                                    ('fund', trans('fund_tracking', default='Fund Tracking')),
                                    ('investor_report', trans('investor_reports', default='Investor Reports')),
                                    ('forecast', trans('forecast_scenario', default='Forecast & Scenario'))],
                           validators=[validators.Optional()], render_kw={'class': 'form-select'})
    user_id = StringField(trans('admin_user_id', default='User ID'), validators=[validators.Optional()], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('general_filter', default='Filter'), render_kw={'class': 'btn btn-primary'})

# Helper Functions
def log_audit_action(action, details=None):
    """Log an admin action to audit_logs collection."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        db.audit_logs.insert_one({
            'admin_id': str(current_user.id),
            'action': action,
            'details': details or {},
            'timestamp': datetime.now(timezone.utc)
        })
    except Exception as e:
        logger.error(f"Error logging audit action '{action}': {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})

# Routes
@admin_bp.route('/dashboard', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def dashboard():
    """Admin dashboard with system statistics."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        stats = {
            'users': db.users.count_documents({}),
            'records': db.records.count_documents({}),
            'cashflows': db.cashflows.count_documents({}),
            'debtors': db.debtors.count_documents({}),
            'creditors': db.creditors.count_documents({}),
            'funds': db.funds.count_documents({}),
            'audit_logs': db.audit_logs.count_documents({}),
            'feedback': db.feedback.count_documents({})
        }
        recent_users = list(db.users.find().sort('created_at', -1).limit(5))
        for user in recent_users:
            user['_id'] = str(user['_id'])
            trial_end = user.get('trial_end')
            subscription_end = user.get('subscription_end')
            trial_end_aware = trial_end.replace(tzinfo=ZoneInfo("UTC")) if trial_end and trial_end.tzinfo is None else trial_end
            subscription_end_aware = subscription_end.replace(tzinfo=ZoneInfo("UTC")) if subscription_end and subscription_end.tzinfo is None else subscription_end
            user['is_trial_active'] = (
                datetime.now(timezone.utc) <= trial_end_aware if user.get('is_trial') and trial_end_aware
                else user.get('is_subscribed') and subscription_end_aware and datetime.now(timezone.utc) <= subscription_end_aware
            )
        logger.info(f"Admin {current_user.id} accessed dashboard",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return render_template(
            'admin/dashboard.html',
            stats=stats,
            recent_users=recent_users,
            title=trans('admin_dashboard', default='Admin Dashboard')
        )
    except Exception as e:
        logger.error(f"Error loading admin dashboard for user {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_dashboard_error', default='An error occurred while loading the dashboard'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/users', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_users():
    """View and manage users."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        users = list(db.users.find({} if utils.is_admin() else {'role': {'$ne': 'admin'}}).sort('created_at', -1))
        for user in users:
            user['_id'] = str(user['_id'])
            user['username'] = user['_id']
            trial_end = user.get('trial_end')
            subscription_end = user.get('subscription_end')
            trial_end_aware = trial_end.replace(tzinfo=ZoneInfo("UTC")) if trial_end and trial_end.tzinfo is None else trial_end
            subscription_end_aware = subscription_end.replace(tzinfo=ZoneInfo("UTC")) if subscription_end and subscription_end.tzinfo is None else subscription_end
            user['is_trial_active'] = (
                datetime.now(timezone.utc) <= trial_end_aware if user.get('is_trial') and trial_end_aware
                else user.get('is_subscribed') and subscription_end_aware and datetime.now(timezone.utc) <= subscription_end_aware
            )
        return render_template('admin/users.html', users=users, title=trans('admin_manage_users_title', default='Manage Users'))
    except Exception as e:
        logger.error(f"Error fetching users for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/users/suspend/<user_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("10 per hour")
def suspend_user(user_id):
    """Suspend a user account."""
    try:
        ObjectId(user_id)
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        user_query = {'_id': ObjectId(user_id)}
        user = db.users.find_one(user_query)
        if user is None:
            flash(trans('admin_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('admin.manage_users'))
        result = db.users.update_one(
            user_query,
            {'$set': {'suspended': True, 'updated_at': datetime.now(timezone.utc)}}
        )
        if result.modified_count == 0:
            flash(trans('admin_user_not_updated', default='User could not be suspended'), 'danger')
        else:
            flash(trans('admin_user_suspended', default='User suspended successfully'), 'success')
            logger.info(f"Admin {current_user.id} suspended user {user_id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('suspend_user', {'user_id': user_id})
        return redirect(url_for('admin.manage_users'))
    except errors.InvalidId:
        logger.error(f"Invalid user_id format: {user_id}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_invalid_user_id', default='Invalid user ID'), 'danger')
        return redirect(url_for('admin.manage_users'))
    except Exception as e:
        logger.error(f"Error suspending user {user_id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/users/delete/<user_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("5 per hour")
def delete_user(user_id):
    """Delete a user and their data."""
    try:
        ObjectId(user_id)
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        user_query = {'_id': ObjectId(user_id)}
        user = db.users.find_one(user_query)
        if user is None:
            flash(trans('admin_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('admin.manage_users'))
        db.records.delete_many({'user_id': user_id})
        db.cashflows.delete_many({'user_id': user_id})
        db.debtors.delete_many({'user_id': user_id})
        db.creditors.delete_many({'user_id': user_id})
        db.funds.delete_many({'user_id': user_id})
        db.feedback.delete_many({'user_id': user_id})
        db.audit_logs.delete_many({'details.user_id': user_id})
        result = db.users.delete_one(user_query)
        if result.deleted_count == 0:
            flash(trans('admin_user_not_deleted', default='User could not be deleted'), 'danger')
        else:
            flash(trans('admin_user_deleted', default='User deleted successfully'), 'success')
            logger.info(f"Admin {current_user.id} deleted user {user_id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('delete_user', {'user_id': user_id})
        return redirect(url_for('admin.manage_users'))
    except errors.InvalidId:
        logger.error(f"Invalid user_id format: {user_id}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_invalid_user_id', default='Invalid user ID'), 'danger')
        return redirect(url_for('admin.manage_users'))
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/data/delete/<collection>/<item_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("10 per hour")
def delete_item(collection, item_id):
    """Delete an item from a collection."""
    valid_collections = ['records', 'cashflows', 'debtors', 'creditors', 'funds']
    if collection not in valid_collections:
        flash(trans('admin_invalid_collection', default='Invalid collection selected'), 'danger')
        return redirect(url_for('admin.dashboard'))
    try:
        ObjectId(item_id)
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        result = db[collection].delete_one({'_id': ObjectId(item_id)})
        if result.deleted_count == 0:
            flash(trans('admin_item_not_found', default='Item not found'), 'danger')
        else:
            flash(trans('admin_item_deleted', default='Item deleted successfully'), 'success')
            logger.info(f"Admin {current_user.id} deleted {collection} item {item_id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action(f'delete_{collection}_item', {'item_id': item_id, 'collection': collection})
        return redirect(url_for(f'admin.{collection}'))
    except errors.InvalidId:
        logger.error(f"Invalid item_id format for collection {collection}: {item_id}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_invalid_item_id', default='Invalid item ID'), 'danger')
        return redirect(url_for('admin.dashboard'))
    except Exception as e:
        logger.error(f"Error deleting {collection} item {item_id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/users/roles', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_user_roles():
    """Manage user roles: list all users and update their roles."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        users = list(db.users.find())
        form = RoleForm()
        if request.method == 'POST' and form.validate_on_submit():
            user_id = request.form.get('user_id')
            try:
                ObjectId(user_id)
                user = db.users.find_one({'_id': ObjectId(user_id)})
                if user is None:
                    flash(trans('user_not_found', default='User not found'), 'danger')
                    return redirect(url_for('admin.manage_user_roles'))
                new_role = form.role.data
                db.users.update_one(
                    {'_id': ObjectId(user_id)},
                    {'$set': {'role': new_role, 'updated_at': datetime.now(timezone.utc)}}
                )
                logger.info(f"User role updated: id={user_id}, new_role={new_role}, admin={current_user.id}",
                            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                log_audit_action('update_user_role', {'user_id': user_id, 'new_role': new_role})
                flash(trans('user_role_updated', default='User role updated successfully'), 'success')
                return redirect(url_for('admin.manage_user_roles'))
            except errors.InvalidId:
                logger.error(f"Invalid user_id format: {user_id}",
                             extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                flash(trans('admin_invalid_user_id', default='Invalid user ID'), 'danger')
                return redirect(url_for('admin.manage_user_roles'))
            except Exception as e:
                logger.error(f"Error updating user role {user_id}: {str(e)}",
                             extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
                return render_template('admin/user_roles.html', form=form, users=users, title=trans('admin_manage_user_roles_title', default='Manage User Roles'))
        
        for user in users:
            user['_id'] = str(user['_id'])
            trial_end = user.get('trial_end')
            subscription_end = user.get('subscription_end')
            trial_end_aware = trial_end.replace(tzinfo=ZoneInfo("UTC")) if trial_end and trial_end.tzinfo is None else trial_end
            subscription_end_aware = subscription_end.replace(tzinfo=ZoneInfo("UTC")) if subscription_end and subscription_end.tzinfo is None else subscription_end
            user['is_trial_active'] = (
                datetime.now(timezone.utc) <= trial_end_aware if user.get('is_trial') and trial_end_aware
                else user.get('is_subscribed') and subscription_end_aware and datetime.now(timezone.utc) <= subscription_end_aware
            )
        return render_template('admin/user_roles.html', form=form, users=users, title=trans('admin_manage_user_roles_title', default='Manage User Roles'))
    except Exception as e:
        logger.error(f"Error in manage_user_roles for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/users/subscriptions', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_user_subscriptions():
    """Manage user subscriptions: list all users and update their subscription status."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        users = list(db.users.find())
        form = SubscriptionForm()
        if request.method == 'POST' and form.validate_on_submit():
            user_id = request.form.get('user_id')
            try:
                ObjectId(user_id)
                user = db.users.find_one({'_id': ObjectId(user_id)})
                if user is None:
                    flash(trans('user_not_found', default='User not found'), 'danger')
                    return redirect(url_for('admin.manage_user_subscriptions'))
                plan_durations = {'monthly': 30, 'yearly': 365}
                update_data = {
                    'is_subscribed': form.is_subscribed.data == 'True',
                    'subscription_plan': form.subscription_plan.data or None,
                    'subscription_start': datetime.now(timezone.utc) if form.is_subscribed.data == 'True' else None,
                    'subscription_end': form.subscription_end.data if form.subscription_end.data else None,
                    'updated_at': datetime.now(timezone.utc)
                }
                if form.is_subscribed.data == 'True' and not form.subscription_end.data and form.subscription_plan.data:
                    duration = plan_durations.get(form.subscription_plan.data, 30)
                    update_data['subscription_end'] = datetime.now(timezone.utc) + timedelta(days=duration)
                db.users.update_one(
                    {'_id': ObjectId(user_id)},
                    {'$set': update_data}
                )
                logger.info(f"User subscription updated: id={user_id}, subscribed={update_data['is_subscribed']}, plan={update_data['subscription_plan']}, admin={current_user.id}",
                            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                log_audit_action('update_user_subscription', {
                    'user_id': user_id,
                    'is_subscribed': update_data['is_subscribed'],
                    'subscription_plan': update_data['subscription_plan'],
                    'subscription_end': update_data['subscription_end'].strftime('%Y-%m-%d') if update_data['subscription_end'] else None
                })
                flash(trans('subscription_updated', default='User subscription updated successfully'), 'success')
                return redirect(url_for('admin.manage_user_subscriptions'))
            except errors.InvalidId:
                logger.error(f"Invalid user_id format: {user_id}",
                             extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                flash(trans('admin_invalid_user_id', default='Invalid user ID'), 'danger')
                return redirect(url_for('admin.manage_user_subscriptions'))
            except Exception as e:
                logger.error(f"Error updating user subscription {user_id}: {str(e)}",
                             extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
                return render_template('admin/user_subscriptions.html', form=form, users=users, title=trans('admin_manage_user_subscriptions_title', default='Manage User Subscriptions'))
        
        for user in users:
            user['_id'] = str(user['_id'])
            trial_end = user.get('trial_end')
            subscription_end = user.get('subscription_end')
            trial_end_aware = trial_end.replace(tzinfo=ZoneInfo("UTC")) if trial_end and trial_end.tzinfo is None else trial_end
            subscription_end_aware = subscription_end.replace(tzinfo=ZoneInfo("UTC")) if subscription_end and subscription_end.tzinfo is None else subscription_end
            user['is_trial_active'] = (
                datetime.now(timezone.utc) <= trial_end_aware if user.get('is_trial') and trial_end_aware
                else user.get('is_subscribed') and subscription_end_aware and datetime.now(timezone.utc) <= subscription_end_aware
            )
        return render_template('admin/user_subscriptions.html', form=form, users=users, title=trans('admin_manage_user_subscriptions_title', default='Manage User Subscriptions'))
    except Exception as e:
        logger.error(f"Error in manage_user_subscriptions for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/users/trials', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_user_trials():
    """Manage user trials: list all users and update their trial status, including bulk updates."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        users = list(db.users.find())
        form = TrialForm()
        if request.method == 'POST' and form.validate_on_submit():
            # Handle individual trial update
            user_id = request.form.get('user_id')
            if user_id:
                try:
                    ObjectId(user_id)
                    user = db.users.find_one({'_id': ObjectId(user_id)})
                    if user is None:
                        flash(trans('user_not_found', default='User not found'), 'danger')
                        return redirect(url_for('admin.manage_user_trials'))
                    update_data = {
                        'is_trial': form.is_trial.data == 'True',
                        'trial_end': form.trial_end.data if form.trial_end.data else None,
                        'updated_at': datetime.now(timezone.utc)
                    }
                    if form.is_trial.data == 'True' and not form.trial_end.data:
                        update_data['trial_end'] = datetime.now(timezone.utc) + timedelta(days=30)
                    db.users.update_one(
                        {'_id': ObjectId(user_id)},
                        {'$set': update_data}
                    )
                    logger.info(f"User trial updated: id={user_id}, is_trial={update_data['is_trial']}, trial_end={update_data['trial_end']}, admin={current_user.id}",
                                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                    log_audit_action('update_user_trial', {
                        'user_id': user_id,
                        'is_trial': update_data['is_trial'],
                        'trial_end': update_data['trial_end'].strftime('%Y-%m-%d') if update_data['trial_end'] else None
                    })
                    flash(trans('trial_updated', default='User trial updated successfully'), 'success')
                    return redirect(url_for('admin.manage_user_trials'))
                except errors.InvalidId:
                    logger.error(f"Invalid user_id format: {user_id}",
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                    flash(trans('admin_invalid_user_id', default='Invalid user ID'), 'danger')
                    return redirect(url_for('admin.manage_user_trials'))
                except Exception as e:
                    logger.error(f"Error updating user trial {user_id}: {str(e)}",
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                    flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
                    return render_template('admin/user_trials.html', form=form, users=users, title=trans('admin_manage_user_trials_title', default='Manage User Trials'))
            
            # Handle bulk trial update
            if form.bulk_trial_days.data and form.bulk_trial_start.data and form.bulk_trial_end.data:
                try:
                    days = int(form.bulk_trial_days.data)
                    start_date = form.bulk_trial_start.data
                    end_date = form.bulk_trial_end.data
                    if start_date > end_date:
                        flash(trans('admin_invalid_date_range', default='Start date must be before end date'), 'danger')
                        return redirect(url_for('admin.manage_user_trials'))
                    start_date_aware = datetime.combine(start_date, datetime.min.time(), tzinfo=ZoneInfo("UTC"))
                    end_date_aware = datetime.combine(end_date, datetime.max.time(), tzinfo=ZoneInfo("UTC"))
                    trial_end = datetime.now(timezone.utc) + timedelta(days=days)
                    query = {
                        'created_at': {'$gte': start_date_aware, '$lte': end_date_aware},
                        'role': {'$in': ['trader', 'startup']}
                    }
                    update_data = {
                        'is_trial': True,
                        'trial_end': trial_end,
                        'updated_at': datetime.now(timezone.utc)
                    }
                    result = db.users.update_many(query, {'$set': update_data})
                    updated_count = result.modified_count
                    logger.info(f"Bulk trial update: {updated_count} users updated, days={days}, start={start_date}, end={end_date}, admin={current_user.id}",
                                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                    log_audit_action('bulk_trial_update', {
                        'updated_count': updated_count,
                        'trial_days': days,
                        'registration_start': start_date.strftime('%Y-%m-%d'),
                        'registration_end': end_date.strftime('%Y-%m-%d'),
                        'trial_end': trial_end.strftime('%Y-%m-%d')
                    })
                    flash(trans('bulk_trial_updated', default=f'Successfully updated trial for {updated_count} users'), 'success')
                    return redirect(url_for('admin.manage_user_trials'))
                except Exception as e:
                    logger.error(f"Error in bulk trial update: {str(e)}",
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
                    flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
                    return render_template('admin/user_trials.html', form=form, users=users, title=trans('admin_manage_user_trials_title', default='Manage User Trials'))
        
        for user in users:
            user['_id'] = str(user['_id'])
            trial_end = user.get('trial_end')
            subscription_end = user.get('subscription_end')
            trial_end_aware = trial_end.replace(tzinfo=ZoneInfo("UTC")) if trial_end and trial_end.tzinfo is None else trial_end
            subscription_end_aware = subscription_end.replace(tzinfo=ZoneInfo("UTC")) if subscription_end and subscription_end.tzinfo is None else subscription_end
            user['is_trial_active'] = (
                datetime.now(timezone.utc) <= trial_end_aware if user.get('is_trial') and trial_end_aware
                else user.get('is_subscribed') and subscription_end_aware and datetime.now(timezone.utc) <= subscription_end_aware
            )
        return render_template('admin/user_trials.html', form=form, users=users, title=trans('admin_manage_user_trials_title', default='Manage User Trials'))
    except Exception as e:
        logger.error(f"Error in manage_user_trials for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/audit', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def audit():
    """View audit logs of admin actions."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        logs = list(db.audit_logs.find().sort('timestamp', -1).limit(100))
        for log in logs:
            log['_id'] = str(log['_id'])
        return render_template('admin/audit.html', logs=logs, title=trans('admin_audit_title', default='Audit Logs'))
    except Exception as e:
        logger.error(f"Error fetching audit logs for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/feedback', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_feedback():
    """View and filter user feedback."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        form = FeedbackFilterForm()
        filter_kwargs = {}
        
        if request.method == 'POST' and form.validate_on_submit():
            if form.tool_name.data:
                filter_kwargs['tool_name'] = form.tool_name.data
            if form.user_id.data:
                filter_kwargs['user_id'] = utils.sanitize_input(form.user_id.data, max_length=50)
        
        feedback_list = [to_dict_feedback(fb) for fb in get_feedback(db, filter_kwargs)]
        for feedback in feedback_list:
            feedback['id'] = str(feedback['id'])
            feedback['timestamp'] = (
                feedback['timestamp'].astimezone(ZoneInfo("UTC")).strftime('%Y-%m-%d %H:%M:%S')
                if feedback['timestamp'] and feedback['timestamp'].tzinfo
                else feedback['timestamp'].replace(tzinfo=ZoneInfo("UTC")).strftime('%Y-%m-%d %H:%M:%S')
                if feedback['timestamp']
                else ''
            )
        
        return render_template(
            'admin/feedback.html',
            form=form,
            feedback_list=feedback_list,
            title=trans('admin_feedback_title', default='Manage Feedback')
        )
    except Exception as e:
        logger.error(f"Error fetching feedback for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/debtors', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_debtors():
    """Manage debtors: list all and add new ones."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        form = DebtorForm()
        if request.method == 'POST' and form.validate_on_submit():
            debtor = {
                'name': utils.sanitize_input(form.name.data, max_length=100),
                'amount': utils.clean_currency(form.amount.data),
                'due_date': form.due_date.data,
                'created_by': current_user.id,
                'created_at': datetime.now(timezone.utc)
            }
            result = db.debtors.insert_one(debtor)
            debtor_id = str(result.inserted_id)
            logger.info(f"Debtor added: id={debtor_id}, name={debtor['name']}, admin={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('add_debtor', {'debtor_id': debtor_id, 'name': debtor['name']})
            flash(trans('debtor_added', default='Debtor added successfully'), 'success')
            return redirect(url_for('admin.manage_debtors'))
        
        debtors = list(db.debtors.find().sort('created_at', -1))
        for debtor in debtors:
            debtor['_id'] = str(debtor['_id'])
        return render_template('admin/debtors.html', form=form, debtors=debtors, title=trans('admin_debtors_title', default='Manage Debtors'))
    except Exception as e:
        logger.error(f"Error in manage_debtors for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/creditors', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_creditors():
    """Manage creditors: list all and add new ones."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        form = CreditorForm()
        if request.method == 'POST' and form.validate_on_submit():
            creditor = {
                'name': utils.sanitize_input(form.name.data, max_length=100),
                'amount': utils.clean_currency(form.amount.data),
                'due_date': form.due_date.data,
                'created_by': current_user.id,
                'created_at': datetime.now(timezone.utc)
            }
            result = db.creditors.insert_one(creditor)
            creditor_id = str(result.inserted_id)
            logger.info(f"Creditor added: id={creditor_id}, name={creditor['name']}, admin={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('add_creditor', {'creditor_id': creditor_id, 'name': creditor['name']})
            flash(trans('creditor_added', default='Creditor added successfully'), 'success')
            return redirect(url_for('admin.manage_creditors'))
        
        creditors = list(db.creditors.find().sort('created_at', -1))
        for creditor in creditors:
            creditor['_id'] = str(creditor['_id'])
        return render_template('admin/creditors.html', form=form, creditors=creditors, title=trans('admin_creditors_title', default='Manage Creditors'))
    except Exception as e:
        logger.error(f"Error in manage_creditors for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/records', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_records():
    """View all income/receipt records."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        records = list(get_records(db, {}).sort('created_at', -1))
        for record in records:
            record['_id'] = str(record['_id'])
        return render_template('admin/records.html', records=records, title=trans('admin_records_title', default='Manage Income Records'))
    except Exception as e:
        logger.error(f"Error fetching records for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/cashflows', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_cashflows():
    """View all payment outflow records."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        cashflows = list(get_cashflows(db, {}).sort('created_at', -1))
        for cashflow in cashflows:
            cashflow['_id'] = str(cashflow['_id'])
        return render_template('admin/cashflows.html', cashflows=cashflows, title=trans('admin_cashflows_title', default='Manage Payment Outflows'))
    except Exception as e:
        logger.error(f"Error fetching cashflows for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/funds', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_funds():
    """Manage funding records: list all and add new ones."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        form = FundForm()
        if request.method == 'POST' and form.validate_on_submit():
            fund = {
                'source': utils.sanitize_input(form.source.data, max_length=100),
                'amount': utils.clean_currency(form.amount.data),
                'received_date': form.received_date.data,
                'created_by': current_user.id,
                'created_at': datetime.now(timezone.utc)
            }
            result = db.funds.insert_one(fund)
            fund_id = str(result.inserted_id)
            logger.info(f"Fund added: id={fund_id}, source={fund['source']}, admin={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('add_fund', {'fund_id': fund_id, 'source': fund['source']})
            flash(trans('fund_added', default='Fund added successfully'), 'success')
            return redirect(url_for('admin.manage_funds'))
        
        funds = list(db.funds.find().sort('created_at', -1))
        for fund in funds:
            fund['_id'] = str(fund['_id'])
        return render_template('admin/funds.html', form=form, funds=funds, title=trans('admin_funds_title', default='Manage Funds'))
    except Exception as e:
        logger.error(f"Error in manage_funds for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/kyc', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_kyc():
    """View and manage KYC submissions."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        kyc_records = list(db.kyc_records.find().sort('created_at', -1))
        for record in kyc_records:
            record['_id'] = str(record['_id'])
        return render_template('kyc/admin.html', kyc_records=kyc_records, title=trans('admin_kyc_title', default='Manage KYC Submissions'))
    except Exception as e:
        logger.error(f"Error fetching KYC records for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/reports/customers', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def customer_reports():
    """Generate customer reports in HTML, PDF, or CSV format."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        format = request.args.get('format', 'html')
        users = list(db.users.find())
        for user in users:
            user['_id'] = str(user['_id'])
            trial_end = user.get('trial_end')
            subscription_end = user.get('subscription_end')
            trial_end_aware = trial_end.replace(tzinfo=ZoneInfo("UTC")) if trial_end and trial_end.tzinfo is None else trial_end
            subscription_end_aware = subscription_end.replace(tzinfo=ZoneInfo("UTC")) if subscription_end and subscription_end.tzinfo is None else subscription_end
            user['is_trial_active'] = (
                datetime.now(timezone.utc) <= trial_end_aware if user.get('is_trial') and trial_end_aware
                else user.get('is_subscribed') and subscription_end_aware and datetime.now(timezone.utc) <= subscription_end_aware
            )
        
        if format == 'pdf':
            return generate_customer_report_pdf(users)
        elif format == 'csv':
            return generate_customer_report_csv(users)
        
        return render_template('admin/customer_reports.html', users=users, title=trans('admin_customer_reports_title', default='Customer Reports'))
    except Exception as e:
        logger.error(f"Error in customer_reports for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/reports/investors', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def investor_reports():
    """Generate investor reports summarizing financial health."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        format = request.args.get('format', 'html')
        funds = list(db.funds.find())
        total_funds = sum(fund['amount'] for fund in funds) if funds else 0
        debtors = list(db.debtors.find())
        total_debtors = sum(debtor['amount'] for debtor in debtors) if debtors else 0
        creditors = list(db.creditors.find())
        total_creditors = sum(creditor['amount'] for creditor in creditors) if creditors else 0
        report_data = {
            'total_funds': utils.format_currency(total_funds),
            'total_debtors': utils.format_currency(total_debtors),
            'total_creditors': utils.format_currency(total_creditors),
            'net_position': utils.format_currency(total_funds - total_creditors)
        }
        if format == 'pdf':
            return generate_investor_report_pdf(report_data)
        elif format == 'csv':
            return generate_investor_report_csv(report_data)
        
        return render_template('admin/investor_reports.html', report_data=report_data, title=trans('admin_investor_reports_title', default='Investor Reports'))
    except Exception as e:
        logger.error(f"Error in investor_reports for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/forecasts', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_forecasts():
    """View basic financial forecasts."""
    try:
        db = utils.get_mongo_db()
        if db is None:
            raise Exception("Failed to connect to MongoDB")
        records = list(get_records(db, {}))
        cashflows = list(get_cashflows(db, {}))
        total_income = sum(record['amount'] for record in records if record['type'] == 'income') if records else 0
        total_expenses = sum(cashflow['amount'] for cashflow in cashflows if cashflow['type'] == 'expense') if cashflows else 0
        forecast = {
            'total_income': utils.format_currency(total_income),
            'total_expenses': utils.format_currency(total_expenses),
            'net_cashflow': utils.format_currency(total_income - total_expenses),
            'projected_income': utils.format_currency(total_income * 1.1),
            'projected_expenses': utils.format_currency(total_expenses * 1.1)
        }
        return render_template('admin/forecasts.html', forecast=forecast, title=trans('admin_forecasts_title', default='Financial Forecasts'))
    except Exception as e:
        logger.error(f"Error generating forecasts for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('error/500.html'), 500

@admin_bp.route('/waitlist', methods=['GET'])
@login_required
@utils.requires_role('admin')
def view_waitlist():
    try:
        db = utils.get_mongo_db()
        entries = get_waitlist_entries(db, {})
        return render_template('admin/waitlist.html', entries=[to_dict_waitlist(e) for e in entries])
    except Exception as e:
        logger.error(f"Error viewing waitlist: {str(e)}", exc_info=True)
        flash(trans('general_error', default='An error occurred while loading the waitlist'))
        return redirect(url_for('home'))

@admin_bp.route('/waitlist/export', methods=['GET'])
@login_required
@utils.requires_role('admin')
def export_waitlist():
    try:
        db = utils.get_mongo_db()
        entries = get_waitlist_entries(db, {})
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Full Name', 'WhatsApp Number', 'Email', 'Business Type', 'Created At', 'Updated At'])
        for entry in entries:
            dict_entry = to_dict_waitlist(entry)
            writer.writerow([
                dict_entry['id'],
                dict_entry['full_name'],
                dict_entry['whatsapp_number'],
                dict_entry['email'],
                dict_entry['business_type'],
                dict_entry['created_at'],
                dict_entry['updated_at']
            ])
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'waitlist_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.csv'
        )
    except Exception as e:
        logger.error(f"Error exporting waitlist: {str(e)}", exc_info=True)
        flash(trans('general_error', default='An error occurred while exporting the waitlist'))
        return redirect(url_for('admin.view_waitlist'))

@admin_bp.route('/waitlist/contact/<string:entry_id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
def contact_signup(entry_id):
    try:
        db = utils.get_mongo_db()
        entry = db.waitlist.find_one({'_id': ObjectId(entry_id)})
        if not entry:
            flash(trans('general_not_found', default='Waitlist entry not found'))
            return redirect(url_for('admin.view_waitlist'))
        
        dict_entry = to_dict_waitlist(entry)
        
        if request.method == 'POST':
            message = request.form.get('message')
            method = request.form.get('method')  # 'email' or 'whatsapp'
            
            if not message or not method:
                flash(trans('general_missing_fields', default='Missing required fields'))
                return render_template('admin/contact.html', entry=dict_entry)
            
            # Placeholder for sending message
            # Implement actual sending logic here, e.g., using external services
            # For email: send_email(dict_entry['email'], 'Message from Admin', message)
            # For whatsapp: send_whatsapp(dict_entry['whatsapp_number'], message)
            # Assuming send_email and send_whatsapp are defined in utils.py or similar
            
            # Log the action
            audit_data = {
                'admin_id': current_user.id,
                'action': f'Contacted waitlist signup via {method}',
                'details': {'entry_id': entry_id, 'method': method, 'message': message},
                'timestamp': datetime.now(timezone.utc)
            }
            log_audit_action('contact_waitlist', audit_data['details'])
            
            flash(trans('general_message_sent', default='Message sent successfully'))
            return redirect(url_for('admin.view_waitlist'))
        
        return render_template('admin/contact.html', entry=dict_entry)
    except Exception as e:
        logger.error(f"Error contacting waitlist signup {entry_id}: {str(e)}", exc_info=True)
        flash(trans('general_error', default='An error occurred while contacting the signup'))
        return redirect(url_for('admin.view_waitlist'))

def generate_customer_report_pdf(users):
    """Generate a PDF report of customer data."""
    try:
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4)
        p.setFont("Helvetica", 12)
        p.drawString(1 * inch, 10.5 * inch, trans('admin_customer_report_title', default='Customer Report'))
        p.drawString(1 * inch, 10.2 * inch, f"{trans('admin_generated_on', default='Generated on')}: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
        y = 9.5 * inch
        p.drawString(1 * inch, y, trans('admin_username', default='Username'))
        p.drawString(2.5 * inch, y, trans('admin_email', default='Email'))
        p.drawString(4 * inch, y, trans('user_role', default='Role'))
        p.drawString(5.5 * inch, y, trans('subscription_status', default='Subscription Status'))
        y -= 0.3 * inch
        for user in users:
            status = 'Subscribed' if user.get('is_subscribed') and user.get('is_trial_active') else 'Trial' if user.get('is_trial') and user.get('is_trial_active') else 'Expired'
            p.drawString(1 * inch, y, user['_id'])
            p.drawString(2.5 * inch, y, user['email'])
            p.drawString(4 * inch, y, user['role'])
            p.drawString(5.5 * inch, y, status)
            y -= 0.3 * inch
            if y < 1 * inch:
                p.showPage()
                p.setFont("Helvetica", 12)
                y = 10.5 * inch
        p.showPage()
        p.save()
        buffer.seek(0)
        return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=customer_report.pdf'})
    except Exception as e:
        logger.error(f"Error generating customer report PDF: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_report_error', default='An error occurred while generating the report'), 'danger')
        return render_template('error/500.html'), 500

def generate_customer_report_csv(users):
    """Generate a CSV report of customer data."""
    try:
        output = [[trans('admin_username', default='Username'), trans('admin_email', default='Email'), trans('user_role', default='Role'), trans('subscription_status', default='Subscription Status')]]
        for user in users:
            status = 'Subscribed' if user.get('is_subscribed') and user.get('is_trial_active') else 'Trial' if user.get('is_trial') and user.get('is_trial_active') else 'Expired'
            output.append([user['_id'], user['email'], user['role'], status])
        buffer = BytesIO()
        writer = csv.writer(buffer, lineterminator='\n')
        writer.writerows(output)
        buffer.seek(0)
        return Response(buffer, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=customer_report.csv'})
    except Exception as e:
        logger.error(f"Error generating customer report CSV: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_report_error', default='An error occurred while generating the report'), 'danger')
        return render_template('error/500.html'), 500

def generate_investor_report_pdf(report_data):
    """Generate a PDF report for investors."""
    try:
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4)
        p.setFont("Helvetica", 12)
        p.drawString(1 * inch, 10.5 * inch, trans('admin_investor_report_title', default='Investor Report'))
        p.drawString(1 * inch, 10.2 * inch, f"{trans('admin_generated_on', default='Generated on')}: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
        y = 9.5 * inch
        p.drawString(1 * inch, y, trans('fund_total', default='Total Funds'))
        p.drawString(3 * inch, y, report_data['total_funds'])
        y -= 0.3 * inch
        p.drawString(1 * inch, y, trans('debtor_total', default='Total Debtors'))
        p.drawString(3 * inch, y, report_data['total_debtors'])
        y -= 0.3 * inch
        p.drawString(1 * inch, y, trans('creditor_total', default='Total Creditors'))
        p.drawString(3 * inch, y, report_data['total_creditors'])
        y -= 0.3 * inch
        p.drawString(1 * inch, y, trans('net_position', default='Net Position'))
        p.drawString(3 * inch, y, report_data['net_position'])
        p.showPage()
        p.save()
        buffer.seek(0)
        return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=investor_report.pdf'})
    except Exception as e:
        logger.error(f"Error generating investor report PDF: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_report_error', default='An error occurred while generating the report'), 'danger')
        return render_template('error/500.html'), 500

def generate_investor_report_csv(report_data):
    """Generate a CSV report for investors."""
    try:
        output = [
            [trans('fund_total', default='Total Funds'), report_data['total_funds']],
            [trans('debtor_total', default='Total Debtors'), report_data['total_debtors']],
            [trans('creditor_total', default='Total Creditors'), report_data['total_creditors']],
            [trans('net_position', default='Net Position'), report_data['net_position']]
        ]
        buffer = BytesIO()
        writer = csv.writer(buffer, lineterminator='\n')
        writer.writerows(output)
        buffer.seek(0)
        return Response(buffer, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=investor_report.csv'})
    except Exception as e:
        logger.error(f"Error generating investor report CSV: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_report_error', default='An error occurred while generating the report'), 'danger')
        return render_template('error/500.html'), 500
