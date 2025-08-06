from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, Response, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, TextAreaField, SubmitField, DateField
from wtforms.validators import DataRequired, Optional
from bson import ObjectId
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import logging
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from helpers.branding_helpers import draw_ficore_pdf_header, ficore_csv_header
import csv
import utils
from translations import trans

logger = logging.getLogger(__name__)

class ForecastForm(FlaskForm):
    title = StringField(trans('forecasts_title', default='Forecast Title'), validators=[DataRequired()])
    projected_revenue = FloatField(trans('forecasts_projected_revenue', default='Projected Revenue'), validators=[DataRequired()])
    projected_expenses = FloatField(trans('forecasts_projected_expenses', default='Projected Expenses'), validators=[DataRequired()])
    forecast_date = DateField(trans('forecasts_date', default='Forecast Date'), validators=[DataRequired()])
    description = TextAreaField(trans('general_description', default='Description'), validators=[Optional()])
    submit = SubmitField(trans('forecasts_add_forecast', default='Add Forecast'))

forecasts_bp = Blueprint('forecasts', __name__, url_prefix='/forecasts')

@forecasts_bp.route('/')
@login_required
@utils.requires_role('startup')
def index():
    """List all forecast records for the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'type': 'forecast'} if utils.is_admin() else {'user_id': str(current_user.id), 'type': 'forecast'}
        forecasts = list(db.records.find(query).sort('forecast_date', -1))
        can_interact = utils.can_user_interact(current_user)
        
        # Convert naive datetimes to timezone-aware
        for forecast in forecasts:
            if forecast.get('forecast_date') and forecast['forecast_date'].tzinfo is None:
                forecast['forecast_date'] = forecast['forecast_date'].replace(tzinfo=ZoneInfo("UTC"))
            if forecast.get('created_at') and forecast['created_at'].tzinfo is None:
                forecast['created_at'] = forecast['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        return render_template(
            'forecasts/index.html',
            forecasts=forecasts,
            can_interact=can_interact,
            title=trans('forecasts_index', default='Financial Forecasts', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching forecasts for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('forecasts_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@forecasts_bp.route('/manage')
@login_required
@utils.requires_role('startup')
def manage():
    """List all forecast records for management (edit/delete) by the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'type': 'forecast'} if utils.is_admin() else {'user_id': str(current_user.id), 'type': 'forecast'}
        forecasts = list(db.records.find(query).sort('forecast_date', -1))
        can_interact = utils.can_user_interact(current_user)
        
        # Convert naive datetimes to timezone-aware
        for forecast in forecasts:
            if forecast.get('forecast_date') and forecast['forecast_date'].tzinfo is None:
                forecast['forecast_date'] = forecast['forecast_date'].replace(tzinfo=ZoneInfo("UTC"))
            if forecast.get('created_at') and forecast['created_at'].tzinfo is None:
                forecast['created_at'] = forecast['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        return render_template(
            'forecasts/manage_forecasts.html',
            forecasts=forecasts,
            can_interact=can_interact,
            title=trans('forecasts_manage', default='Manage Forecasts', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching forecasts for manage page for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('forecasts_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('forecasts.index'))

@forecasts_bp.route('/view/<id>')
@login_required
@utils.requires_role('startup')
def view(id):
    """View detailed information about a specific forecast (JSON API)."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'forecast'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'forecast'}
        forecast = db.records.find_one(query)
        if not forecast:
            return jsonify({'error': trans('forecasts_record_not_found', default='Record not found')}), 404
        
        # Convert naive datetimes to timezone-aware
        if forecast.get('forecast_date') and forecast['forecast_date'].tzinfo is None:
            forecast['forecast_date'] = forecast['forecast_date'].replace(tzinfo=ZoneInfo("UTC"))
        if forecast.get('created_at') and forecast['created_at'].tzinfo is None:
            forecast['created_at'] = forecast['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        forecast['_id'] = str(forecast['_id'])
        forecast['forecast_date'] = forecast['forecast_date'].isoformat() if forecast.get('forecast_date') else None
        forecast['created_at'] = forecast['created_at'].isoformat() if forecast.get('created_at') else None
        
        return jsonify(forecast)
    except Exception as e:
        logger.error(f"Error fetching forecast {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return jsonify({'error': trans('forecasts_fetch_error', default='An error occurred')}), 500

@forecasts_bp.route('/view_page/<id>')
@login_required
@utils.requires_role('startup')
def view_page(id):
    """Render a detailed view page for a specific forecast."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'forecast'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'forecast'}
        forecast = db.records.find_one(query)
        if not forecast:
            flash(trans('forecasts_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('forecasts.index'))
        
        # Convert naive datetimes to timezone-aware
        if forecast.get('forecast_date') and forecast['forecast_date'].tzinfo is None:
            forecast['forecast_date'] = forecast['forecast_date'].replace(tzinfo=ZoneInfo("UTC"))
        if forecast.get('created_at') and forecast['created_at'].tzinfo is None:
            forecast['created_at'] = forecast['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        can_interact = utils.can_user_interact(current_user)
        
        return render_template(
            'forecasts/view.html',
            forecast=forecast,
            can_interact=can_interact,
            title=trans('forecasts_details', default='Forecast Details', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error rendering forecast view page {id} for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('forecasts_view_error', default='An error occurred'), 'danger')
        return redirect(url_for('forecasts.index'))

@forecasts_bp.route('/generate_report/<id>')
@login_required
@utils.requires_role('startup')
def generate_report(id):
    """Generate PDF report for a forecast."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('forecasts_subscription_required', default='Your trial or subscription has expired. Please subscribe to generate reports.'), 'danger')
            return redirect(url_for('dashboard.upgrade'))

        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'forecast'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'forecast'}
        forecast = db.records.find_one(query)
        
        if not forecast:
            flash(trans('forecasts_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('forecasts.index'))
        
        # Convert naive datetimes to timezone-aware
        if forecast.get('forecast_date') and forecast['forecast_date'].tzinfo is None:
            forecast['forecast_date'] = forecast['forecast_date'].replace(tzinfo=ZoneInfo("UTC"))
        if forecast.get('created_at') and forecast['created_at'].tzinfo is None:
            forecast['created_at'] = forecast['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        draw_ficore_pdf_header(p, current_user, y_start=10.5)
        
        header_height = 0.7
        extra_space = 0.2
        title_y = 10.5 - header_height - extra_space
        
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, title_y * inch, trans('forecasts_report_title', default='FiCore Records - Forecast Report'))
        
        p.setFont("Helvetica", 12)
        y_position = title_y - 0.5
        p.drawString(inch, y_position * inch, f"{trans('forecasts_title', default='Title')}: {forecast['title']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('forecasts_projected_revenue', default='Projected Revenue')}: {utils.format_currency(forecast['projected_revenue'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('forecasts_projected_expenses', default='Projected Expenses')}: {utils.format_currency(forecast['projected_expenses'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('forecasts_net_profit', default='Net Profit')}: {utils.format_currency(forecast['projected_revenue'] - forecast['projected_expenses'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('forecasts_date', default='Forecast Date')}: {utils.format_date(forecast['forecast_date'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('general_description', default='Description')}: {forecast.get('description', 'No description provided')}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('forecasts_date_recorded', default='Date Recorded')}: {utils.format_date(forecast['created_at'])}")
        
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, trans('forecasts_report_footer', default='This document serves as a financial forecast recorded on FiCore Records.'))
        
        p.showPage()
        p.save()
        
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_Forecast_Report_{forecast["title"]}.pdf'
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating forecast report {id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('forecasts_report_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('forecasts.index'))

@forecasts_bp.route('/generate_report_csv/<id>')
@login_required
@utils.requires_role('startup')
def generate_report_csv(id):
    """Generate CSV report for a forecast."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('forecasts_subscription_required', default='Your trial or subscription has expired. Please subscribe to generate reports.'), 'danger')
            return redirect(url_for('dashboard.upgrade'))
        
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'forecast'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'forecast'}
        forecast = db.records.find_one(query)
        
        if not forecast:
            flash(trans('forecasts_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('forecasts.index'))
        
        # Convert naive datetimes to timezone-aware
        if forecast.get('forecast_date') and forecast['forecast_date'].tzinfo is None:
            forecast['forecast_date'] = forecast['forecast_date'].replace(tzinfo=ZoneInfo("UTC"))
        if forecast.get('created_at') and forecast['created_at'].tzinfo is None:
            forecast['created_at'] = forecast['created_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        output = []
        output.extend(ficore_csv_header(current_user))
        output.append([trans('forecasts_report_title', default='FiCore Records - Forecast Report')])
        output.append([''])
        output.append([trans('forecasts_title', default='Title'), forecast['title']])
        output.append([trans('forecasts_projected_revenue', default='Projected Revenue'), utils.format_currency(forecast['projected_revenue'])])
        output.append([trans('forecasts_projected_expenses', default='Projected Expenses'), utils.format_currency(forecast['projected_expenses'])])
        output.append([trans('forecasts_net_profit', default='Net Profit'), utils.format_currency(forecast['projected_revenue'] - forecast['projected_expenses'])])
        output.append([trans('forecasts_date', default='Forecast Date'), utils.format_date(forecast['forecast_date'])])
        output.append([trans('general_description', default='Description'), forecast.get('description', 'No description provided')])
        output.append([trans('forecasts_date_recorded', default='Date Recorded'), utils.format_date(forecast['created_at'])])
        output.append([''])
        output.append([trans('forecasts_report_footer', default='This document serves as a financial forecast recorded on FiCore Records.')])
        
        buffer = io.BytesIO()
        writer = csv.writer(buffer, lineterminator='\n')
        writer.writerows(output)
        buffer.seek(0)
        
        return Response(
            buffer,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_Forecast_Report_{forecast["title"]}.csv'
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating forecast report CSV {id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('forecasts_report_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('forecasts.index'))

@forecasts_bp.route('/add', methods=['GET', 'POST'])
@login_required
@utils.requires_role('startup')
def add():
    """Add a new forecast record."""
    if not utils.can_user_interact(current_user):
        flash(trans('forecasts_subscription_required', default='Your trial or subscription has expired. Please subscribe to add forecasts.'), 'danger')
        return redirect(url_for('dashboard.upgrade'))

    form = ForecastForm()
    if form.validate_on_submit():
        try:
            db = utils.get_mongo_db()
            # Convert date to datetime with UTC timezone
            forecast_date = datetime.combine(form.forecast_date.data, datetime.min.time(), tzinfo=ZoneInfo("UTC"))
            forecast_data = {
                'user_id': str(current_user.id),
                'type': 'forecast',
                'title': form.title.data,
                'projected_revenue': form.projected_revenue.data,
                'projected_expenses': form.projected_expenses.data,
                'forecast_date': forecast_date,
                'description': form.description.data,
                'created_at': datetime.now(timezone.utc)
            }
            db.records.insert_one(forecast_data)
            
            logger.info(
                f"Forecast added for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('forecasts_add_success', default='Forecast added successfully'), 'success')
            return redirect(url_for('forecasts.index'))
        except Exception as e:
            logger.error(
                f"Error adding forecast for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('forecasts_add_error', default='An error occurred while adding forecast'), 'danger')

    return render_template(
        'forecasts/add.html',
        form=form,
        can_interact=utils.can_user_interact(current_user),
        title=trans('forecasts_add_forecast', default='Add Forecast', lang=session.get('lang', 'en'))
    )

@forecasts_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role('startup')
def edit(id):
    """Edit an existing forecast record."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('forecasts_subscription_required', default='Your trial or subscription has expired. Please subscribe to edit forecasts.'), 'danger')
            return redirect(url_for('dashboard.upgrade'))

        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'forecast'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'forecast'}
        forecast = db.records.find_one(query)
        
        if not forecast:
            flash(trans('forecasts_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('forecasts.index'))

        # Convert forecast_date to date for form
        forecast_date = forecast['forecast_date'].date() if isinstance(forecast['forecast_date'], datetime) else forecast['forecast_date']
        
        form = ForecastForm(data={
            'title': forecast['title'],
            'projected_revenue': forecast['projected_revenue'],
            'projected_expenses': forecast['projected_expenses'],
            'forecast_date': forecast_date,
            'description': forecast.get('description', '')
        })

        if form.validate_on_submit():
            try:
                # Convert date to datetime with UTC timezone
                forecast_date = datetime.combine(form.forecast_date.data, datetime.min.time(), tzinfo=ZoneInfo("UTC"))
                updated_record = {
                    'title': form.title.data,
                    'projected_revenue': form.projected_revenue.data,
                    'projected_expenses': form.projected_expenses.data,
                    'forecast_date': forecast_date,
                    'description': form.description.data,
                    'updated_at': datetime.now(timezone.utc)
                }
                db.records.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_record}
                )
                logger.info(
                    f"Forecast {id} updated for user {current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('forecasts_edit_success', default='Forecast updated successfully'), 'success')
                return redirect(url_for('forecasts.index'))
            except Exception as e:
                logger.error(
                    f"Error updating forecast {id} for user {current_user.id}: {str(e)}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('forecasts_edit_error', default='An error occurred'), 'danger')

        return render_template(
            'forecasts/edit.html',
            form=form,
            forecast=forecast,
            can_interact=utils.can_user_interact(current_user),
            title=trans('forecasts_edit_forecast', default='Edit Forecast', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(
            f"Error fetching forecast {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('forecasts_record_not_found', default='Record not found'), 'danger')
        return redirect(url_for('forecasts.index'))

@forecasts_bp.route('/delete/<id>', methods=['POST'])
@login_required
@utils.requires_role('startup')
def delete(id):
    """Delete a forecast record."""
    try:
        if not utils.can_user_interact(current_user):
            flash(trans('forecasts_subscription_required', default='Your trial or subscription has expired. Please subscribe to delete forecasts.'), 'danger')
            return redirect(url_for('dashboard.upgrade'))

        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'forecast'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'forecast'}
        result = db.records.delete_one(query)
        if result.deleted_count:
            logger.info(
                f"Forecast {id} deleted for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('forecasts_delete_success', default='Forecast deleted successfully'), 'success')
        else:
            flash(trans('forecasts_record_not_found', default='Record not found'), 'danger')
    except Exception as e:
        logger.error(
            f"Error deleting forecast {id} for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('forecasts_delete_error', default='An error occurred'), 'danger')
    return redirect(url_for('forecasts.index'))
