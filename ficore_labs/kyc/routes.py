from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError
from wtforms import StringField, SelectField, FileField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from bson import ObjectId
import os
import uuid
import logging
import utils
from utils import get_mongo_db
from translations import trans

logger = logging.getLogger(__name__)

kyc_bp = Blueprint('kyc', __name__, url_prefix='/kyc')

# Form for KYC submission
class KYCForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=100)])
    id_type = SelectField('ID Type', choices=[('NIN', 'NIN'), ('Voters Card', 'Voter’s Card'), ('Passport', 'Passport')], validators=[DataRequired()])
    id_number = StringField('ID Number', validators=[DataRequired(), Length(max=50)])
    id_photo = FileField('ID Photo', validators=[DataRequired()])
    submit = SubmitField('Submit')

@kyc_bp.route('/submit', methods=['GET', 'POST'])
@login_required
@utils.limiter.limit('10 per minute')
def submit():
    """Submit KYC information."""
    form = KYCForm()
    if form.validate_on_submit():
        try:
            # Validate file
            file = form.id_photo.data
            if not file:
                flash(trans('kyc_file_required', default='ID photo is required'), 'danger')
                return render_template('kyc/submit.html', form=form)
            
            # Validate file extension and size
            allowed_extensions = {'.jpg', '.jpeg', '.png', '.pdf'}
            file_ext = os.path.splitext(secure_filename(file.filename))[1].lower()
            if file_ext not in allowed_extensions:
                flash(trans('kyc_invalid_file_type', default='Invalid file type. Allowed types: jpg, jpeg, png, pdf'), 'danger')
                return render_template('kyc/submit.html', form=form)
            
            file_size = len(file.read())
            file.seek(0)  # Reset file pointer
            max_size = 5 * 1024 * 1024  # 5MB
            if file_size > max_size:
                flash(trans('kyc_file_too_large', default='File size exceeds 5MB limit'), 'danger')
                return render_template('kyc/submit.html', form=form)
            
            # Ensure Uploads directory exists
            upload_dir = 'uploads'
            os.makedirs(upload_dir, exist_ok=True)
            
            # Save file with unique filename
            unique_filename = f"{uuid.uuid4()}{file_ext}"
            file_path = os.path.join(upload_dir, unique_filename)
            file.save(file_path)
            
            # Sanitize inputs
            full_name = utils.sanitize_input(form.full_name.data, max_length=100)
            id_number = utils.sanitize_input(form.id_number.data, max_length=50)
            
            # Save KYC record
            kyc_record = {
                'user_id': str(current_user.id),
                'full_name': full_name,
                'id_type': form.id_type.data,
                'id_number': id_number,
                'uploaded_id_photo_url': file_path,
                'status': 'pending',
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc)
            }
            db = get_mongo_db()
            db.kyc_records.insert_one(kyc_record)
            
            # Update session with KYC status
            session['kyc_status'] = 'pending'
            
            logger.info(
                f"KYC submitted for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('kyc_submit_success', default='KYC submitted successfully!'), 'success')
            return redirect(url_for('kyc.status'))
        except CSRFError as e:
            logger.error(
                f"CSRF error in KYC submission for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('kyc_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
            return render_template('kyc/submit.html', form=form), 400
        except Exception as e:
            logger.error(
                f"Error submitting KYC for user {current_user.id}: {str(e)}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('kyc_submit_error', default='An error occurred while submitting KYC'), 'danger')
            return render_template('kyc/submit.html', form=form), 500
    return render_template('kyc/submit.html', form=form, title=trans('kyc_submit_title', default='Submit KYC', lang=session.get('lang', 'en')))

@kyc_bp.route('/status')
@login_required
def status():
    """Check KYC status for the current user."""
    try:
        db = get_mongo_db()
        kyc_record = db.kyc_records.find_one({'user_id': str(current_user.id)})
        if kyc_record:
            # Convert naive datetimes to timezone-aware
            if kyc_record.get('created_at') and kyc_record['created_at'].tzinfo is None:
                kyc_record['created_at'] = kyc_record['created_at'].replace(tzinfo=ZoneInfo("UTC"))
            if kyc_record.get('updated_at') and kyc_record['updated_at'].tzinfo is None:
                kyc_record['updated_at'] = kyc_record['updated_at'].replace(tzinfo=ZoneInfo("UTC"))
            
            status = kyc_record['status']
            session['kyc_status'] = status  # Update session cache
            logger.info(
                f"Fetched KYC status for user {current_user.id}: {status}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return render_template(
                'kyc/status.html',
                status=status,
                allow_resubmit=(status == 'rejected'),
                title=trans('kyc_status_title', default='KYC Status', lang=session.get('lang', 'en'))
            )
        else:
            session['kyc_status'] = 'not_submitted'
            logger.info(
                f"No KYC record found for user {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('kyc_no_record', default='No KYC record found. Please submit your KYC information.'), 'warning')
            return redirect(url_for('kyc.submit'))
    except Exception as e:
        logger.error(
            f"Error fetching KYC status for user {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('kyc_status_error', default='An error occurred while fetching KYC status'), 'danger')
        return redirect(url_for('kyc.submit'))

@kyc_bp.route('/admin')
@login_required
@utils.requires_role(['admin'])
def admin():
    """Admin dashboard to view all KYC records."""
    try:
        db = get_mongo_db()
        kyc_records = list(db.kyc_records.find())
        # Convert naive datetimes to timezone-aware
        for record in kyc_records:
            if record.get('created_at') and record['created_at'].tzinfo is None:
                record['created_at'] = record['created_at'].replace(tzinfo=ZoneInfo("UTC"))
            if record.get('updated_at') and record['updated_at'].tzinfo is None:
                record['updated_at'] = record['updated_at'].replace(tzinfo=ZoneInfo("UTC"))
        
        logger.info(
            f"Admin accessed KYC records dashboard",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return render_template(
            'kyc/admin.html',
            kyc_records=kyc_records,
            title=trans('kyc_admin_title', default='Admin KYC Dashboard', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(
            f"Error fetching KYC records for admin {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('kyc_admin_error', default='An error occurred while fetching KYC records'), 'danger')
        return redirect(url_for('dashboard.index'))

@kyc_bp.route('/admin/approve/<kyc_id>', methods=['POST'])
@login_required
@utils.requires_role(['admin'])
@utils.limiter.limit('10 per minute')
def approve(kyc_id):
    """Approve a KYC record."""
    try:
        db = get_mongo_db()
        result = db.kyc_records.update_one(
            {'_id': ObjectId(kyc_id)},
            {'$set': {'status': 'approved', 'updated_at': datetime.now(timezone.utc)}}
        )
        if result.modified_count:
            logger.info(
                f"KYC {kyc_id} approved by admin {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('kyc_approve_success', default='KYC approved successfully!'), 'success')
        else:
            logger.warning(
                f"KYC record {kyc_id} not found for approval by admin {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('kyc_record_not_found', default='KYC record not found'), 'danger')
        return redirect(url_for('kyc.admin'))
    except ValueError:
        logger.error(
            f"Invalid KYC ID {kyc_id} for approval by admin {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('kyc_invalid_id', default='Invalid KYC ID'), 'danger')
        return redirect(url_for('kyc.admin'))
    except CSRFError as e:
        logger.error(
            f"CSRF error in KYC approval {kyc_id} by admin {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('kyc_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return redirect(url_for('kyc.admin'))
    except Exception as e:
        logger.error(
            f"Error approving KYC {kyc_id} by admin {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('kyc_approve_error', default='An error occurred while approving KYC'), 'danger')
        return redirect(url_for('kyc.admin'))

@kyc_bp.route('/admin/reject/<kyc_id>', methods=['POST'])
@login_required
@utils.requires_role(['admin'])
@utils.limiter.limit('10 per minute')
def reject(kyc_id):
    """Reject a KYC record."""
    try:
        db = get_mongo_db()
        result = db.kyc_records.update_one(
            {'_id': ObjectId(kyc_id)},
            {'$set': {'status': 'rejected', 'updated_at': datetime.now(timezone.utc)}}
        )
        if result.modified_count:
            logger.info(
                f"KYC {kyc_id} rejected by admin {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('kyc_reject_success', default='KYC rejected successfully!'), 'success')
        else:
            logger.warning(
                f"KYC record {kyc_id} not found for rejection by admin {current_user.id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('kyc_record_not_found', default='KYC record not found'), 'danger')
        return redirect(url_for('kyc.admin'))
    except ValueError:
        logger.error(
            f"Invalid KYC ID {kyc_id} for rejection by admin {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('kyc_invalid_id', default='Invalid KYC ID'), 'danger')
        return redirect(url_for('kyc.admin'))
    except CSRFError as e:
        logger.error(
            f"CSRF error in KYC rejection {kyc_id} by admin {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('kyc_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return redirect(url_for('kyc.admin'))
    except Exception as e:
        logger.error(
            f"Error rejecting KYC {kyc_id} by admin {current_user.id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('kyc_reject_error', default='An error occurred while rejecting KYC'), 'danger')
        return redirect(url_for('kyc.admin'))
