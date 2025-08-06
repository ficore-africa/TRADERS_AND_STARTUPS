from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify, send_file
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from flask_wtf.csrf import CSRFError
from translations import trans
from utils import requires_role, is_valid_email, format_currency, get_mongo_db, sanitize_input
from models import User, get_user, update_user, create_kyc_record, update_kyc_record, get_kyc_record, to_dict_kyc_record, to_dict_user
from bson import ObjectId
from datetime import datetime, timezone
from wtforms import StringField, TextAreaField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, Email, Optional
from gridfs import GridFS
from io import BytesIO
from PIL import Image
import logging
import utils

logger = logging.getLogger(__name__)

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')

class ProfileForm(FlaskForm):
    full_name = StringField(trans('general_full_name', default='Full Name'), [
        DataRequired(message=trans('general_full_name_required', default='Full name is required')),
        Length(min=1, max=100, message=trans('general_full_name_length', default='Full name must be between 1 and 100 characters'))
    ], render_kw={'class': 'form-control'})
    email = StringField(trans('general_email', default='Email'), [
        DataRequired(message=trans('general_email_required', default='Email is required')),
        Email(message=trans('general_email_invalid', default='Invalid email address'))
    ], render_kw={'class': 'form-control'})
    phone = StringField(trans('general_phone', default='Phone'), [
        Optional(),
        Length(max=20, message=trans('general_phone_length', default='Phone number too long'))
    ], render_kw={'class': 'form-control'})
    business_name = StringField(trans('general_business_name', default='Business Name'), [
        Optional(),
        Length(max=100, message=trans('general_business_name_length', default='Business name too long'))
    ], render_kw={'class': 'form-control'})
    business_address = TextAreaField(trans('general_business_address', default='Business Address'), [
        Optional(),
        Length(max=500, message=trans('general_business_address_length', default='Business address too long'))
    ], render_kw={'class': 'form-control'})
    industry = StringField(trans('general_industry', default='Industry'), [
        Optional(),
        Length(max=50, message=trans('general_industry_length', default='Industry name too long'))
    ], render_kw={'class': 'form-control'})
    products_services = StringField(trans('general_products_services', default='Products/Services'), [
        Optional(),
        Length(max=200, message=trans('general_products_services_length', default='Products/Services description too long'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('general_save_changes', default='Save Changes'), render_kw={'class': 'btn btn-primary w-100'})

def get_role_based_nav():
    """Helper function to determine role-based navigation data."""
    if current_user.role == 'trader':
        return utils.TRADER_TOOLS, utils.get_explore_features(), utils.TRADER_NAV
    elif current_user.role == 'startup':
        return utils.STARTUP_TOOLS, utils.get_explore_features(), utils.STARTUP_NAV
    elif current_user.role == 'admin':
        return utils.ALL_TOOLS, utils.get_explore_features(), utils.ADMIN_NAV
    else:
        logger.warning(
            f"Unexpected role {current_user.role} for user {current_user.id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return [], [], []  # Fallback for unexpected roles

@settings_bp.route('/')
@login_required
@requires_role(['trader', 'startup', 'admin'])
def index():
    """Display settings overview with KYC button."""
    try:
        db = get_mongo_db()
        kyc_records = get_kyc_record(db, {'user_id': str(current_user.id)})
        kyc_status = kyc_records[0]['status'] if kyc_records else 'not_submitted'
        session['kyc_status'] = kyc_status
        logger.info(
            f"Rendering settings page for user {current_user.id}, KYC status: {kyc_status}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return render_template(
            'settings/index.html',
            user=current_user,
            title=trans('settings_index_title', default='Settings', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(
            f"Error loading settings for user {current_user.id}: {str(e)}",
            exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('general_bp.home'))

@settings_bp.route('/profile', methods=['GET', 'POST'])
@login_required
@requires_role(['trader', 'startup', 'admin'])
@utils.limiter.limit('10 per minute')
def profile():
    """Unified profile management page with KYC status."""
    try:
        db = get_mongo_db()
        user_id = str(current_user.id)
        user = get_user(db, user_id)
        if not user:
            logger.warning(
                f"User {user_id} not found",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            flash(trans('general_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('general_bp.home'))

        form = ProfileForm()
        if request.method == 'GET':
            form.full_name.data = user.display_name
            form.email.data = user.email
            form.phone.data = user.phone
            user_dict = to_dict_user(user)
            if user.role in ['trader', 'startup'] and user_dict.get('business_details'):
                form.business_name.data = user_dict['business_details'].get('name', '')
                form.business_address.data = user_dict['business_details'].get('address', '')
                form.industry.data = user_dict['business_details'].get('industry', '')
                form.products_services.data = user_dict['business_details'].get('products_services', '')

        if form.validate_on_submit():
            try:
                email = sanitize_input(form.email.data, max_length=100)
                if email != user.email and get_user_by_email(db, email):
                    flash(trans('general_email_exists', default='Email already in use'), 'danger')
                    return render_template(
                        'settings/profile.html',
                        form=form,
                        user=to_dict_user(user),
                        title=trans('settings_profile_title', default='Profile Settings', lang=session.get('lang', 'en'))
                    )
                update_data = {
                    'display_name': sanitize_input(form.full_name.data, max_length=100),
                    'email': email,
                    'phone': sanitize_input(form.phone.data, max_length=20) if form.phone.data else None,
                    'setup_complete': True
                }
                if user.role in ['trader', 'startup']:
                    update_data['business_details'] = {
                        'name': sanitize_input(form.business_name.data, max_length=100) if form.business_name.data else '',
                        'address': sanitize_input(form.business_address.data, max_length=500) if form.business_address.data else '',
                        'industry': sanitize_input(form.industry.data, max_length=50) if form.industry.data else '',
                        'products_services': sanitize_input(form.products_services.data, max_length=200) if form.products_services.data else '',
                        'phone_number': sanitize_input(form.phone.data, max_length=20) if form.phone.data else ''
                    }
                if update_user(db, user_id, update_data):
                    logger.info(
                        f"Profile updated for user {user_id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                    )
                    flash(trans('general_profile_updated', default='Profile updated successfully'), 'success')
                else:
                    flash(trans('general_no_changes', default='No changes made to profile'), 'info')
                return redirect(url_for('settings.profile'))
            except Exception as e:
                logger.error(
                    f"Error updating profile for user {user_id}: {str(e)}",
                    exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')

        kyc_records = get_kyc_record(db, {'user_id': user_id})
        user_dict = to_dict_user(user)
        user_dict['kyc_status'] = kyc_records[0]['status'] if kyc_records else 'not_submitted'
        session['kyc_status'] = user_dict['kyc_status']
        logger.info(
            f"Rendering profile page for user {user_id}, KYC status: {user_dict['kyc_status']}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return render_template(
            'settings/profile.html',
            form=form,
            user=user_dict,
            title=trans('settings_profile_title', default='Profile Settings', lang=session.get('lang', 'en'))
        )
    except CSRFError as e:
        logger.error(
            f"CSRF error in profile settings for user {current_user.id}: {str(e)}",
            exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('settings_csrf_error', default='Invalid CSRF token. Please try again.'), 'danger')
        return render_template(
            'settings/profile.html',
            form=form,
            user=to_dict_user(user),
            title=trans('settings_profile_title', default='Profile Settings', lang=session.get('lang', 'en'))
        ), 400
    except Exception as e:
        logger.error(
            f"Error in profile settings for user {current_user.id}: {str(e)}",
            exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('general_bp.home'))

@settings_bp.route('/api/upload-profile-picture', methods=['POST'])
@login_required
@requires_role(['trader', 'startup', 'admin'])
@utils.limiter.limit('10 per minute')
def upload_profile_picture():
    """API endpoint to handle profile picture uploads."""
    try:
        db = get_mongo_db()
        fs = GridFS(db)
        user_id = str(current_user.id)
        user = get_user(db, user_id)
        if not user:
            logger.warning(
                f"User {user_id} not found for profile picture upload",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({"success": False, "message": trans('general_user_not_found', default='User not found.')}), 404

        if 'profile_picture' not in request.files:
            logger.error(
                f"No file uploaded for user {user_id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({"success": False, "message": trans('general_no_file_uploaded', default='No file uploaded.')}), 400

        file = request.files['profile_picture']
        if file.filename == '':
            logger.error(
                f"No file selected for user {user_id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({"success": False, "message": trans('general_no_file_selected', default='No file selected.')}), 400

        # Validate file size (5MB limit)
        file.seek(0, 2)  # Move to end of file
        if file.tell() > 5 * 1024 * 1024:
            logger.error(
                f"Image size too large for user {user_id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({"success": False, "message": trans('settings_image_too_large', default='Image size must be less than 5MB.')}), 400
        file.seek(0)  # Reset file pointer

        # Validate file type using PIL
        try:
            file_content = file.read()
            img = Image.open(BytesIO(file_content))
            file_format = img.format.lower()
            if file_format not in ['jpeg', 'png', 'gif']:
                logger.error(
                    f"Invalid image format {file_format} for user {user_id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )
                return jsonify({"success": False, "message": trans('general_invalid_image_format', default='Only JPG, PNG, and GIF files are allowed.')}), 400
        except Exception as e:
            logger.error(
                f"Error validating image file for user {user_id}: {str(e)}",
                exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({"success": False, "message": trans('general_invalid_image_format', default='Only JPG, PNG, and GIF files are allowed.')}), 400

        # Delete existing profile picture if it exists
        if user.profile_picture:
            try:
                fs.delete(ObjectId(user.profile_picture))
            except ValueError:
                logger.warning(
                    f"Invalid existing profile picture ID {user.profile_picture} for user {user_id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
                )

        # Store new profile picture
        file_id = fs.put(file_content, filename=sanitize_input(file.filename, max_length=100), content_type=file.content_type)
        update_user(db, user_id, {
            'profile_picture': str(file_id),
            'updated_at': datetime.now(timezone.utc)
        })
        logger.info(
            f"Profile picture uploaded for user {user_id}, file_id: {file_id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({
            "success": True,
            "message": trans('settings_profile_picture_updated', default='Profile picture updated successfully.'),
            "image_url": url_for('settings.get_profile_picture', user_id=user_id)
        })
    except CSRFError as e:
        logger.error(
            f"CSRF error in profile picture upload for user {user_id}: {str(e)}",
            exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({
            "success": False,
            "message": trans('settings_csrf_error', default='Invalid CSRF token. Please try again.')
        }), 400
    except Exception as e:
        logger.error(
            f"Error uploading profile picture for user {user_id}: {str(e)}",
            exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({"success": False, "message": trans('general_something_went_wrong', default='An error occurred.')}), 500

@settings_bp.route('/profile-picture/<user_id>')
@login_required
@requires_role(['trader', 'startup', 'admin'])
def get_profile_picture(user_id):
    """Serve the user's profile picture."""
    try:
        db = get_mongo_db()
        fs = GridFS(db)
        user = get_user(db, str(user_id))
        if not user or not user.profile_picture:
            logger.info(
                f"No profile picture found for user {user_id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return redirect(url_for('static', filename='img/default_profile.png'))

        file_id = ObjectId(user.profile_picture)
        grid_out = fs.get(file_id)
        logger.info(
            f"Serving profile picture for user {user_id}, file_id: {file_id}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return send_file(BytesIO(grid_out.read()), mimetype=grid_out.content_type)
    except ValueError:
        logger.error(
            f"Invalid user ID or profile picture ID for user {user_id}",
            exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return redirect(url_for('static', filename='img/default_profile.png'))
    except Exception as e:
        logger.error(
            f"Error retrieving profile picture for user {user_id}: {str(e)}",
            exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return redirect(url_for('static', filename='img/default_profile.png'))

@settings_bp.route('/api/update-user-setting', methods=['POST'])
@login_required
@requires_role(['trader', 'startup', 'admin'])
@utils.limiter.limit('10 per minute')
def update_user_setting():
    """API endpoint to update user settings via AJAX."""
    try:
        db = get_mongo_db()
        user_id = str(current_user.id)
        user = get_user(db, user_id)
        if not user:
            logger.warning(
                f"User {user_id} not found for setting update",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({"success": False, "message": trans('general_user_not_found', default='User not found.')}), 404

        data = request.get_json()
        setting_name = sanitize_input(data.get('setting'), max_length=50)
        value = data.get('value')
        valid_settings = [
            'showKoboToggle', 'incognitoModeToggle', 'appSoundsToggle',
            'fingerprintPasswordToggle', 'fingerprintPinToggle', 'hideSensitiveDataToggle'
        ]
        if setting_name not in valid_settings:
            logger.error(
                f"Invalid setting name {setting_name} for user {user_id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({"success": False, "message": trans('general_invalid_setting', default='Invalid setting name.')}), 400

        settings = user.settings.copy()
        security_settings = user.security_settings.copy()
        if setting_name == 'showKoboToggle':
            settings['show_kobo'] = bool(value)
        elif setting_name == 'incognitoModeToggle':
            settings['incognito_mode'] = bool(value)
        elif setting_name == 'appSoundsToggle':
            settings['app_sounds'] = bool(value)
        elif setting_name == 'fingerprintPasswordToggle':
            security_settings['fingerprint_password'] = bool(value)
        elif setting_name == 'fingerprintPinToggle':
            security_settings['fingerprint_pin'] = bool(value)
        elif setting_name == 'hideSensitiveDataToggle':
            security_settings['hide_sensitive_data'] = bool(value)

        update_data = {
            'settings': settings,
            'security_settings': security_settings,
            'updated_at': datetime.now(timezone.utc)
        }
        if update_user(db, user_id, update_data):
            logger.info(
                f"Setting {setting_name} updated for user {user_id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({"success": True, "message": trans('general_setting_updated', default='Setting updated successfully.')})
        else:
            logger.info(
                f"No changes made to setting {setting_name} for user {user_id}",
                extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
            )
            return jsonify({"success": False, "message": trans('general_no_changes', default='No changes made to settings.')}), 200
    except CSRFError as e:
        logger.error(
            f"CSRF error in updating setting for user {user_id}: {str(e)}",
            exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({
            "success": False,
            "message": trans('settings_csrf_error', default='Invalid CSRF token. Please try again.')
        }), 400
    except Exception as e:
        logger.error(
            f"Error updating user setting for user {user_id}: {str(e)}",
            exc_info=True, extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id}
        )
        return jsonify({"success": False, "message": trans('general_setting_update_error', default='An error occurred while updating the setting.')}), 500
