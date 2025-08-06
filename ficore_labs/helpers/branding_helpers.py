from flask import current_app
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors

# Colors from your CSS
FICORE_PRIMARY_COLOR = "#b88a44"
FICORE_HEADER_BG = "#F2EFEA"
FICORE_TEXT_COLOR = "#1e293b"
FICORE_LOGO_PATH = "img/ficore_logo.png"  # relative to static folder
TOP_MARGIN = 10.5  # in inches, adjusted to match new y_start

FICORE_MARKETING = "Empowering Africa's Businesses and Households. Contact: FicoreAfrica@gmail.com  | +234-xxx-xxxx"
FICORE_BRAND = "Ficore Africa"

def draw_ficore_pdf_header(canvas, user, y_start=10.5):
    """
    Draw Ficore branding and user info at the top of a PDF page with a shaded background and separator line.
    """
    inch = 72  # 1 inch in points
    static_folder = current_app.static_folder
    logo_path = f"{static_folder}/{FICORE_LOGO_PATH}"

   # Improved header dimensions
    header_height = 1.05       # big enough to cover everything + some padding
    y_logo = y_start - 0.30    # logo a bit lower
    y_brand = y_start - 0.07
    y_marketing = y_start - 0.24
    y_user = y_start - 0.7    # username well below logo/brand
    y_separator = y_start - header_height + 0.05  # separator stays nicely at bottom

    # Background rectangle for header
# Assuming y_start is top (e.g., 11 for Letter), y_separator is the Y position of the red line
    canvas.setFillColor(FICORE_HEADER_BG)
    canvas.rect(
        0,      # X (start at left)
        y_separator * inch,      # Y (bottom of header, at red line)
        8.5 * inch,              # Width of page
        (y_start - y_separator) * inch,  # Height from top to red line
        fill=1,
        stroke=0
    )
    canvas.setFillColor(colors.black)  # Reset fill color


    # Draw logo
    try:
        logo = ImageReader(logo_path)
        canvas.drawImage(logo, 1 * inch, y_logo * inch, width=0.5 * inch, height=0.5 * inch, mask='auto')
    except Exception:
        pass  # Don't break PDF if logo fails

    # Brand name
    canvas.setFont("Helvetica-Bold", 16)
    canvas.setFillColor(FICORE_PRIMARY_COLOR)
    canvas.drawString(1.75 * inch, y_brand * inch, FICORE_BRAND)

    # Marketing
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.black)
    canvas.drawString(1.75 * inch, y_marketing * inch, FICORE_MARKETING)

    # User info (display_name > _id > username)
    user_display = getattr(user, "display_name", "") or getattr(user, "_id", "") or getattr(user, "username", "User")
    user_email = getattr(user, "email", "")
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(FICORE_TEXT_COLOR)
    canvas.drawString(1 * inch, y_user * inch, f"Username: {user_display} | Email: {user_email}")

    # Red separator line below header content
    canvas.setStrokeColor(colors.red)
    canvas.setLineWidth(1)
    canvas.line(0.7 * inch, y_separator * inch, 7.7 * inch, y_separator * inch)
    canvas.setStrokeColor(colors.black)  # Reset stroke color

def ficore_csv_header(user):
    """
    Return a list of rows (each is a list of str) for branding/user info for CSV.
    """
    user_display = getattr(user, "display_name", "") or getattr(user, "_id", "") or getattr(user, "username", "User")
    user_email = getattr(user, "email", "")
    return [
        [FICORE_BRAND],
        [FICORE_MARKETING],
        [f"Username: {user_display} | Email: {user_email}"],
        []
    ]
