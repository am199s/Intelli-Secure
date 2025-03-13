import tempfile
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from PIL import Image as PILImage  # Import Pillow to get image dimensions

class Report:  # Renamed class to match your filename
    @staticmethod
    def create_report(scan_type: str, target: str, stats: dict, attributes: dict = None) -> str:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        doc = SimpleDocTemplate(temp_file.name, pagesize=letter)

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='Header',
            fontSize=14,
            leading=16,
            alignment=1,  # Center alignment
            spaceAfter=20
        ))
        styles.add(ParagraphStyle(
            name='SubHeader',
            fontSize=12,
            leading=14,
            alignment=0,  # Left alignment
            spaceBefore=10,
            spaceAfter=10
        ))
        styles.add(ParagraphStyle(
            name='NormalLeft',
            fontSize=10,
            leading=12,
            alignment=0,  # Left alignment
        ))

        # Path to the logo image
        logo_path = os.path.join(os.path.dirname(__file__), "..", "..", "resources", "logo.png")
        if not os.path.exists(logo_path):
            raise FileNotFoundError(f"Logo file not found at {logo_path}")

        # Get original image dimensions using Pillow
        with PILImage.open(logo_path) as img:
            original_width, original_height = img.size
            aspect_ratio = original_width / original_height

        # Set a maximum width and calculate height to preserve aspect ratio
        max_width = 2 * inch
        scaled_height = max_width / aspect_ratio
        max_height = 2 * inch
        if scaled_height > max_height:
            scaled_height = max_height
            max_width = scaled_height * aspect_ratio

        # Add logo image with preserved aspect ratio
        logo = Image(logo_path, width=max_width, height=scaled_height)
        logo.hAlign = 'CENTER'

        content = [
            logo,
            Spacer(1, 20),
            Paragraph(f"{scan_type} Scan Report", styles['Header']),
            Paragraph(f"<b>Target:</b> {target}", styles['Normal']),
            Paragraph(
                f"<b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                styles['Normal']
            ),
            Spacer(1, 20)
        ]

        # Stats table with "N/A" fallback
        data = [
            ["Category", "Count"],
            ["Malicious", stats.get("malicious", "N/A")],
            ["Suspicious", stats.get("suspicious", "N/A")],
            ["Undetected", stats.get("undetected", "N/A")],
            ["Harmless", stats.get("harmless", "N/A")]
        ]
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        content.append(table)

        # Additional Threat Intelligence section
        content.extend([
            Spacer(1, 20),
            Paragraph("Additional Threat Intelligence", styles['SubHeader'])
        ])

        if attributes:
            # Extract specific fields from attributes
            threat_categories = ", ".join(attributes.get("categories", {}).keys()) or "N/A"
            malware_names = ", ".join(attributes.get("names", [])) or "N/A"
            first_submission = attributes.get("first_submission_date", "N/A")
            if first_submission != "N/A":
                first_submission = datetime.fromtimestamp(first_submission).strftime('%Y-%m-%d %H:%M:%S')
            file_size = attributes.get("size", "N/A")
            if file_size != "N/A":
                file_size = f"{file_size} bytes"
            file_type = attributes.get("type", "N/A") or attributes.get("magic", "N/A")

            intel_data = [
                f"<b>Threat Categories:</b> {threat_categories}",
                f"<b>Malware Names:</b> {malware_names}",
                f"<b>First Submission Date:</b> {first_submission}",
                f"<b>File Size:</b> {file_size}",
                f"<b>File Type:</b> {file_type}"
            ]
            for line in intel_data:
                content.append(Paragraph(line, styles['NormalLeft']))
        else:
            content.append(Paragraph(
                "No additional threat intelligence available.",
                styles['NormalLeft']
            ))

        content.append(Spacer(1, 10))
        doc.build(content)
        return temp_file.name