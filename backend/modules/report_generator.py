from fpdf import FPDF
import os
from datetime import datetime
from backend.modules.db_manager import get_all_evidence

def create_pdf_report():
    # Initialize the PDF document
    pdf = FPDF()
    pdf.add_page()
    
    # Add Title and Timestamp
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Automated Cyber Forensics Report", ln=True, align='C')
    
    pdf.set_font("Arial", 'I', 10)
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    pdf.cell(200, 10, txt=f"Report Generated: {current_time}", ln=True, align='C')
    pdf.ln(10)
    
    # Add Chain of Custody Section
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="1. Chain of Custody (Evidence Log)", ln=True)
    pdf.set_font("Arial", size=10)
    
    evidence = get_all_evidence()
    
    if not evidence:
        pdf.cell(200, 10, txt="No evidence logged in the database.", ln=True)
    else:
        for item in evidence:
            pdf.cell(200, 8, txt=f"Time: {item['upload_time']}", ln=True)
            pdf.cell(200, 8, txt=f"File: {item['filename']}", ln=True)
            pdf.cell(200, 8, txt=f"MD5: {item['md5']}", ln=True)
            pdf.ln(5) # Add a small blank line between entries

    # Define the save path
    report_folder = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'reports')
    report_path = os.path.join(report_folder, 'Official_Forensic_Report.pdf')
    
    # Output the PDF
    pdf.output(report_path)
    
    return report_path