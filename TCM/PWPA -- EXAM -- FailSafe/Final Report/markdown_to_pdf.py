#!/usr/bin/env python3
"""
Convert Markdown report to PDF with embedded images using reportlab
"""

import os
import re
from pathlib import Path
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY

# Configuration
MARKDOWN_FILE = r"c:\Users\mathe\OneDrive\Documents\ObsidianVault\notes\NOTES\TCM\PWPA -- EXAM -- FailSafe\Final Report\FailSafe - Final Penetration Test Report.md"
OUTPUT_PDF = r"c:\Users\mathe\OneDrive\Documents\ObsidianVault\notes\NOTES\TCM\PWPA -- EXAM -- FailSafe\Final Report\FailSafe - Final Penetration Test Report.pdf"
IMAGES_DIR = r"c:\Users\mathe\OneDrive\Documents\ObsidianVault\notes\NOTES\TCM\PWPA -- EXAM -- FailSafe\Images"

def read_markdown(filepath):
    """Read markdown file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

def find_images_for_finding(finding_num):
    """Find all images for a specific finding"""
    images = []
    finding_dir = os.path.join(IMAGES_DIR, f"Finding {finding_num},")
    
    for root, dirs, files in os.walk(IMAGES_DIR):
        if f"Finding {finding_num}," in root:
            for file in sorted(files):
                if file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                    images.append(os.path.join(root, file))
    
    return images

def parse_markdown_to_elements(markdown_text):
    """Parse markdown and convert to reportlab elements"""
    elements = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1f4788'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=colors.HexColor('#1f4788'),
        spaceAfter=12,
        spaceBefore=12
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=colors.HexColor('#2d5aa8'),
        spaceAfter=10,
        spaceBefore=10
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=10,
        alignment=TA_JUSTIFY,
        spaceAfter=8
    )
    
    lines = markdown_text.split('\n')
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Skip empty lines
        if not line.strip():
            elements.append(Spacer(1, 0.1*inch))
            i += 1
            continue
        
        # Title (# at start)
        if line.startswith('# ') and not line.startswith('## '):
            title = line.replace('# ', '').strip()
            elements.append(Paragraph(title, title_style))
            elements.append(Spacer(1, 0.2*inch))
            i += 1
            continue
        
        # Heading 1 (## at start)
        if line.startswith('## '):
            heading = line.replace('## ', '').strip()
            elements.append(Paragraph(heading, heading1_style))
            i += 1
            continue
        
        # Heading 2 (### at start)
        if line.startswith('### '):
            heading = line.replace('### ', '').strip()
            elements.append(Paragraph(heading, heading2_style))
            i += 1
            continue
        
        # Code block
        if line.strip().startswith('```'):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            
            code_text = '\n'.join(code_lines)
            code_style = ParagraphStyle(
                'Code',
                parent=styles['Normal'],
                fontName='Courier',
                fontSize=8,
                textColor=colors.HexColor('#333333'),
                backColor=colors.HexColor('#f0f0f0'),
                leftIndent=20,
                spaceAfter=10
            )
            elements.append(Paragraph(f"<pre>{code_text}</pre>", code_style))
            i += 1
            continue
        
        # Regular paragraph
        if line.strip():
            # Remove markdown formatting
            text = line.strip()
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)  # Bold
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)      # Italic
            text = re.sub(r'`(.*?)`', r'<font face="Courier">\1</font>', text)  # Inline code
            
            elements.append(Paragraph(text, body_style))
        
        i += 1
    
    return elements

def create_pdf():
    """Create PDF from markdown with images"""
    print("Reading markdown file...")
    markdown_text = read_markdown(MARKDOWN_FILE)
    
    print("Creating PDF document...")
    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    
    print("Parsing markdown to elements...")
    elements = parse_markdown_to_elements(markdown_text)
    
    print("Adding images for each finding...")
    # Add images for findings 1-11
    for finding_num in range(1, 12):
        images = find_images_for_finding(finding_num)
        if images:
            print(f"  Finding {finding_num}: Found {len(images)} image(s)")
            for img_path in images:
                if os.path.exists(img_path):
                    try:
                        # Add image with max width of 6 inches
                        img = Image(img_path, width=6*inch, height=4*inch)
                        elements.append(Spacer(1, 0.2*inch))
                        elements.append(img)
                        elements.append(Spacer(1, 0.2*inch))
                    except Exception as e:
                        print(f"    Error adding image {img_path}: {e}")
    
    print("Building PDF...")
    doc.build(elements)
    print(f"PDF created successfully: {OUTPUT_PDF}")

if __name__ == "__main__":
    try:
        create_pdf()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
