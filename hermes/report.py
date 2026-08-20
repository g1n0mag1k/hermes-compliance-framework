"""
hermes/report.py - Client-Facing PDF Evidence Report Generator
"""
import io
from dataclasses import asdict
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, Spacer, TableStyle

CFR = {
    "HIPAA_PHI_PERSON":      "45 CFR 164.514(b)(2)(i)(A)",
    "HIPAA_PHI_ORG":         "45 CFR 164.514(b)(2)(i)(A)",
    "HIPAA_PHI_ADDRESS":     "45 CFR 164.514(b)(2)(i)(B)",
    "HIPAA_PHI_GPS":         "45 CFR 164.514(b)(2)(i)(B)",
    "HIPAA_PHI_DATE":        "45 CFR 164.514(b)(2)(i)(C)",
    "HIPAA_PHI_AGE_89":      "45 CFR 164.514(b)(2)(i)(C)",
    "HIPAA_PHI_PHONE":       "45 CFR 164.514(b)(2)(i)(D)",
    "HIPAA_PHI_FAX":         "45 CFR 164.514(b)(2)(i)(E)",
    "HIPAA_PHI_EMAIL":       "45 CFR 164.514(b)(2)(i)(F)",
    "HIPAA_SSN":             "45 CFR 164.514(b)(2)(i)(G)",
    "HIPAA_PHI_MRN":         "45 CFR 164.514(b)(2)(i)(H)",
    "HIPAA_PHI_HPBN":        "45 CFR 164.514(b)(2)(i)(I)",
    "HIPAA_PHI_ACCOUNT":     "45 CFR 164.514(b)(2)(i)(J)",
    "HIPAA_PHI_VIN":         "45 CFR 164.514(b)(2)(i)(L)",
    "HIPAA_PHI_URL":         "45 CFR 164.514(b)(2)(i)(N)",
    "HIPAA_PHI_IP":          "45 CFR 164.514(b)(2)(i)(O)",
    "HIPAA_PHI_BANK_NUMBER": "45 CFR 164.514(b)(2)(i)(J)",
    "PCI_PAN":               "PCI-DSS Req. 3",
}

def generate_evidence_report(receipt, engagement_meta: dict) -> bytes:
    receipt_dict = asdict(receipt) if hasattr(receipt, "__dataclass_fields__") else receipt
    detected = receipt_dict.get("pii_classes_detected", [])
    zero_egress = receipt_dict.get("zero_pii_egress_confirmed", False)
    NAVY = colors.HexColor("#0b1622")
    LIGHT = colors.HexColor("#f4f7fa")
    styles = getSampleStyleSheet()
    N = styles["Normal"]
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
        rightMargin=0.75*inch, leftMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch)
    story = []
    story.append(Paragraph("<b><font size=18>HERMES RELAY</font></b>", N))
    story.append(Paragraph("PHI Telemetry Scan - Evidence Report", N))
    story.append(Paragraph("hermesrelay.dev  andrew@hermesrelay.dev", N))
    story.append(Spacer(1, 12))
    story.append(Paragraph("<b>ENGAGEMENT DETAILS</b>", N))
    story.append(Spacer(1, 4))
    meta = Table([
        ["Client", engagement_meta.get("client_name", "-")],
        ["Scan Date", engagement_meta.get("scan_date", "-")],
        ["Engineer", engagement_meta.get("engineer", "Andrew Rogers - Hermes Relay")],
        ["Scope", engagement_meta.get("scope", "-")],
        ["Exclusions", engagement_meta.get("excluded", "(K) Certificate/license; (M) Device identifiers; (P) Biometric; (Q) Full face photos; (R) Other unique IDs")],
    ], colWidths=[1.2*inch, 5.6*inch])
    meta.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,-1),LIGHT),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8.5),
        ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#d0dce6")),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1),8),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("WORDWRAP",(0,0),(-1,-1),True),
    ]))
    story.append(meta)
    story.append(Spacer(1, 12))
    story.append(Paragraph("<b>SCAN RESULTS</b>", N))
    story.append(Spacer(1, 4))
    rows = [["Category","Detected","CFR Citation"]]
    for flag, citation in CFR.items():
        label = flag.replace("HIPAA_PHI_","").replace("HIPAA_","").replace("PCI_","").replace("_"," ").title()
        rows.append([label, "YES" if flag in detected else "No", citation])
    rt = Table(rows, colWidths=[1.5*inch, 0.7*inch, 4.6*inch])
    rt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),NAVY),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#d0dce6")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,LIGHT]),
        ("TOPPADDING",(0,0),(-1,-1),4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING",(0,0),(-1,-1),6),
    ]))
    story.append(rt)
    story.append(Spacer(1, 12))
    story.append(Paragraph("<b>CRYPTOGRAPHIC ATTESTATION</b>", N))
    story.append(Spacer(1, 4))
    h = receipt_dict.get("receipt_hash", "")
    at = Table([
        ["Receipt ID", receipt_dict.get("receipt_id", "-")],
        ["Chain Position", str(receipt_dict.get("chain_position", "-"))],
        ["Issued At UTC", receipt_dict.get("issued_at", "-")],
        ["Issuer", receipt_dict.get("issuer", "Hermes Relay")],
        ["Zero-PHI Egress", "CONFIRMED" if zero_egress else "NOT CONFIRMED - Review required"],
        ["Receipt Hash", h[:32] + "..." if len(h) > 32 else h],
    ], colWidths=[1.4*inch, 5.4*inch])
    at.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,-1),LIGHT),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#d0dce6")),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1),8),
    ]))
    story.append(at)
    story.append(Spacer(1, 12))
    story.append(Paragraph("<b>CONCLUSION</b>", N))
    story.append(Spacer(1, 4))
    if zero_egress and not detected:
        c = "No unredacted PHI or PAN detected in declared scope. Chain integrity verified."
    elif zero_egress:
        readable = [f.replace('HIPAA_PHI_','').replace('HIPAA_','').replace('PCI_','').replace('_',' ').title() for f in detected]
        c = f"PHI detected and redacted before egress: {', '.join(readable)}. Zero egress confirmed."
    else:
        c = f"PHI detected: {', '.join(detected)}. Unredacted egress could not be confirmed. Review required."
    story.append(Paragraph(c, N))
    story.append(Spacer(1, 8))
    incomplete = receipt_dict.get("evidence_incomplete_categories", [])
    if incomplete:
        incomplete_str = "; ".join(incomplete)
        disc = (
            f"DISCLAIMER: This report is operational evidence only. It does not constitute "
            f"legal advice or a guarantee of HIPAA compliance. The following 45 CFR "
            f"\u00a7164.514(b)(2)(i) categories are outside declared scope and were not "
            f"scanned: {incomplete_str}."
        )
    else:
        disc = (
            "DISCLAIMER: This report is operational evidence only. It does not constitute "
            "legal advice or a guarantee of HIPAA compliance."
        )
    story.append(Paragraph(f"<i>{disc}</i>", N))
    story.append(Spacer(1, 24))
    story.append(Paragraph("<b>SIGNATURES</b>", N))
    story.append(Spacer(1, 4))
    st = Table([
        ["Client Authorized Signature","Engineer Signature"],
        ["____________________________","____________________________"],
        ["Name: _____________________","Name: Andrew Rogers"],
        ["Title: ____________________","Title: Compliance Systems Engineer"],
        ["Date:  ____________________","Date:  ____________________"],
    ], colWidths=[3.4*inch, 3.4*inch])
    st.setStyle(TableStyle([
        ("FONTSIZE",(0,0),(-1,-1),8.5),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
    ]))
    story.append(st)
    doc.build(story)
    buffer.seek(0)
    return buffer.read()
