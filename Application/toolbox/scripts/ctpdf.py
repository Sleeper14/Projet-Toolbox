import os
import re
from datetime import datetime

from fpdf import FPDF

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PDF(FPDF):
    def header(self):
        if self.page_no() == 1:  # Vérifie si c'est la première page
            # Logo
            self.image(f"{BASE_DIR}/static/images/pdf_logo.png", 10, 8, 33)
            self.set_font("Arial", "B", 15)
            
            # Titre
            w = self.get_string_width(title) + 6
            self.set_x((210 - w) / 2)
            self.set_draw_color(8, 61, 119)
            self.set_fill_color(0, 86, 179)
            self.set_text_color(255, 255, 255)
            self.set_line_width(1)
            self.cell(w, 9, title, 1, 1, "C", 1)
            self.ln(3)  # Espace après le titre
            
            # Type de rapport
            rt = self.get_string_width(report_type) + 6
            self.set_x((210 - rt) / 2)
            self.set_text_color(8, 61, 119)
            self.cell(rt, 9, report_type, 0, 1, "C")
            
            self.ln(30)  # Plus d'espace après l'en-tête pour éviter le chevauchement
    # Page footer
    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font("Arial", "I", 8)
        # Page number
        self.cell(0, 10, "Page " + str(self.page_no()) + "/{nb}", 0, 0, "C")

def convert_to_pdf(output, user_name, ip, function_name):
    import codecs

    with open(f"{BASE_DIR}/static/c.bin", "r") as n:
        n = codecs.decode(n.readline().rstrip(), "hex").decode("utf-8")

    pdf = PDF()
    global title, report_type, u
    u = str(n).split(",")
    report_type = f"{str(function_name).upper()}"
    title = ip
    directory = f"{BASE_DIR}/media/reports/{user_name}"
    os.makedirs(directory, exist_ok=True)

    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_text_color(1, 1, 3)

    for line in output:
        if function_name == "scanhote":
            pdf.set_font("Times", "B", 11) if "/tcp" in line else pdf.set_font(
                "Times", "", 10
            )
        else:
            pdf.set_font(
                "Times", "B", 11
            ) if "scan report for" in line else pdf.set_font("Times", "", 10)

        pdf.cell(0, 7, line, 0, 1)

    if re.match(r"[\d\.]+\/\d+", str(ip)):
        ip = str(ip).split("/")[0]
    elif re.match(r"http\w?\://\S+", str(ip)):
        ip = str(ip).split("/")[2]

    pdf.output(f"{directory}/{function_name}-{str(ip)}.pdf", "F")
