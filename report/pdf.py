from pathlib import Path
from markdown2 import markdown
import shutil, tempfile

def md_to_pdf(md_path: Path, pdf_path: Path):
    md_path = Path(md_path)
    pdf_path = Path(pdf_path)
    if not md_path.exists():
        raise FileNotFoundError(f'Markdown tidak ditemukan: {md_path}')
    html = markdown(md_path.read_text())
    try:
        from weasyprint import HTML
        HTML(string=html).write_pdf(str(pdf_path))
        return
    except Exception:
        pass
    try:
        import pdfkit
        wk = shutil.which('wkhtmltopdf')
        if not wk:
            raise RuntimeError('wkhtmltopdf tidak ditemukan')
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tmp:
            tmp.write(html.encode('utf-8')); tmp.flush()
            pdfkit.from_file(tmp.name, str(pdf_path))
        return
    except Exception as e:
        raise RuntimeError(f'Tidak ada backend PDF yang tersedia: {e}')
