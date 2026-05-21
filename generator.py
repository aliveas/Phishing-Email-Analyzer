
import os
from jinja2 import Environment, FileSystemLoader


def generate_report(
    eml_file        : str,
    scan_time       : str,
    elapsed         : float,
    email_data      : dict,
    header_findings : list,
    urls            : list,
    attachments     : list,
    vt_url_results  : list,
    vt_hash_results : list,
    whois_result    : dict,
    risk            : dict,
    output_path     : str,
) -> None:

    template_dir = os.path.dirname(__file__)
    env          = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    template     = env.get_template("template.html")

 
    vt_by_url = {r["query"]: r for r in vt_url_results}

    html = template.render(
        eml_file        = os.path.basename(eml_file),
        scan_time       = scan_time,
        elapsed         = elapsed,
        email_data      = email_data,
        header_findings = header_findings,
        urls            = urls,
        attachments     = attachments,
        vt_url_results  = vt_url_results,
        vt_hash_results = vt_hash_results,
        vt_by_url       = vt_by_url,
        whois_result    = whois_result,
        risk            = risk,
        total_iocs      = len(urls) + len(attachments),
        has_vt          = bool(vt_url_results or vt_hash_results),
        has_whois       = bool(whois_result and not whois_result.get("error")),
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
