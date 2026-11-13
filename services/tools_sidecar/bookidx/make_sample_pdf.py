"""
make_sample_pdf.py - generate a SYNTHETIC test PDF with FAKE course-like content.

This exists ONLY so the pipeline can be exercised without touching any real
Study/course material. All content below is invented. The end user never needs
this; it is a test fixture.

Layout:
  * pages 1-2 : cover + TOC (front matter -> page_offset must be 2)
  * page  3   : printed page 1  (commands)
  * page  4   : printed page 2  (Event IDs)
  * page  5   : printed page 3  (ports/protocols + acronyms)
  * page  6   : printed page 4  (concept paragraph + a small table)
  * page  7   : printed page 5  (Course: Volatility memory forensics)
  * page  8   : printed page 6  (Course: EZ Tools + Windows artifacts)
  * page  9   : printed page 7  (Course: KAPE / Plaso / Sleuth Kit)
  * page 10   : printed page 8  (Course: NTFS artifacts, Event IDs, Linux)

Run:  python make_sample_pdf.py
Output: books/sample.pdf
"""
import os

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas


def _footer(c, printed_page):
    c.setFont("Helvetica", 9)
    c.drawCentredString(letter[0] / 2, 0.5 * inch, f"Page {printed_page}")


def _header(c, text):
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(inch, letter[1] - 0.5 * inch, text)


def _body(c, lines, start_y=letter[1] - 1.2 * inch):
    c.setFont("Helvetica", 11)
    y = start_y
    for ln in lines:
        c.drawString(inch, y, ln)
        y -= 0.28 * inch


def build(path="books/sample.pdf"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = canvas.Canvas(path, pagesize=letter)

    # --- Front matter (no footer page number) : PDF page 1 = cover ---
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(letter[0] / 2, letter[1] - 3 * inch, "FAKE DFIR COURSE 501")
    c.setFont("Helvetica", 12)
    c.drawCentredString(letter[0] / 2, letter[1] - 3.5 * inch, "Synthetic Test Material (invented)")
    c.showPage()

    # PDF page 2 = TOC
    c.setFont("Helvetica-Bold", 16)
    c.drawString(inch, letter[1] - 1.5 * inch, "Table of Contents")
    _body(c, [
        "1. Commands ................. 1",
        "2. Windows Event IDs ........ 2",
        "3. Ports and Acronyms ....... 3",
        "4. Concepts and Tables ...... 4",
    ], start_y=letter[1] - 2.2 * inch)
    c.showPage()

    # --- Content pages (printed pages start at 1) ---
    # PDF page 3 = printed page 1 : commands
    _header(c, "FAKE DFIR COURSE 501 - Module 1")
    _body(c, [
        "Scanning commands you must know:",
        "Use nmap -sS for a stealth SYN scan of a target host.",
        "Run tcpdump -nn -i eth0 to capture packets without name resolution.",
        "The command netstat -ano lists connections with owning PIDs.",
        "Use tshark -r capture.pcap to read a saved packet capture.",
    ])
    _footer(c, 1)
    c.showPage()

    # PDF page 4 = printed page 2 : Event IDs
    _header(c, "FAKE DFIR COURSE 501 - Module 2")
    _body(c, [
        "Key Windows Security event log identifiers:",
        "Event ID 4624 records a successful account logon.",
        "Event ID 4625 records a failed logon attempt.",
        "Event ID 4688 records new process creation.",
        "Event ID 4672 records special privileges assigned to a new logon.",
    ])
    _footer(c, 2)
    c.showPage()

    # PDF page 5 = printed page 3 : ports + acronyms
    _header(c, "FAKE DFIR COURSE 501 - Module 3")
    _body(c, [
        "Common ports and protocols:",
        "Port 88 Kerberos authentication traffic.",
        "Port 445 SMB file sharing.",
        "Port 3389 RDP remote desktop.",
        "The KDC (Key Distribution Center) issues Kerberos tickets.",
        "LDAP (Lightweight Directory Access Protocol) queries directory data.",
    ])
    _footer(c, 3)
    c.showPage()

    # PDF page 6 = printed page 4 : concept + small table
    _header(c, "FAKE DFIR COURSE 501 - Module 4")
    _body(c, [
        "Concept: Lateral movement is how an attacker pivots between hosts",
        "after gaining an initial foothold, often abusing valid credentials",
        "and remote administration protocols to reach higher-value systems.",
        "",
        "Quick reference table:",
    ])
    # (table drawn below, then _course_pages() appends printed pages 5-8)
    # Draw a tiny table-like grid.
    tbl_x, tbl_y = inch, letter[1] - 3.6 * inch
    rows = [
        ["Protocol", "Port", "Purpose"],
        ["Kerberos", "88", "Authentication"],
        ["SMB", "445", "File sharing"],
        ["RDP", "3389", "Remote desktop"],
    ]
    c.setFont("Helvetica", 10)
    col_w = [1.6 * inch, 1.0 * inch, 2.2 * inch]
    row_h = 0.3 * inch
    for ri, row in enumerate(rows):
        x = tbl_x
        yy = tbl_y - ri * row_h
        for ci, cell in enumerate(row):
            c.rect(x, yy - row_h, col_w[ci], row_h, stroke=1, fill=0)
            c.drawString(x + 4, yy - row_h + 8, cell)
            x += col_w[ci]
    _footer(c, 4)
    c.showPage()

    # --- Course flavored content (all FAKE) : printed pages 5-8 ---
    _course_pages(c)

    c.save()
    print(f"Wrote synthetic test PDF: {path}  (10 PDF pages; page_offset=2 -> printed 1..8)")


def _course_pages(c):
    """Append 4 FAKE Course-flavored content pages (printed 5-8, PDF 7-10)."""
    # PDF page 7 = printed page 5 : Volatility / memory forensics
    _header(c, "FAKE Course - Memory Forensics")
    _body(c, [
        "Volatility memory analysis (all examples are invented):",
        "Run vol.py -f mem.raw malfind to find injected/hidden code.",
        "Use vol.py -f mem.raw --profile=Win10x64 pslist to list processes.",
        "The psscan plugin scans for hidden or terminated processes.",
        "pstree shows parent-child relationships; netscan recovers sockets.",
        "cmdline reveals per-process command-line arguments.",
    ])
    _footer(c, 5)
    c.showPage()

    # PDF page 8 = printed page 6 : EZ Tools + Windows artifacts
    _header(c, "FAKE Course - EZ Tools & Artifacts")
    _body(c, [
        "Eric Zimmerman tooling (fake syntax):",
        "MFTECmd -f $MFT --csv . parses the master file table.",
        "PECmd -d C:\\Windows\\Prefetch parses Prefetch execution data.",
        "AppCompatCacheParser dumps ShimCache; AmcacheParser reads Amcache.",
        "EvtxECmd -f Security.evtx --csv . converts event logs.",
        "Prefetch proves how many times and when a program ran.",
    ])
    _footer(c, 6)
    c.showPage()

    # PDF page 9 = printed page 7 : KAPE / Plaso / Sleuth Kit
    _header(c, "FAKE Course - Collection & Timelining")
    _body(c, [
        "Triage and timeline tooling (invented commands):",
        "kape.exe --tsource C: --target !SANS_Triage collects artifacts.",
        "log2timeline.py plaso.dump image.E01 builds a super timeline.",
        "psort.py -o l2tcsv plaso.dump sorts the timeline output.",
        "fls -r -m C: image.dd lists files; icat extracts by inode.",
        "mactime -b bodyfile builds a MAC timeline; bulk_extractor carves.",
    ])
    _footer(c, 7)
    c.showPage()

    # PDF page 10 = printed page 8 : NTFS artifacts + Event IDs + Linux
    _header(c, "FAKE Course - NTFS, Events & Linux")
    _body(c, [
        "NTFS metadata and logs (fake):",
        "The $UsnJrnl:$J stream records file create/delete/rename history.",
        "$STANDARD_INFORMATION (SI) times are targets of timestomping;",
        "$FILE_NAME (FN) times resist it. Shellbags show folder access.",
        "Event ID 4688 records new process creation.",
        "Event ID 4624 records a successful logon; Event ID 7045 a service.",
        "On Linux inspect /var/log/auth.log, /var/log/secure, ~/.bash_history.",
    ])
    _footer(c, 8)
    c.showPage()


if __name__ == "__main__":
    build()
