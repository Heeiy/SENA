import socket
import threading
import time
from datetime import datetime
from collections import deque
from flask import Flask, request, jsonify, render_template, send_file
import json
import uuid
import io
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.pdfgen import canvas # Import this for header/footer

app = Flask(__name__, static_folder='static')

# Global variables to track scan progress and store results
scan_results = {}
scan_status = {}

# Dictionary untuk menyimpan definisi risiko port
PORT_RISK_DEFINITIONS = {
    21: {'service': 'FTP', 'risk_level': 'High', 'risk_description': 'FTP without encryption can expose credentials and data. It often has vulnerabilities due to misconfigurations or outdated versions.', 'recommendations': 'Use SFTP or FTPS. Disable anonymous FTP. Implement strong authentication.'},
    22: {'service': 'SSH', 'risk_level': 'Medium', 'risk_description': 'SSH is generally secure but can be vulnerable to brute-force attacks or weak key management.', 'recommendations': 'Use key-based authentication. Disable root login. Implement strong passwords/passphrases. Keep SSH up-to-date.'},
    23: {'service': 'Telnet', 'risk_level': 'Critical', 'risk_description': 'Telnet transmits data, including passwords, in plain text. Highly vulnerable to eavesdropping and credential theft.', 'recommendations': 'Do not use Telnet. Replace with SSH.'},
    25: {'service': 'SMTP', 'risk_level': 'Medium', 'risk_description': 'SMTP can be abused for spam relay or information gathering. Open relays are a significant security risk.', 'recommendations': 'Implement strict relay controls. Use authenticated SMTP (SMTPS/STARTTLS). Secure SMTP servers against exploits.'},
    53: {'service': 'DNS', 'risk_level': 'Low', 'risk_description': 'DNS can be vulnerable to cache poisoning, DDoS, or zone transfers.', 'recommendations': 'Implement DNSSEC. Restrict zone transfers. Use rate limiting.'},
    80: {'service': 'HTTP', 'risk_level': 'Medium', 'risk_description': 'HTTP without encryption can expose sensitive information. Web servers can have various vulnerabilities (e.g., XSS, SQLi).', 'recommendations': 'Implement HTTPS. Patch web server software regularly. Use a Web Application Firewall (WAF).'},
    110: {'service': 'POP3', 'risk_level': 'High', 'risk_description': 'POP3 without encryption sends credentials in plain text.', 'recommendations': 'Use POP3S (port 995).'},
    111: {'service': 'RPCBind', 'risk_level': 'High', 'risk_description': 'RPCBind provides information about other RPC services, potentially exposing attack vectors.', 'recommendations': 'Block access from untrusted networks. Ensure only necessary RPC services are running.'},
    135: {'service': 'MSRPC', 'risk_level': 'Medium', 'risk_description': 'Microsoft RPC Endpoint Mapper. Can be exploited in Windows environments for enumeration and privilege escalation.', 'recommendations': 'Apply Windows security updates. Restrict access to necessary hosts.'},
    139: {'service': 'NetBIOS-SSN', 'risk_level': 'High', 'risk_description': 'NetBIOS Session Service, often associated with SMB. Can be vulnerable to various attacks like NTLM relay or information disclosure.', 'recommendations': 'Disable NetBIOS over TCP/IP if not needed. Restrict access. Use SMBv3 with encryption.'},
    143: {'service': 'IMAP', 'risk_level': 'High', 'risk_description': 'IMAP without encryption sends credentials in plain text.', 'recommendations': 'Use IMAPS (port 993).'},
    443: {'service': 'HTTPS', 'risk_level': 'Low', 'risk_description': 'HTTPS provides encrypted communication but can still be vulnerable to misconfigurations or outdated TLS versions.', 'recommendations': 'Use strong TLS versions (TLS 1.2/1.3). Implement HSTS. Obtain valid SSL certificates.'},
    445: {'service': 'SMB', 'risk_level': 'Critical', 'risk_description': 'Server Message Block (SMB) can be highly vulnerable, often exploited by ransomware and worms (e.g., EternalBlue).', 'recommendations': 'Disable SMBv1. Apply all security patches. Restrict access to internal networks only.'},
    993: {'service': 'IMAPS', 'risk_level': 'Low', 'risk_description': 'Secure IMAP. Generally secure but requires proper certificate management and configuration.', 'recommendations': 'Ensure valid SSL/TLS certificates and strong ciphers.'},
    995: {'service': 'POP3S', 'risk_level': 'Low', 'risk_description': 'Secure POP3. Generally secure but requires proper certificate management and configuration.', 'recommendations': 'Ensure valid SSL/TLS certificates and strong ciphers.'},
    1723: {'service': 'PPTP', 'risk_level': 'High', 'risk_description': 'Point-to-Point Tunneling Protocol (PPTP) is considered insecure due to known vulnerabilities in its authentication mechanisms.', 'recommendations': 'Do not use PPTP. Use more secure VPN protocols like OpenVPN or IKEv2/IPsec.'},
    3306: {'service': 'MySQL', 'risk_level': 'Medium', 'risk_description': 'MySQL databases can be vulnerable to weak credentials, SQL injection, or unpatched vulnerabilities.', 'recommendations': 'Use strong passwords. Restrict remote access. Enable SSL/TLS for connections. Keep MySQL patched.'},
    3389: {'service': 'RDP', 'risk_level': 'High', 'risk_description': 'Remote Desktop Protocol (RDP) is a common target for brute-force attacks and can expose systems if not properly secured.', 'recommendations': 'Use strong passwords. Implement Network Level Authentication (NLA). Use a VPN. Disable RDP if not needed.'},
    5900: {'service': 'VNC', 'risk_level': 'High', 'risk_description': 'VNC without strong authentication or encryption can allow unauthorized remote access.', 'recommendations': 'Use strong passwords. Encrypt VNC traffic (e.g., via SSH tunnel).'},
    8080: {'service': 'HTTP Proxy / Tomcat', 'risk_level': 'Medium', 'risk_description': 'Often used for web proxies or alternative HTTP services. Can expose administrative interfaces or unpatched applications.', 'recommendations': 'Ensure applications are patched. Restrict access. Implement strong authentication.'},
    # Tambahkan definisi port lain sesuai kebutuhan
}

class PortScanner:
    def __init__(self, target, algorithm='bfs', common_ports_first=True, max_threads=100,
                 scan_id=None, port_range_start=1, port_range_end=1024):
        self.target = target
        self.algorithm = algorithm.lower()
        self.common_ports_first = common_ports_first
        self.max_threads = max_threads
        self.open_ports = []
        self.lock = threading.Lock()
        self.active_threads = 0
        self.thread_semaphore = threading.Semaphore(max_threads)
        self.scan_id = scan_id
        self.port_range_start = port_range_start
        self.port_range_end = port_range_end

        self.common_ports = [
            p for p in [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5900, 8080
            ] if self.port_range_start <= p <= self.port_range_end
        ]

    def get_port_info(self, port):
        """Mendapatkan nama layanan, tingkat risiko, deskripsi, dan rekomendasi untuk port."""
        service = "unknown"
        risk_level = "Unknown"
        risk_description = "No specific risk information available for this port."
        recommendations = "Consult official documentation for security best practices for this port."

        try:
            service = socket.getservbyport(port)
        except OSError:
            pass

        if port in PORT_RISK_DEFINITIONS:
            info = PORT_RISK_DEFINITIONS[port]
            risk_level = info['risk_level']
            risk_description = info['risk_description']
            recommendations = info['recommendations']

        return service, risk_level, risk_description, recommendations

    def scan_port(self, port):
        """Scan satu port dan tambahkan ke daftar jika terbuka"""
        try:
            with self.thread_semaphore:
                with self.lock:
                    self.active_threads += 1

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((self.target, port))

                if result == 0:
                    service, risk_level, risk_description, recommendations = self.get_port_info(port)
                    with self.lock:
                        self.open_ports.append({
                            'port': port,
                            'service': service,
                            'risk_level': risk_level,
                            'risk_description': risk_description,
                            'recommendations': recommendations
                        })
                s.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            with self.lock:
                self.active_threads -= 1
                if self.scan_id:
                    scan_results[self.scan_id]['progress'] += 1

    def get_ports_to_scan(self):
        """Menghasilkan daftar port yang akan dipindai berdasarkan rentang dan preferensi."""
        ports_to_scan = []

        if self.common_ports_first:
            for port in self.common_ports:
                if self.port_range_start <= port <= self.port_range_end:
                    ports_to_scan.append(port)

        all_ports_in_range = set(range(self.port_range_start, self.port_range_end + 1))

        remaining_ports = sorted(list(all_ports_in_range - set(ports_to_scan)))
        ports_to_scan.extend(remaining_ports)

        return ports_to_scan

    def bfs_scan(self):
        """Algoritma BFS untuk port scanning"""
        ports = self.get_ports_to_scan()
        queue = deque(ports)

        total_ports = len(queue)
        if self.scan_id:
            scan_results[self.scan_id]['total_ports'] = total_ports

        threads = []
        ports_to_process = list(queue)
        for port in ports_to_process:
            self.thread_semaphore.acquire()
            t = threading.Thread(target=self.scan_port_and_release, args=(port,))
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.finish_scan()

    def dfs_scan(self):
        """Algoritma DFS untuk port scanning"""
        ports = self.get_ports_to_scan()
        stack = list(reversed(ports))

        total_ports = len(stack)
        if self.scan_id:
            scan_results[self.scan_id]['total_ports'] = total_ports

        threads = []
        ports_to_process = list(stack)
        for port in ports_to_process:
            self.thread_semaphore.acquire()
            t = threading.Thread(target=self.scan_port_and_release, args=(port,))
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.finish_scan()

    def scan_port_and_release(self, port):
        """Wrapper function to scan port and then release the semaphore."""
        try:
            self.scan_port(port)
        finally:
            self.thread_semaphore.release()

    def finish_scan(self):
        """Finalisasi status scan setelah semua port selesai dipindai."""
        if self.scan_id:
            scan_status[self.scan_id] = "completed"
            scan_results[self.scan_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            elapsed_time = time.time() - scan_results[self.scan_id]['start_timestamp']
            scan_results[self.scan_id]['elapsed_time'] = f"{elapsed_time:.2f} seconds"
            scan_results[self.scan_id]['open_ports'] = sorted(self.open_ports, key=lambda x: x['port'])


    def run(self):
        """Jalankan port scanner dengan algoritma yang dipilih"""
        start_time = time.time()

        if self.scan_id:
            scan_results[self.scan_id] = {
                'target': self.target,
                'algorithm': self.algorithm.upper(),
                'common_ports_first': self.common_ports_first,
                'port_range_start': self.port_range_start,
                'port_range_end': self.port_range_end,
                'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'start_timestamp': start_time,
                'open_ports': [],
                'progress': 0,
                'total_ports': 0,
                'status_message': 'Scanning initiated...'
            }
            scan_status[self.scan_id] = "running"

        try:
            if self.algorithm == 'bfs':
                self.bfs_scan()
            elif self.algorithm == 'dfs':
                self.dfs_scan()
            else:
                self.bfs_scan()
        except Exception as e:
            print(f"Scan failed for {self.target}: {e}")
            if self.scan_id:
                scan_status[self.scan_id] = "failed"
                scan_results[self.scan_id]['status_message'] = f"Scan failed: {e}"
                scan_results[self.scan_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                elapsed_time = time.time() - scan_results[self.scan_id]['start_timestamp']
                scan_results[self.scan_id]['elapsed_time'] = f"{elapsed_time:.2f} seconds"

# Route for the main page
@app.route('/')
def index():
    return render_template('index.html')

# API endpoint to start a new scan
@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    algorithm = data.get('algorithm', 'bfs')
    common_ports_first = data.get('common_ports_first', True)
    max_threads = int(data.get('max_threads', 100))
    port_range_start = int(data.get('port_range_start', 1))
    port_range_end = int(data.get('port_range_end', 1024))

    scan_id = str(uuid.uuid4())

    scanner = PortScanner(
        target=target,
        algorithm=algorithm,
        common_ports_first=common_ports_first,
        max_threads=max_threads,
        scan_id=scan_id,
        port_range_start=port_range_start,
        port_range_end=port_range_end
    )

    scan_thread = threading.Thread(target=scanner.run)
    scan_thread.daemon = True
    scan_thread.start()

    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'target': target
    })

# API endpoint to get scan status and results
@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404

    result = scan_results[scan_id].copy()
    result['status'] = scan_status.get(scan_id, 'unknown')

    if 'status_message' not in result and result['status'] == 'running':
        result['status_message'] = f"Scanning {result['progress']}/{result['total_ports']} ports..."
    elif 'status_message' not in result and result['status'] == 'completed':
        result['status_message'] = "Scan completed successfully."
    elif 'status_message' not in result and result['status'] == 'failed':
        result['status_message'] = "Scan failed."

    return jsonify(result)

# API endpoint to get all scans
@app.route('/api/scans', methods=['GET'])
def get_all_scans():
    result = []
    for scan_id in scan_results:
        scan_data = scan_results[scan_id].copy()
        scan_data['scan_id'] = scan_id
        scan_data['status'] = scan_status.get(scan_id, 'unknown')

        if 'status_message' not in scan_data and scan_data['status'] == 'running':
            scan_data['status_message'] = f"Scanning {scan_data['progress']}/{scan_data['total_ports']} ports..."
        elif 'status_message' not in scan_data and scan_data['status'] == 'completed':
            scan_data['status_message'] = "Scan completed successfully."
        elif 'status_message' not in scan_data and scan_data['status'] == 'failed':
            scan_data['status_message'] = "Scan failed."

        result.append(scan_data)

    result.sort(key=lambda x: x.get('start_timestamp', 0), reverse=True)

    return jsonify(result)

# --- PDF Generation Functions ---

# Header callback function
def header(canvas_obj, doc):
    canvas_obj.saveState()
    # Bar header
    canvas_obj.setFont('Helvetica-Bold', 10)
    canvas_obj.setFillColor(colors.HexColor('#0f2027')) # Warna gelap untuk bar header
    canvas_obj.rect(0, A4[1] - 0.5 * inch, A4[0], 0.5 * inch, fill=1)
    canvas_obj.setFillColor(colors.whitesmoke) # Warna teks untuk bar header (putih)
    canvas_obj.drawString(doc.leftMargin, A4[1] - 0.35 * inch, "Port Scan Report")
    canvas_obj.drawRightString(A4[0] - doc.rightMargin, A4[1] - 0.35 * inch, datetime.now().strftime('%Y-%m-%d %H:%M'))
    canvas_obj.restoreState()

# Footer callback function
def footer(canvas_obj, doc):
    canvas_obj.saveState()
    # Footer bar
    canvas_obj.setFont('Helvetica', 9)
    canvas_obj.setFillColor(colors.HexColor('#0f2027')) # Warna gelap untuk bar footer
    canvas_obj.rect(0, 0.3 * inch, A4[0], 0.3 * inch, fill=1)
    canvas_obj.setFillColor(colors.whitesmoke) # Warna teks untuk bar footer (putih)
    page_num_text = "Page %d" % doc.page
    canvas_obj.drawString(doc.leftMargin, 0.4 * inch, "Generated by Python Port Scanner")
    canvas_obj.drawRightString(A4[0] - doc.rightMargin, 0.4 * inch, page_num_text)
    canvas_obj.restoreState()


# API endpoint to export scan results to PDF
@app.route('/api/scan/<scan_id>/export/pdf', methods=['GET'])
def export_scan_to_pdf(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = scan_results[scan_id]

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4, # Use A4 for standard paper size
        rightMargin=0.75 * inch, # 0.75 inch margin
        leftMargin=0.75 * inch,  # 0.75 inch margin
        topMargin=1 * inch,    # Space for header
        bottomMargin=0.8 * inch # Space for footer
    )

    styles = getSampleStyleSheet()

    # Custom styles for various text elements - Background Putih = Font Hitam
    styles.add(ParagraphStyle(name='TitleStyle', fontSize=24, leading=28, alignment=1, spaceAfter=20, fontName='Helvetica-Bold', textColor=colors.HexColor('#0f2027'))) # Judul besar, gelap
    styles.add(ParagraphStyle(name='Heading2Style', fontSize=16, leading=18, spaceBefore=15, spaceAfter=8, fontName='Helvetica-Bold', textColor=colors.HexColor('#2c5364'))) # Sub-judul, biru gelap
    styles.add(ParagraphStyle(name='NormalText', fontSize=10, leading=12, spaceAfter=5, fontName='Helvetica', textColor=colors.black)) # Teks normal, hitam
    styles.add(ParagraphStyle(name='TableCaption', fontSize=11, leading=13, spaceAfter=5, fontName='Helvetica-BoldOblique', textColor=colors.HexColor('#3a7bd5'))) # Caption tabel, biru
    
    # TableText untuk tabel SUMMARY - ini harus hitam
    styles.add(ParagraphStyle(name='SummaryTableText', fontSize=9, leading=11, fontName='Helvetica', alignment=0, textColor=colors.black))
    styles.add(ParagraphStyle(name='SummaryTableTextCenter', fontSize=9, leading=11, fontName='Helvetica', alignment=1, textColor=colors.black))

    # Warna risiko untuk tabel Open Ports Details (background gelap) - lebih cerah agar menonjol
    styles.add(ParagraphStyle(name='RiskCriticalDarkBG', fontSize=9, leading=11, fontName='Helvetica-Bold', textColor=colors.HexColor('#FF6B6B'))) # Merah lebih cerah
    styles.add(ParagraphStyle(name='RiskHighDarkBG', fontSize=9, leading=11, fontName='Helvetica-Bold', textColor=colors.HexColor('#FFD166'))) # Kuning/Oranye lebih cerah
    styles.add(ParagraphStyle(name='RiskMediumDarkBG', fontSize=9, leading=11, fontName='Helvetica-Bold', textColor=colors.HexColor('#ffe082'))) # Kuning lebih cerah
    styles.add(ParagraphStyle(name='RiskLowDarkBG', fontSize=9, leading=11, fontName='Helvetica-Bold', textColor=colors.HexColor('#6BFF91'))) # Hijau lebih cerah
    styles.add(ParagraphStyle(name='RiskUnknownDarkBG', fontSize=9, leading=11, fontName='Helvetica-Bold', textColor=colors.HexColor('#B0B0B0'))) # Abu-abu lebih cerah

    # TableText untuk tabel Open Ports Details (background gelap) - ini harus putih
    styles.add(ParagraphStyle(name='OpenPortsTableText', fontSize=9, leading=11, fontName='Helvetica', alignment=0, textColor=colors.white))
    styles.add(ParagraphStyle(name='OpenPortsTableTextCenter', fontSize=9, leading=11, fontName='Helvetica', alignment=1, textColor=colors.white))

    elements = []

    # Main Report Content
    # Pastikan teks di sini menggunakan style yang sesuai (NormalText, TitleStyle, Heading2Style)
    elements.append(Paragraph(f"Port Scan Report for <font color='#3a7bd5'>{scan_data['target']}</font>", styles['TitleStyle']))
    elements.append(Spacer(1, 0.2 * inch))

    # Scan Summary
    elements.append(Paragraph("1. Scan Summary", styles['Heading2Style']))
    elements.append(Paragraph("This section provides a high-level overview of the port scan operation.", styles['NormalText']))
    elements.append(Spacer(1, 0.1 * inch))

    summary_data = [
        [Paragraph("Target:", styles['NormalText']), Paragraph(scan_data['target'], styles['NormalText'])],
        [Paragraph("Algorithm Used:", styles['NormalText']), Paragraph(scan_data['algorithm'], styles['NormalText'])],
        [Paragraph("Port Range Scanned:", styles['NormalText']), Paragraph(f"{scan_data.get('port_range_start', 'N/A')} - {scan_data.get('port_range_end', 'N/A')}", styles['NormalText'])],
        [Paragraph("Common Ports First:", styles['NormalText']), Paragraph('Yes' if scan_data['common_ports_first'] else 'No', styles['NormalText'])],
        [Paragraph("Scan Start Time:", styles['NormalText']), Paragraph(scan_data['start_time'], styles['NormalText'])],
        [Paragraph("Scan End Time:", styles['NormalText']), Paragraph(scan_data.get('end_time', 'N/A'), styles['NormalText'])],
        [Paragraph("Total Duration:", styles['NormalText']), Paragraph(scan_data.get('elapsed_time', 'N/A'), styles['NormalText'])],
        [Paragraph("Scan Status:", styles['NormalText']), Paragraph(scan_status.get(scan_id, 'Unknown').capitalize(), styles['NormalText'])],
        [Paragraph("Total Ports Processed:", styles['NormalText']), Paragraph(str(scan_data['total_ports']), styles['NormalText'])],
        [Paragraph("Open Ports Found:", styles['NormalText']), Paragraph(str(len(scan_data['open_ports'])), styles['NormalText'])]
    ]

    summary_col_widths = [doc.width * 0.35, doc.width * 0.65]
    summary_table = Table(summary_data, colWidths=summary_col_widths)
    summary_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.25, colors.HexColor('#CCCCCC')), # Grid abu-abu terang di background putih
        ('BACKGROUND', (0,0), (-1,-1), colors.white), # Background putih
        ('TEXTCOLOR', (0,0), (-1,-1), colors.black) # Teks hitam untuk tabel ringkasan
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.4 * inch))

    # Open Ports Details
    elements.append(Paragraph("2. Open Ports Details", styles['Heading2Style']))
    elements.append(Paragraph("This section lists all open ports identified during the scan, along with their associated services, risk levels, and recommendations.", styles['NormalText']))
    elements.append(Spacer(1, 0.1 * inch))

    if scan_data['open_ports']:
        # Define table header
        port_table_data = [
            [Paragraph("Port", styles['OpenPortsTableTextCenter']), # Menggunakan style baru untuk teks putih
             Paragraph("Service", styles['OpenPortsTableTextCenter']),
             Paragraph("Risk Level", styles['OpenPortsTableTextCenter']),
             Paragraph("Description", styles['OpenPortsTableTextCenter']),
             Paragraph("Recommendations", styles['OpenPortsTableTextCenter'])]
        ]

        for port_info in scan_data['open_ports']:
            # Choose appropriate risk style for DARK background
            risk_style = styles['RiskUnknownDarkBG']
            if port_info['risk_level'] == 'Critical': risk_style = styles['RiskCriticalDarkBG']
            elif port_info['risk_level'] == 'High': risk_style = styles['RiskHighDarkBG']
            elif port_info['risk_level'] == 'Medium': risk_style = styles['RiskMediumDarkBG']
            elif port_info['risk_level'] == 'Low': risk_style = styles['RiskLowDarkBG']

            port_table_data.append([
                Paragraph(str(port_info['port']), styles['OpenPortsTableTextCenter']),
                Paragraph(port_info['service'], styles['OpenPortsTableText']),
                Paragraph(port_info['risk_level'], risk_style), # Apply custom risk style
                Paragraph(port_info['risk_description'], styles['OpenPortsTableText']),
                Paragraph(port_info['recommendations'], styles['OpenPortsTableText'])
            ])

        # Set column widths for open ports table
        port_col_widths = [
            doc.width * 0.08, # Port
            doc.width * 0.15, # Service
            doc.width * 0.12, # Risk Level
            doc.width * 0.30, # Description
            doc.width * 0.35  # Recommendations
        ]

        # Gaya tabel port tetap gelap dengan teks putih
        port_table_style = TableStyle([
            # Header Styling
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f2027')), # Dark blue-grey header background
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke), # White header text
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('TOPPADDING', (0,0), (-1,0), 10),
            ('ALIGN', (0,0), (-1,0), 'CENTER'), # Center header text

            # Row Styling
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#203a43')), # Darker row background
            ('TEXTCOLOR', (0,1), (-1,-1), colors.white), # White body text (disediakan oleh OpenPortsTableText)
            ('ALIGN', (0,1), (0,-1), 'CENTER'), # Port column centered
            ('ALIGN', (1,1), (-1,-1), 'LEFT'),  # Other columns left aligned
            ('VALIGN', (0,0), (-1,-1), 'TOP'), # Align cell content to top

            # Grid lines
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#2c5364')), # Grid lines color
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#2c5364')), # Outer box color
        ])

        port_table = Table(port_table_data, colWidths=port_col_widths)
        port_table.setStyle(port_table_style)
        elements.append(port_table)
    else:
        elements.append(Paragraph("No open ports found during this scan.", styles['NormalText']))

    # Build the PDF document with header and footer
    doc.build(elements, onFirstPage=header, onLaterPages=header, canvasmaker=canvas.Canvas)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=f"scan_report_{scan_id}.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True)