from flask import Flask, render_template, request, jsonify, make_response
import requests
import socket
import pdfkit
import ipaddress

app = Flask(__name__)

# トップページ
@app.route('/')
def index():
    return render_template('index.html')

# URLスキャン機能
@app.route('/scan_url', methods=['POST'])
def scan_url():
    url = request.form['url']
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        security_issues = []

        # セキュリティヘッダーの確認
        if 'X-Frame-Options' not in headers:
            security_issues.append('X-Frame-Options is missing.')
        if 'X-XSS-Protection' not in headers:
            security_issues.append('X-XSS-Protection is missing.')
        if 'Strict-Transport-Security' not in headers:
            security_issues.append('Strict-Transport-Security is missing.')
        if 'Content-Security-Policy' not in headers:
            security_issues.append('Content-Security-Policy is missing.')
        if 'Referrer-Policy' not in headers:
            security_issues.append('Referrer-Policy is missing.')

        return jsonify({'status': response.status_code, 'issues': security_issues})
    except requests.exceptions.Timeout:
        return jsonify({'error': 'The URL request timed out'}), 408
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

# ポートスキャン機能
@app.route('/scan_ports', methods=['POST'])
def scan_ports():
    host = request.form['host']

    # ホストが有効なIPアドレスかをチェック
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return jsonify({'error': 'Invalid IP address'}), 400

    if host in ['127.0.0.1', '0.0.0.0']:
        return jsonify({'error': 'Cannot scan localhost or invalid IP addresses'}), 400

    # よく使われるポート範囲
    ports = [22, 80, 443, 8080, 3306, 5432, 5900]  
    open_ports = []

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)

    return jsonify({'open_ports': open_ports})

if __name__ == '__main__':
    app.run(debug=True)
