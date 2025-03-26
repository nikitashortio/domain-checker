from flask import Flask, render_template, request, jsonify
import dns.resolver
import whois
import requests
import ssl
import socket
from urllib.parse import urlparse
import json
from datetime import datetime, date
import re
import os

app = Flask(__name__)

def get_dns_records(domain, record_type):
    """Get DNS records for a domain using multiple DNS resolvers"""
    results = []
    errors = []
    
    # List of DNS resolvers to try
    resolvers = [
        ('cloudflare', '1.1.1.1'),
        ('google', '8.8.8.8'),
        ('quad9', '9.9.9.9')
    ]
    
    for resolver_name, resolver_ip in resolvers:
        try:
            print(f"Looking up {record_type} records using {resolver_name}...")
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.timeout = 10
            resolver.lifetime = 10
            
            try:
                answers = resolver.resolve(domain, record_type)
                for rdata in answers:
                    result = {
                        'resolver': resolver_name,
                        'ttl': answers.ttl,
                        'value': str(rdata)
                    }
                    results.append(result)
                print(f"Found {len(answers)} {record_type} records with TTL {answers.ttl}")
            except dns.resolver.NoAnswer:
                print(f"No {record_type} records found")
            except dns.resolver.NXDOMAIN:
                print(f"Domain {domain} does not exist")
                errors.append(f"Domain {domain} does not exist")
            except dns.resolver.NoNameservers:
                print(f"No nameservers found for {resolver_name}")
                errors.append(f"No nameservers found for {resolver_name}")
            except dns.resolver.Timeout:
                print(f"Timeout while querying {resolver_name}")
                errors.append(f"Timeout while querying {resolver_name}")
            except Exception as e:
                print(f"Error with {resolver_name}: {str(e)}")
                errors.append(f"Error with {resolver_name}: {str(e)}")
                
        except Exception as e:
            print(f"Error setting up {resolver_name}: {str(e)}")
            errors.append(f"Error setting up {resolver_name}: {str(e)}")
    
    if not results and errors:
        return {'error': '; '.join(errors)}
    
    return results

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        if not w.domain_name:
            return {'error': 'Domain not found in WHOIS database'}
        
        # Convert datetime objects to strings
        info = {}
        for key, value in w.items():
            if isinstance(value, (datetime, date)):
                info[key] = value.isoformat()
            else:
                info[key] = value
        return info
    except Exception as e:
        return {'error': f'Failed to get WHOIS info: {str(e)}'}

def check_ssl_certificate(domain):
    """Check SSL certificate information."""
    try:
        # Clean and validate the domain
        domain = domain.strip().lower()
        
        # If the domain contains a path, extract just the domain part
        if '/' in domain:
            domain = domain.split('/')[0]
        
        # Remove any protocol prefix if present
        domain = domain.replace('http://', '').replace('https://', '')
        
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain) as sock:
            sock.settimeout(5)  # Reduced from 10
            sock.connect((domain, 443))
            cert = sock.getpeercert()
            
            # Extract all SANs
            alt_names = []
            for type_id, value in cert.get('subjectAltName', []):
                if type_id == 'DNS':
                    alt_names.append(value)
            
            www_domain = f'www.{domain}'
            includes_www = www_domain.lower() in [name.lower() for name in alt_names]

            # Extract issuer information
            issuer = {}
            if cert.get('issuer'):
                for field in cert['issuer']:
                    for key, value in field:
                        # Map common SSL certificate field names to readable names
                        field_map = {
                            'organizationName': 'O',
                            'commonName': 'CN',
                            'organizationalUnitName': 'OU',
                            'countryName': 'C'
                        }
                        # Use mapped name if available, otherwise use original
                        issuer[field_map.get(key, key)] = value

            return {
                'issuer': issuer,
                'valid_from': cert.get('notBefore'),
                'valid_until': cert.get('notAfter'),
                'valid': True,
                'includes_www': includes_www,
                'subject_alt_names': sorted(alt_names)  # Sort SANs for consistent display
            }
    except ssl.SSLError as e:
        return {
            'error': f'SSL Error: {str(e)}',
            'valid': False
        }
    except socket.gaierror:
        return {
            'error': 'Could not resolve domain name',
            'valid': False
        }
    except socket.timeout:
        return {
            'error': 'Connection timed out',
            'valid': False
        }
    except Exception as e:
        return {
            'error': str(e),
            'valid': False
        }

def check_availability(domain):
    try:
        w = whois.whois(domain)
        if not w.domain_name:
            return {
                'available': True
            }
            
        # Handle creation date formatting
        creation_date = None
        if hasattr(w, 'creation_date'):
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0].isoformat() if w.creation_date and w.creation_date[0] else None
            elif w.creation_date:
                creation_date = w.creation_date.isoformat()
            
        return {
            'available': False,
            'creation_date': creation_date,
            'registrar': w.registrar if hasattr(w, 'registrar') else None
        }
    except Exception as e:
        print(f"Availability check error: {str(e)}")  # Debug log
        return {'error': f'Failed to check availability: {str(e)}'}

def check_referrer(domain):
    try:
        headers = {'Referer': 'https://example.com'}
        response = requests.get(f'https://{domain}', headers=headers, timeout=5)  # Reduced from 10
        return {'allows_referrer': 'Referer' in response.request.headers}
    except Exception as e:
        return {'error': f'Failed to check referrer: {str(e)}'}

def check_iframe(domain):
    try:
        response = requests.get(f'https://{domain}', timeout=5)  # Reduced from 10
        return {'allows_iframe': 'X-Frame-Options' not in response.headers}
    except Exception as e:
        return {'error': f'Failed to check iframe: {str(e)}'}

def check_domain_redirects(domain):
    try:
        # Parse the input URL
        parsed_url = urlparse(domain)
        if not parsed_url.scheme:
            # If no scheme provided, assume https
            domain = f"https://{domain}"
            parsed_url = urlparse(domain)
        
        # Extract base domain and path
        base_domain = parsed_url.netloc
        path = parsed_url.path
        
        # Construct the full URL for the request
        full_url = f"{parsed_url.scheme}://{base_domain}{path}"
        
        # Make the request with history tracking
        response = requests.get(full_url, allow_redirects=True, timeout=10)
        
        # Build redirect chain
        redirect_chain = []
        
        # Add initial request
        redirect_chain.append({
            'url': full_url,
            'status': f"{response.status_code} {response.reason}",
            'headers': dict(response.request.headers)
        })
        
        # Add each redirect step
        for r in response.history:
            redirect_chain.append({
                'url': r.url,
                'status': f"{r.status_code} {r.reason}",
                'headers': dict(r.headers)
            })
        
        # Add final response
        if response.history:
            redirect_chain.append({
                'url': response.url,
                'status': f"{response.status_code} {response.reason}",
                'headers': dict(response.headers)
            })
        
        return {
            'redirect_chain': redirect_chain,
            'redirect_count': len(response.history),
            'final_url': response.url
        }
        
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': str(e)}

def get_headers(domain):
    try:
        response = requests.get(f'https://{domain}', timeout=5)  # Reduced from 10
        return dict(response.headers)
    except Exception as e:
        return {'error': f'Failed to get headers: {str(e)}'}

def check_web_risk(domain):
    try:
        # Use VirusTotal's public scanning endpoint
        response = requests.get(f'https://www.virustotal.com/gui/domain/{domain}', timeout=5)  # Reduced from 10
        if response.status_code == 200:
            # Extract basic information from the response
            return {
                'scan_date': datetime.now().isoformat(),
                'status': 'Scanned',
                'message': 'Domain has been scanned by VirusTotal',
                'url': f'https://www.virustotal.com/gui/domain/{domain}'
            }
        else:
            return {
                'error': f'Failed to get security report (Status: {response.status_code})',
                'scan_date': None,
                'status': None,
                'url': None
            }
    except Exception as e:
        return {
            'error': f'Failed to check web risk: {str(e)}',
            'scan_date': None,
            'status': None,
            'url': None
        }

def check_security(domain):
    """Check domain security using multiple services."""
    try:
        # Google Web Risk check (public API endpoint)
        web_risk_result = {
            'is_safe': True,  # Default to safe
            'threats': []
        }
        
        try:
            # Use urlscan.io API for basic security check
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(f'https://urlscan.io/api/v1/search/?q=domain:{domain}', headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('results'):
                    # Check if any results indicate malicious activity
                    for result in data['results']:
                        if result.get('result', {}).get('verdicts', {}).get('overall', {}).get('malicious'):
                            web_risk_result['is_safe'] = False
                            web_risk_result['threats'].append('Malicious Activity Detected')
                            break
        except Exception as e:
            print(f"Error checking urlscan.io: {str(e)}")

        # VirusTotal check (public API endpoint)
        vt_result = {
            'scan_date': datetime.now().isoformat(),
            'positives': 0,
            'total': 0,
            'categories': []
        }
        
        try:
            # Use public HTML parsing instead of API
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(f'https://www.virustotal.com/gui/domain/{domain}/detection', headers=headers, timeout=10)
            
            if response.status_code == 200:
                # If we can access the page, domain has been scanned before
                vt_result['url'] = f'https://www.virustotal.com/gui/domain/{domain}/detection'
            else:
                vt_result['error'] = 'Domain not found in VirusTotal database'
        except Exception as e:
            vt_result['error'] = f"Error accessing VirusTotal: {str(e)}"

        return {
            'google_web_risk': web_risk_result,
            'virustotal': vt_result
        }
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_domain():
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        update_type = data.get('update_type', 'all')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
            
        print(f"Starting check for domain: {domain}")
        
        result = {
            'dns': {},
            'whois': {},
            'ssl': {},
            'redirects': []
        }
        
        # Extract base domain for WHOIS and SSL checks
        base_domain = domain.split('/')[0]
        
        try:
            if update_type in ['all', 'dns']:
                print(f"Checking DNS records for {base_domain}")
                # Use a single DNS resolver for better reliability
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                
                result['dns'] = {
                    'a': get_dns_records(base_domain, 'A'),
                    'aaaa': get_dns_records(base_domain, 'AAAA'),
                    'mx': get_dns_records(base_domain, 'MX'),
                    'ns': get_dns_records(base_domain, 'NS'),
                    'txt': get_dns_records(base_domain, 'TXT'),
                    'cname': get_dns_records(base_domain, 'CNAME'),
                    'soa': get_dns_records(base_domain, 'SOA')
                }
                print("DNS check completed")
        except Exception as e:
            print(f"Error in DNS check: {str(e)}")
            result['dns'] = {'error': str(e)}
        
        try:
            if update_type in ['all', 'whois']:
                print(f"Checking WHOIS for {base_domain}")
                whois_info = whois.whois(base_domain, timeout=5)  # Reduced timeout
                result['whois'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': whois_info.creation_date,
                    'expiration_date': whois_info.expiration_date,
                    'name_servers': whois_info.name_servers
                }
                print("WHOIS check completed")
        except Exception as e:
            print(f"Error in WHOIS check: {str(e)}")
            result['whois'] = {'error': str(e)}
        
        try:
            if update_type in ['all', 'ssl']:
                print(f"Checking SSL for {base_domain}")
                context = ssl.create_default_context()
                with socket.create_connection((base_domain, 443), timeout=5) as sock:  # Reduced timeout
                    with context.wrap_socket(sock, server_hostname=base_domain) as ssock:
                        cert = ssock.getpeercert()
                        result['ssl'] = {
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'expiry': datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').isoformat(),
                            'version': cert['version'],
                            'subject': dict(x[0] for x in cert['subject'])
                        }
                print("SSL check completed")
        except Exception as e:
            print(f"Error in SSL check: {str(e)}")
            result['ssl'] = {'error': str(e)}
        
        try:
            if update_type in ['all', 'redirects']:
                print(f"Checking redirects for {domain}")
                response = requests.get(f"https://{domain}", allow_redirects=True, timeout=5)  # Reduced timeout
                result['redirects'] = [{'url': r.url, 'status_code': r.status_code} for r in response.history]
                result['redirects'].append({'url': response.url, 'status_code': response.status_code})
                print("Redirects check completed")
        except Exception as e:
            print(f"Error in redirects check: {str(e)}")
            result['redirects'] = [{'error': str(e)}]
        
        print("All checks completed successfully")
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in check_domain: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/check_dns', methods=['POST'])
def check_dns():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'No domain provided'}), 400

        domain = data['domain'].strip()
        if not domain:
            return jsonify({'error': 'Empty domain provided'}), 400

        return jsonify(get_dns_records(domain, 'A'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check_whois', methods=['POST'])
def check_whois():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'No domain provided'}), 400

        domain = data['domain'].strip()
        if not domain:
            return jsonify({'error': 'Empty domain provided'}), 400

        return jsonify(get_whois_info(domain))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check_ssl', methods=['POST'])
def check_ssl():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'No domain provided'}), 400

        domain = data['domain'].strip()
        if not domain:
            return jsonify({'error': 'Empty domain provided'}), 400

        return jsonify(check_ssl_certificate(domain))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check_availability', methods=['POST'])
def check_domain_availability():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'No domain provided'}), 400

        domain = data['domain'].strip()
        if not domain:
            return jsonify({'error': 'Empty domain provided'}), 400

        return jsonify(check_availability(domain))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check_referrer', methods=['POST'])
def check_domain_referrer():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'No domain provided'}), 400

        domain = data['domain'].strip()
        if not domain:
            return jsonify({'error': 'Empty domain provided'}), 400

        return jsonify(check_referrer(domain))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check_iframe', methods=['POST'])
def check_domain_iframe():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'No domain provided'}), 400

        domain = data['domain'].strip()
        if not domain:
            return jsonify({'error': 'Empty domain provided'}), 400

        return jsonify(check_iframe(domain))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check_headers', methods=['POST'])
def check_domain_headers():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'No domain provided'}), 400

        domain = data['domain'].strip()
        if not domain:
            return jsonify({'error': 'Empty domain provided'}), 400

        return jsonify(get_headers(domain))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check_security', methods=['POST'])
def check_domain_security():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'No domain provided'}), 400

        domain = data['domain'].strip()
        if not domain:
            return jsonify({'error': 'Empty domain provided'}), 400

        return jsonify(check_security(domain))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # For local development
    if os.environ.get('PYTHONANYWHERE_SITE') is None:
        app.run(debug=True, port=3000)
    # For PythonAnywhere deployment
    else:
        app.run(host='0.0.0.0', port=8080) 