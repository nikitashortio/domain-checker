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
        # Set a default timeout for the entire function
        socket.setdefaulttimeout(10)
        
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
    except socket.timeout:
        return {'error': 'WHOIS request timed out'}
    except Exception as e:
        return {'error': f'Failed to get WHOIS info: {str(e)}'}
    finally:
        # Reset the default timeout
        socket.setdefaulttimeout(None)

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
        
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Create socket and wrap with SSL
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
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
                            # Store the original key for direct access
                            issuer[key] = value
                            # Also store with mapped name for display
                            field_map = {
                                'organizationName': 'Organization',
                                'commonName': 'Common Name',
                                'organizationalUnitName': 'Unit',
                                'countryName': 'Country',
                                'stateOrProvinceName': 'State',
                                'localityName': 'City'
                            }
                            if key in field_map:
                                issuer[field_map[key]] = value

                # Get validity dates
                valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                # Check if certificate is valid
                now = datetime.now()
                is_valid = valid_from <= now <= valid_until

                return {
                    'issuer': issuer,
                    'valid_from': valid_from.isoformat(),
                    'valid_until': valid_until.isoformat(),
                    'valid': is_valid,
                    'includes_www': includes_www,
                    'subject_alt_names': sorted(alt_names),  # Sort SANs for consistent display
                    'version': cert.get('version', 'Unknown'),
                    'serial_number': cert.get('serialNumber', 'Unknown')
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
        # Set a default timeout for the entire function
        socket.setdefaulttimeout(10)
        
        w = whois.whois(domain)
        
        # Check if domain exists
        if not w.domain_name:
            return {
                'available': True,
                'message': 'Domain is available for registration',
                'creation_date': None,
                'expiration_date': None,
                'registrar': None,
                'name_servers': None
            }
            
        # Format dates
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        
        # Format name servers
        name_servers = w.name_servers
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        elif isinstance(name_servers, list):
            name_servers = [ns.lower() for ns in name_servers]
        
        # Check if domain is premium
        premium_info = None
        try:
            # This is a simplified check. In a real implementation,
            # you would want to check with actual registrars
            if len(domain.split('.')[0]) <= 3:
                premium_info = {
                    'is_premium': True,
                    'reason': 'Short domain name (3 characters or less)'
                }
        except Exception:
            pass
        
        return {
            'available': False,
            'message': 'Domain is already registered',
            'registrar': w.registrar,
            'creation_date': creation_date.isoformat() if creation_date else None,
            'expiration_date': expiration_date.isoformat() if expiration_date else None,
            'registrant': w.registrant or w.name,
            'registrant_country': w.registrant_country,
            'name_servers': name_servers,
            'status': w.status if isinstance(w.status, list) else [w.status] if w.status else None,
            'premium_info': premium_info
        }
    except socket.timeout:
        return {'error': 'WHOIS request timed out'}
    except Exception as e:
        return {'error': f'Failed to check availability: {str(e)}'}
    finally:
        # Reset the default timeout
        socket.setdefaulttimeout(None)

def check_referrer(domain):
    try:
        headers = {'Referer': 'https://example.com'}
        response = requests.get(f'https://{domain}', headers=headers, timeout=5)
        
        # Get all headers from the response
        response_headers = dict(response.headers)
        
        # Check for specific referrer-related headers
        referrer_policy = response_headers.get('Referrer-Policy', 'Not Set')
        
        # Perform test with different referrer values
        test_results = {}
        
        # Test with HTTPS referrer
        try:
            https_response = requests.get(f'https://{domain}', headers={'Referer': 'https://example.com'}, timeout=5)
            test_results['https_referrer'] = {
                'success': True,
                'message': 'HTTPS referrer accepted'
            }
        except Exception as e:
            test_results['https_referrer'] = {
                'success': False,
                'message': str(e)
            }
        
        # Test with HTTP referrer
        try:
            http_response = requests.get(f'https://{domain}', headers={'Referer': 'http://example.com'}, timeout=5)
            test_results['http_referrer'] = {
                'success': True,
                'message': 'HTTP referrer accepted'
            }
        except Exception as e:
            test_results['http_referrer'] = {
                'success': False,
                'message': str(e)
            }
        
        return {
            'status': referrer_policy,
            'headers': response_headers,
            'test_results': test_results
        }
    except Exception as e:
        return {'error': f'Failed to check referrer: {str(e)}'}

def check_iframe(domain):
    try:
        response = requests.get(f'https://{domain}', timeout=5)
        headers = dict(response.headers)
        
        # Check X-Frame-Options header
        x_frame_options = headers.get('X-Frame-Options', 'Not Set')
        
        # Check Content-Security-Policy header for frame-ancestors directive
        csp = headers.get('Content-Security-Policy', '')
        frame_ancestors = 'Not Set'
        if csp:
            for directive in csp.split(';'):
                if 'frame-ancestors' in directive.lower():
                    frame_ancestors = directive.strip()
                    break
        
        # Get connection header
        connection = headers.get('Connection', 'Not Set')
        
        # Determine if iframes are allowed
        allowed = True
        message = []
        
        if x_frame_options:
            if x_frame_options.upper() in ['DENY', 'SAMEORIGIN']:
                allowed = False
                message.append(f'X-Frame-Options is set to {x_frame_options}')
        
        if frame_ancestors and 'none' in frame_ancestors.lower():
            allowed = False
            message.append('frame-ancestors directive is set to none')
        
        return {
            'allowed': allowed,
            'headers': {
                'X-Frame-Options': x_frame_options,
                'Content-Security-Policy': csp,
                'Connection': connection
            },
            'frame_ancestors_directive': frame_ancestors,
            'message': ' and '.join(message) if message else ('Iframe embedding is ' + ('blocked' if not allowed else 'allowed'))
        }
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
        # Add User-Agent and other headers to avoid being blocked
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Make request with headers
        response = requests.get(f'https://{domain}', headers=headers, timeout=10, allow_redirects=True, verify=True)
        
        # Get all headers
        response_headers = dict(response.headers)
        
        # Convert all header values to strings and ensure proper formatting
        headers_dict = {}
        for key, value in response_headers.items():
            if isinstance(value, (list, tuple)):
                headers_dict[key] = ', '.join(map(str, value))
            else:
                headers_dict[key] = str(value)
        
        # Add response status code and message
        headers_dict['Status-Code'] = str(response.status_code)
        headers_dict['Status-Message'] = response.reason
        
        return headers_dict
    except requests.exceptions.SSLError as e:
        return {'error': f'SSL Error: {str(e)}'}
    except requests.exceptions.RequestException as e:
        return {'error': f'Request Error: {str(e)}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}

def check_web_risk(domain):
    try:
        # VirusTotal API configuration
        vt_api_key = '7b4e00ad6eb1cea6c55c31af621a0b7647704712914c62b8e9a1f4302c007e78'  # Hardcoded API key
        vt_base_url = 'https://www.virustotal.com/vtapi/v2'
        
        # Ensure domain has protocol
        if not domain.startswith(('http://', 'https://')):
            domain = f'https://{domain}'
        
        # First, submit the domain for scanning if it hasn't been scanned recently
        scan_url = f'{vt_base_url}/url/scan'
        scan_params = {'apikey': vt_api_key, 'url': domain}
        
        try:
            scan_response = requests.post(scan_url, data=scan_params, timeout=10)
            scan_response.raise_for_status()  # Raise an exception for bad status codes
            
            scan_result = scan_response.json()
            resource = scan_result.get('resource')
            
            # Now get the report
            report_url = f'{vt_base_url}/url/report'
            report_params = {'apikey': vt_api_key, 'resource': resource}
            
            report_response = requests.get(report_url, params=report_params, timeout=10)
            report_response.raise_for_status()  # Raise an exception for bad status codes
            
            report = report_response.json()
            
            # Check if the report indicates the resource was not found
            if report.get('response_code') == 0:
                return {
                    'scan_date': None,
                    'virustotal': {
                        'status': 'Not found',
                        'score': 100,  # Default to 100 if not found
                        'positives': 0,
                        'total_scanners': 0,
                        'url': f'https://www.virustotal.com/gui/domain/{domain.replace("https://", "").replace("http://", "")}',
                        'scans': {}
                    }
                }
            
            # Calculate score based on positives and total scanners
            total_scanners = report.get('total', 0)
            positives = report.get('positives', 0)
            score = max(0, 100 - (positives / total_scanners * 100)) if total_scanners > 0 else 100
            
            # Get scan date
            scan_date = report.get('scan_date')
            if scan_date:
                try:
                    scan_date = datetime.strptime(scan_date, '%Y-%m-%d %H:%M:%S').isoformat()
                except ValueError:
                    try:
                        scan_date = datetime.fromtimestamp(scan_date).isoformat()
                    except (ValueError, TypeError):
                        scan_date = None
            
            # Process scan results
            scans = {}
            for scanner, result in report.get('scans', {}).items():
                if isinstance(result, dict):
                    scans[scanner] = {
                        'detected': result.get('detected', False),
                        'result': result.get('result', 'Clean'),
                        'version': result.get('version', ''),
                        'update': result.get('update', '')
                    }
            
            return {
                'scan_date': scan_date,
                'virustotal': {
                    'status': 'Scanned',
                    'score': round(score, 2),
                    'positives': positives,
                    'total_scanners': total_scanners,
                    'url': f'https://www.virustotal.com/gui/domain/{domain.replace("https://", "").replace("http://", "")}',
                    'scans': scans
                }
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'error': f'VirusTotal API request failed: {str(e)}',
                'scan_date': None,
                'virustotal': None
            }
            
    except Exception as e:
        return {
            'error': f'Failed to check web risk: {str(e)}',
            'scan_date': None,
            'virustotal': None
        }

def check_security(domain):
    """Check domain security using multiple services and calculate an overall security score."""
    try:
        security_info = {
            'score': 0,
            'max_score': 100,
            'issues': [],
            'recommendations': []
        }
        
        # Check SSL/TLS (30 points)
        ssl_info = check_ssl_certificate(domain)
        if 'error' not in ssl_info:
            security_info['ssl'] = ssl_info
            if ssl_info['valid']:
                security_info['score'] += 30
            else:
                security_info['issues'].append('Invalid SSL certificate')
                security_info['recommendations'].append('Install a valid SSL certificate')
        
        # Check security headers (40 points)
        headers = get_headers(domain)
        if 'error' not in headers:
            security_info['headers'] = headers
            
            # Important security headers (6-7 points each)
            security_headers = {
                'Strict-Transport-Security': 'Implement HSTS to enforce HTTPS',
                'Content-Security-Policy': 'Implement CSP to prevent XSS attacks',
                'X-Frame-Options': 'Set X-Frame-Options to prevent clickjacking',
                'X-Content-Type-Options': 'Set X-Content-Type-Options to prevent MIME-type sniffing',
                'X-XSS-Protection': 'Enable browser XSS protection',
                'Referrer-Policy': 'Set a referrer policy to control information leakage'
            }
            
            for header, recommendation in security_headers.items():
                if header in headers:
                    security_info['score'] += 7
                else:
                    security_info['issues'].append(f'Missing {header} header')
                    security_info['recommendations'].append(recommendation)
        
        # Check web risk (30 points)
        web_risk = check_web_risk(domain)
        if 'error' not in web_risk:
            security_info['web_risk'] = web_risk
            
            # Add Google Web Risk score (15 points)
            if web_risk.get('google_web_risk', {}).get('status') == 'SAFE':
                security_info['score'] += 15
            else:
                security_info['issues'].append('Domain flagged by Google Web Risk')
                security_info['recommendations'].append('Investigate and resolve Google Web Risk flags')
            
            # Add VirusTotal score (15 points)
            vt_score = web_risk.get('virustotal', {}).get('score', 0)
            security_info['score'] += min(15, vt_score * 15 / 100)  # Scale VT score to max 15 points
            
            if vt_score < 80:
                security_info['issues'].append('Low VirusTotal reputation score')
                security_info['recommendations'].append('Investigate and improve domain reputation')
        
        # Ensure score doesn't exceed 100
        security_info['score'] = min(100, security_info['score'])
        
        # Calculate risk level
        if security_info['score'] >= 80:
            security_info['risk_level'] = 'LOW'
        elif security_info['score'] >= 60:
            security_info['risk_level'] = 'MEDIUM'
        else:
            security_info['risk_level'] = 'HIGH'
        
        return security_info
        
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_domain():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
            
        domain = data.get('domain', '').strip()
        update_type = data.get('update_type', 'all')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
            
        print(f"Starting check for domain: {domain}")
        
        # Initialize result dictionary
        result = {
            'dns': {},
            'whois': {},
            'ssl': {},
            'availability': {},
            'referrer': {},
            'iframe': {},
            'redirects': {},
            'headers': {},
            'security': {}
        }
        
        # Clean domain input
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc
        
        try:
            if update_type == 'all' or update_type == 'dns':
                dns_record_type = data.get('dns_record_type', 'all')
                if dns_record_type == 'all':
                    # If 'all' is specified, get all record types
                    result['dns'] = {
                        'a': get_dns_records(domain, 'A'),
                        'aaaa': get_dns_records(domain, 'AAAA'),
                        'mx': get_dns_records(domain, 'MX'),
                        'ns': get_dns_records(domain, 'NS'),
                        'txt': get_dns_records(domain, 'TXT'),
                        'cname': get_dns_records(domain, 'CNAME'),
                        'soa': get_dns_records(domain, 'SOA'),
                        'caa': get_dns_records(domain, 'CAA')
                    }
                else:
                    # Get specific record type
                    result['dns'] = get_dns_records(domain, dns_record_type.upper())
            
            if update_type == 'all' or update_type == 'whois':
                result['whois'] = get_whois_info(domain)
            
            if update_type == 'all' or update_type == 'ssl':
                result['ssl'] = check_ssl_certificate(domain)
            
            if update_type == 'all' or update_type == 'availability':
                result['availability'] = check_availability(domain)
            
            if update_type == 'all' or update_type == 'referrer':
                result['referrer'] = check_referrer(domain)
            
            if update_type == 'all' or update_type == 'iframe':
                result['iframe'] = check_iframe(domain)
            
            if update_type == 'all' or update_type == 'redirects':
                result['redirects'] = check_domain_redirects(domain)
            
            if update_type == 'all' or update_type == 'headers':
                result['headers'] = get_headers(domain)
            
            if update_type == 'all' or update_type == 'security':
                result['security'] = check_web_risk(domain)
            
            return jsonify(result)
            
        except Exception as e:
            print(f"Error checking domain: {str(e)}")
            # If there's an error with a specific check, return what we have
            return jsonify(result)
            
    except Exception as e:
        print(f"Error processing request: {str(e)}")
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
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True, port=3000)
    # For production deployment
    else:
        port = int(os.environ.get('PORT', 8080))
        app.run(host='0.0.0.0', port=port) 