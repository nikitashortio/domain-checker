// Add this at the beginning of the file
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.role = 'alert';
    alertDiv.innerHTML = `
        <i class="fas fa-${type === 'danger' ? 'exclamation-circle' : 'info-circle'}"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    const container = document.querySelector('.container');
    container.insertBefore(alertDiv, container.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        alertDiv.classList.remove('show');
        setTimeout(() => alertDiv.remove(), 150);
    }, 5000);
}

// Add this at the beginning of the file
let dnsResults = {
    cloudflare: null,
    google: null,
    quad9: null
};

// Add cache for other tabs
let tabResults = {
    whois: null,
    ssl: null,
    availability: null,
    referrer: null,
    iframe: null,
    redirects: null,
    headers: null,
    security: null
};

// Add these functions at the beginning of the file, after the variable declarations
function clearDNSResults() {
    const resolvers = ['cloudflare', 'google', 'quad9'];
    resolvers.forEach(resolver => {
        const container = document.getElementById(`dns-results-${resolver}`);
        if (container) {
            container.innerHTML = '<tr class="no-records"><td colspan="4">No records found</td></tr>';
        }
    });
}

function clearWHOISResults() {
    const element = document.getElementById('whois-results');
    if (element) {
        element.innerHTML = '<div class="whois-info">No WHOIS information available</div>';
    }
}

function clearSSLResults() {
    const element = document.getElementById('ssl-results');
    if (element) {
        element.innerHTML = '<div class="ssl-info">No SSL information available</div>';
    }
}

function clearRedirectResults() {
    const element = document.getElementById('redirects-info');
    if (element) {
        element.innerHTML = '<div class="redirects-info">No redirect information available</div>';
    }
}

// Add this function to handle tab activation
function activateTab(tabId) {
    // Remove active class from all tabs and panes
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active', 'show');
        pane.style.display = 'none';
    });
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    // Activate the selected tab
    const selectedPane = document.getElementById(tabId);
    const selectedTab = document.querySelector(`[data-bs-target="#${tabId}"]`);
    
    if (selectedPane) {
        selectedPane.classList.add('active', 'show');
        selectedPane.style.display = 'block';
    }
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // If switching to DNS tab and domain is entered, ensure records are displayed
    if (tabId === 'dns' && document.body.classList.contains('domain-entered')) {
        // Show DNS controls and resolvers
        const dnsElements = document.querySelectorAll('.dns-controls, .dns-resolvers, .dns-table-wrapper, .dns-table, #dns .nav-pills');
        dnsElements.forEach(element => {
            if (element) element.style.display = 'block';
        });

        // Always switch to Cloudflare resolver when activating DNS tab
        switchDNSResolver('cloudflare');
        
        // If we have DNS results stored, update the display
        if (dnsResults) {
            updateDNSResults(dnsResults);
        }
    }
}

// Add this function to handle DNS resolver tab activation
function activateDnsTab(tabId) {
    // Get all DNS resolver tabs and panes
    const dnsTabPanes = document.querySelectorAll('#dns .tab-pane');
    const dnsNavLinks = document.querySelectorAll('#dns .nav-pills .nav-link');
    
    // Remove active class from all tabs and panes
    dnsTabPanes.forEach(pane => {
        pane.classList.remove('active', 'show');
        pane.style.display = 'none';
    });
    
    dnsNavLinks.forEach(link => {
        link.classList.remove('active');
    });
    
    // Activate the selected tab and pane
    const selectedPane = document.getElementById(tabId);
    const selectedLink = document.querySelector(`[data-bs-target="#${tabId}"]`);
    
    if (selectedPane) {
        selectedPane.classList.add('active', 'show');
        selectedPane.style.display = 'block';
    }
    
    if (selectedLink) {
        selectedLink.classList.add('active');
    }
}

// Add this function to handle DNS resolver tab switching
function switchDNSResolver(resolverId) {
    // Remove active class from all resolver tabs and panes
    document.querySelectorAll('#dns .tab-pane').forEach(pane => {
        pane.classList.remove('active', 'show');
        pane.style.display = 'none';
    });
    
    document.querySelectorAll('#dns .nav-pills .nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    // Activate the selected resolver tab
    const selectedPane = document.getElementById(resolverId);
    const selectedTab = document.querySelector(`[data-bs-target="#${resolverId}"]`);
    
    if (selectedPane) {
        selectedPane.classList.add('active', 'show');
        selectedPane.style.display = 'block';
    }
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // Update DNS results if we have them
    if (dnsResults) {
        updateDNSResults(dnsResults);
    }
}

// Add event listeners for tab clicks
document.addEventListener('DOMContentLoaded', function() {
    // Initialize with no active tab and hide all tab content
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active', 'show');
        pane.style.display = 'none';
    });
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });

    // Hide DNS controls initially
    const dnsControls = document.querySelector('.dns-controls');
    const dnsResolvers = document.querySelector('.dns-resolvers');
    const dnsTableWrapper = document.querySelector('.dns-table-wrapper');
    const dnsNavPills = document.querySelector('#dns .nav-pills');
    
    if (dnsControls) dnsControls.style.display = 'none';
    if (dnsResolvers) dnsResolvers.style.display = 'none';
    if (dnsTableWrapper) dnsTableWrapper.style.display = 'none';
    if (dnsNavPills) dnsNavPills.style.display = 'none';

    // Add event listeners for main tab clicks
    document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
        tab.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            const target = this.getAttribute('data-bs-target');
            if (!target) return;
            
            const tabId = target.replace('#', '');
            activateTab(tabId);
            updateHintText(tabId);
        });
    });

    // Add event listeners for DNS resolver tab clicks
    document.querySelectorAll('#dns .nav-pills .nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            if (!document.body.classList.contains('domain-entered')) {
                return;
            }
            
            const target = this.getAttribute('data-bs-target');
            if (target) {
                const tabId = target.replace('#', '');
                switchDNSResolver(tabId);
            }
        });
    });

    // Set initial hint text
    updateHintText('dns');
});

function updateHintText(tabId) {
    const hintMessage = document.getElementById('hint-message');
    if (!hintMessage) return;

    const messages = {
        'dns': 'Enter a domain name to check DNS records',
        'whois': 'Enter a domain name to check WHOIS information',
        'ssl': 'Enter a domain name to check SSL certificate',
        'availability': 'Enter a domain name to check domain availability',
        'referrer': 'Enter a domain name to check referrer policy',
        'iframe': 'Enter a domain name to check iframe policy',
        'redirects': 'Enter a domain name to check redirect chain',
        'headers': 'Enter a domain name to check HTTP headers',
        'security': 'Enter a domain name to check security status'
    };

    if (!document.body.classList.contains('domain-entered')) {
        hintMessage.style.display = 'block';
        hintMessage.textContent = messages[tabId] || messages['dns'];
    } else {
        hintMessage.style.display = 'none';
    }
}

// Helper function for date formatting and validation
function formatDate(dateStr, includeTime = true) {
    if (!dateStr) return '-';
    try {
        // Handle array of dates
        if (Array.isArray(dateStr)) {
            dateStr = dateStr[0];
        }
        
        // Convert string date to Date object
        const date = new Date(dateStr);
        if (isNaN(date.getTime())) {
            return dateStr; // Return original string if invalid date
        }
        
        const options = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            ...(includeTime && { hour: '2-digit', minute: '2-digit' })
        };
        return date.toLocaleDateString('en-US', options);
    } catch (e) {
        return dateStr;
    }
}

function getDaysLeft(dateStr) {
    if (!dateStr) return null;
    try {
        const expiryDate = new Date(dateStr);
        const today = new Date();
        const diffTime = expiryDate - today;
        return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    } catch (e) {
        return null;
    }
}

function getEndpointForTab(tabId) {
    const endpoints = {
        'dns-tab': 'dns',
        'whois-tab': 'whois',
        'ssl-tab': 'ssl',
        'availability-tab': 'availability',
        'referrer-tab': 'referrer',
        'iframe-tab': 'iframe',
        'redirects-tab': 'redirects',
        'headers-tab': 'headers',
        'security-tab': 'security'
    };
    return endpoints[tabId] || 'all';
}

function updateTabResults(endpoint, data) {
    console.log(`Updating ${endpoint} tab with data:`, data);
    
    switch(endpoint) {
        case 'dns':
            updateDNSResults(data);
            break;
        case 'whois':
            updateWHOISResults(data);
            break;
        case 'ssl':
            updateSSLResults(data);
            break;
        case 'availability':
            updateAvailabilityResults(data);
            break;
        case 'referrer':
            updateReferrerResults(data);
            break;
        case 'iframe':
            updateIframeResults(data);
            break;
        case 'redirects':
            updateRedirectsResults(data);
            break;
        case 'headers':
            updateHeadersResults(data);
            break;
        case 'security':
            updateSecurityResults(data);
            break;
        default:
            console.error(`Unknown endpoint: ${endpoint}`);
    }
}

// Add this function to initialize DNS tab
function initializeDNSTab() {
    const dnsControls = document.querySelector('.dns-controls');
    const dnsResolvers = document.querySelector('.dns-resolvers');
    const dnsTableWrapper = document.querySelector('.dns-table-wrapper');
    
    // Show DNS controls and resolvers
    if (dnsControls) dnsControls.style.display = 'block';
    if (dnsResolvers) dnsResolvers.style.display = 'block';
    if (dnsTableWrapper) dnsTableWrapper.style.display = 'block';
    
    // Initialize first DNS resolver tab
    const firstDnsTab = document.querySelector('#dns .nav-pills .nav-link');
    if (firstDnsTab) {
        const target = firstDnsTab.getAttribute('data-bs-target');
        if (target) {
            const tabId = target.replace('#', '');
            const tabPane = document.getElementById(tabId);
            const navLinks = document.querySelectorAll('#dns .nav-pills .nav-link');
            
            // Remove active class from all tabs and panes
            document.querySelectorAll('#dns .tab-pane').forEach(pane => {
                pane.classList.remove('active', 'show');
                pane.style.display = 'none';
            });
            
            navLinks.forEach(link => {
                link.classList.remove('active');
            });
            
            // Activate the first tab
            if (tabPane) {
                tabPane.classList.add('active', 'show');
                tabPane.style.display = 'block';
            }
            
            firstDnsTab.classList.add('active');
        }
    }
}

function updateDNSResults(data) {
    console.log('Starting updateDNSResults with data:', data);
    const resolvers = ['cloudflare', 'google', 'quad9'];
    const selectedType = document.getElementById('dnsRecordType').value;
    const recordTypes = selectedType === 'all' ? ['a', 'aaaa', 'mx', 'ns', 'txt', 'cname', 'soa'] : [selectedType.toLowerCase()];
    let domain = document.getElementById('domain').value.trim();
    
    // Extract root domain from URL
    if (domain.startsWith(('http://', 'https://'))) {
        domain = new URL(domain).hostname;
    } else if (domain.includes('/')) {
        domain = domain.split('/')[0];
    }
    domain = domain.split('?')[0].split('#')[0].trim();
    
    // Show DNS controls and resolvers
    const dnsControls = document.querySelector('.dns-controls');
    const dnsResolvers = document.querySelector('.dns-resolvers');
    const dnsTableWrapper = document.querySelector('.dns-table-wrapper');
    const dnsTab = document.getElementById('dns');
    
    // Ensure all DNS-related elements are visible
    if (dnsControls) dnsControls.style.display = 'block';
    if (dnsResolvers) dnsResolvers.style.display = 'block';
    if (dnsTableWrapper) dnsTableWrapper.style.display = 'block';
    if (dnsTab) dnsTab.style.display = 'block';
    
    // Handle error case
    if (!data || data.error) {
        resolvers.forEach(resolver => {
            const container = document.getElementById(`dns-results-${resolver}`);
            if (container) {
                container.innerHTML = `
                    <tr class="error-row">
                        <td colspan="4">
                            <div class="alert alert-danger">
                                <i class="fas fa-exclamation-circle"></i>
                                ${data?.error || 'No DNS data available'}
                            </div>
                        </td>
                    </tr>`;
            }
        });
        return;
    }
    
    // Store the new results
    dnsResults = data;
    
    // Update the UI for each resolver
    resolvers.forEach(resolver => {
        let tableContent = '';
        let hasRecords = false;
        
        recordTypes.forEach(type => {
            const records = data[type];
            // Skip if records is not an array or is undefined
            if (!Array.isArray(records)) {
                console.log(`No records found for type ${type}`);
                return;
            }
            
            records.forEach(record => {
                if (record && record.resolver === resolver) {
                    hasRecords = true;
                    tableContent += `
                        <tr data-type="${type.toUpperCase()}">
                            <td>${type.toUpperCase()}</td>
                            <td>${domain}</td>
                            <td>${record.value || ''}</td>
                            <td>${record.ttl || ''}</td>
                        </tr>`;
                }
            });
        });

        const container = document.getElementById(`dns-results-${resolver}`);
        if (container) {
            if (hasRecords) {
                container.innerHTML = tableContent;
            } else {
                container.innerHTML = `<tr class="no-records"><td colspan="4">No ${selectedType === 'all' ? '' : selectedType.toUpperCase() + ' '}records found</td></tr>`;
            }
        }
    });

    // Ensure the active DNS resolver tab is visible
    const activeDnsTab = document.querySelector('#dns .nav-pills .nav-link.active');
    if (activeDnsTab) {
        const target = activeDnsTab.getAttribute('data-bs-target');
        if (target) {
            const tabId = target.replace('#', '');
            activateDnsTab(tabId);
        }
    } else {
        // If no active tab, activate the first one
        const firstDnsTab = document.querySelector('#dns .nav-pills .nav-link');
        if (firstDnsTab) {
            const target = firstDnsTab.getAttribute('data-bs-target');
            if (target) {
                const tabId = target.replace('#', '');
                activateDnsTab(tabId);
            }
        }
    }
}

function updateWHOISResults(data) {
    const element = document.getElementById('whois-results');
    let html = '<div class="whois-info">';
    
    if (data.error) {
        html += `<div class="alert alert-danger">${data.error}</div>`;
    } else {
        const fieldsToShow = {
            'registrar': 'Registrar',
            'creation_date': 'Created Date',
            'expiration_date': 'Expiry Date',
            'updated_date': 'Updated Date',
            'status': 'Status',
            'nameservers': 'Nameservers',
            'ip': 'IP Address',
            'ip_location': 'IP Location',
            'ip_org': 'IP Organization'
        };

        for (const [key, label] of Object.entries(fieldsToShow)) {
            let value = data[key];
            
            // Special handling for different field types
            if (key === 'status') {
                // Strip HTML from status values and get only the status text
                value = Array.isArray(value) ? value.map(status => {
                    // Extract just the status text before the link
                    return status.split(' <a')[0].trim();
                }).join(', ') : value;
            } else if (key === 'nameservers' && Array.isArray(value)) {
                value = value.join(', ');
            } else if (key === 'ip_location' && typeof value === 'object') {
                value = `${value.city || ''}, ${value.region || ''}, ${value.country || ''}`.replace(/^[, ]+|[, ]+$/g, '');
            }
            
            let valueClass = '';
            if (key === 'expiration_date') {
                const daysLeft = getDaysLeft(value);
                valueClass = daysLeft <= 0 ? 'expired' : 'valid';
            }
            
            // Skip empty values
            if (!value) continue;
            
            // Display the value, using formatDate for date fields
            const displayValue = (key === 'creation_date' || key === 'expiration_date' || key === 'updated_date') ? formatDate(value) : value;
            
            html += `
                <div class="whois-field">
                    <strong>${label}</strong>
                    <span class="${valueClass}">${displayValue}</span>
                </div>`;
        }
    }
    
    html += '</div>';
    element.innerHTML = html;
}

function updateSSLResults(data) {
    const element = document.getElementById('ssl-results');
    let html = '<div class="ssl-info">';
    
    if (data.error) {
        html += `<div class="alert alert-danger">${data.error}</div>`;
    } else {
        // Format issuer information
        let issuerDisplay = 'Unknown';
        if (data.issuer && Object.keys(data.issuer).length > 0) {
            const issuerParts = [];
            
            // Try to get organization name (both original and mapped keys)
            const orgName = data.issuer.organizationName || data.issuer.Organization;
            if (orgName) {
                issuerParts.push(orgName);
            }
            
            // Try to get common name (both original and mapped keys)
            const commonName = data.issuer.commonName || data.issuer['Common Name'];
            if (commonName && (!orgName || !commonName.includes(orgName))) {
                issuerParts.push(commonName);
            }
            
            // Try to get organizational unit (both original and mapped keys)
            const orgUnit = data.issuer.organizationalUnitName || data.issuer.Unit;
            if (orgUnit && !issuerParts.some(part => part.includes(orgUnit))) {
                issuerParts.push(orgUnit);
            }
            
            // If we have any parts, join them, otherwise show all available issuer information
            if (issuerParts.length > 0) {
                issuerDisplay = issuerParts.join(' - ');
            } else {
                // Show all available issuer information as a fallback
                issuerDisplay = Object.entries(data.issuer)
                    .map(([key, value]) => `${key}: ${value}`)
                    .join(', ');
            }
        }

        const daysLeft = getDaysLeft(data.valid_until);
        let daysLeftClass = 'valid';
        if (daysLeft <= 0) {
            daysLeftClass = 'expired';
        } else if (daysLeft <= 30) {
            daysLeftClass = 'warning';
        }

        html += `
            <div class="ssl-field">
                <strong>Issuer</strong>
                <span>${issuerDisplay}</span>
            </div>
            <div class="ssl-field">
                <strong>Valid From</strong>
                <span>${formatDate(data.valid_from)}</span>
            </div>
            <div class="ssl-field">
                <strong>Valid Until</strong>
                <span>
                    ${formatDate(data.valid_until)}
                    <span class="days-left ${daysLeftClass}">
                        ${daysLeft > 0 ? `${daysLeft} days left` : 'Expired'}
                    </span>
                </span>
            </div>
            <div class="ssl-field">
                <strong>Status</strong>
                <span class="${data.valid ? 'text-success' : 'text-danger'}">
                    ${data.valid ? 'Valid' : 'Invalid'}
                </span>
            </div>`;

        // Add Subject Alternative Names section
        if (data.subject_alt_names && data.subject_alt_names.length > 0) {
            html += `
                <div class="ssl-field">
                    <strong>Subject Alternative Names</strong>
                    <div class="sans-list">
                        ${data.subject_alt_names.map(san => `
                            <div class="san-item">
                                <i class="bi bi-shield-check"></i>
                                ${san}
                            </div>
                        `).join('')}
                    </div>
                </div>`;
        }
    }
    
    html += '</div>';
    element.innerHTML = html;
}

function updateAvailabilityResults(data) {
    console.log('Updating availability results with data:', data);
    const container = document.getElementById('availability-results');
    
    if (data.error) {
        container.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i>
                ${data.error}
            </div>`;
        return;
    }
    
    let html = `
        <div class="availability-info">
            <div class="availability-status ${data.available ? 'available' : 'unavailable'}">
                <i class="fas ${data.available ? 'fa-check-circle' : 'fa-times-circle'}"></i>
                ${data.message || (data.available ? 'Domain is available for registration' : 'Domain is already registered')}
            </div>`;
    
    if (!data.available) {
        html += `
            <div class="availability-details">
                <div class="detail-row">
                    <strong>Registrar:</strong>
                    <span>${data.registrar || 'Unknown'}</span>
                </div>`;
        
        if (data.creation_date) {
            html += `
                <div class="detail-row">
                    <strong>Creation Date:</strong>
                    <span>${formatDate(data.creation_date)}</span>
                </div>`;
        }
        
        if (data.expiration_date) {
            html += `
                <div class="detail-row">
                    <strong>Expiration Date:</strong>
                    <span>${formatDate(data.expiration_date)}</span>
                </div>`;
        }
        
        if (data.registrant) {
            html += `
                <div class="detail-row">
                    <strong>Registrant:</strong>
                    <span>${data.registrant}</span>
                </div>`;
        }
        
        if (data.registrant_country) {
            html += `
                <div class="detail-row">
                    <strong>Registrant Country:</strong>
                    <span>${data.registrant_country}</span>
                </div>`;
        }
        
        if (data.name_servers && data.name_servers.length > 0) {
            html += `
                <div class="detail-row">
                    <strong>Name Servers:</strong>
                    <ul class="name-servers-list">
                        ${data.name_servers.map(ns => `<li>${ns}</li>`).join('')}
                    </ul>
                </div>`;
        }
        
        html += `</div>`;
    }
    
    html += `</div>`;
    container.innerHTML = html;
}

function updateReferrerResults(data) {
    const element = document.getElementById('referrer-results');
    let html = '<div class="referrer-info">';
    
    if (data.error) {
        html += `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i>
                ${data.error}
            </div>`;
    } else {
        // Format the referrer policy status
        const policyStatus = data.status || 'Not Set';
        const policyClass = policyStatus === 'Not Set' ? 'text-warning' : 'text-success';
        
        html += `
            <div class="referrer-field">
                <strong>Referrer Policy:</strong>
                <span class="${policyClass}">${policyStatus}</span>
            </div>`;
            
        // Add headers section if available
        if (data.headers) {
            html += `
                <div class="referrer-field">
                    <strong>Security Headers:</strong>
                    <div class="headers-container">
                        <pre class="headers-pre">${JSON.stringify(data.headers, null, 2)}</pre>
                    </div>
                </div>`;
        }
        
        // Add explanation of the policy
        html += `
            <div class="referrer-field">
                <strong>Policy Explanation:</strong>
                <div class="policy-explanation">
                    ${getReferrerPolicyExplanation(policyStatus)}
                </div>
            </div>`;
            
        // Add test results if available
        if (data.test_results) {
            html += `
                <div class="referrer-field">
                    <strong>Test Results:</strong>
                    <div class="test-results">`;
            
            Object.entries(data.test_results).forEach(([test, result]) => {
                const resultClass = result.success ? 'text-success' : 'text-danger';
                const resultIcon = result.success ? 'fa-check-circle' : 'fa-times-circle';
                
                html += `
                    <div class="test-result-item">
                        <i class="fas ${resultIcon} ${resultClass}"></i>
                        <span>${test}: ${result.message}</span>
                    </div>`;
            });
            
            html += `</div></div>`;
        }
    }
    
    html += '</div>';
    element.innerHTML = html;
}

function getReferrerPolicyExplanation(policy) {
    const explanations = {
        'Not Set': 'No referrer policy is set. This means the browser will send the full URL as the referrer by default.',
        'no-referrer': 'The referrer information will not be sent with any requests.',
        'origin': 'Only the origin (scheme, host, and port) will be sent as the referrer.',
        'same-origin': 'The referrer will only be sent for same-origin requests.',
        'strict-origin': 'The referrer will be sent as the origin for cross-origin requests, and no referrer for downgrades.',
        'strict-origin-when-cross-origin': 'The referrer will be sent as the origin for cross-origin requests, and no referrer for downgrades.',
        'unsafe-url': 'The full URL will be sent as the referrer for all requests (not recommended).'
    };
    
    return explanations[policy] || 'Unknown policy.';
}

function updateIframeResults(data) {
    const iframeResults = document.getElementById('iframe-results');
    if (!iframeResults) return;

    const domain = document.getElementById('domain').value.trim();
    const url = domain.startsWith('http') ? domain : `https://${domain}`;

    if (data.error) {
        iframeResults.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        return;
    }

    const headers = data.headers || {};
    const connectionStatus = headers.Connection || 'Not Set';
    
    let html = '<div class="iframe-info">';
    
    // Add X-Frame-Options status
    html += `
        <div class="iframe-field">
            <strong>X-Frame-Options:</strong>
            <span>${headers['X-Frame-Options'] || 'Not Set'}</span>
        </div>`;

    // Add CSP and Connection Status
    html += `
        <div class="iframe-field">
            <strong>Content Security Policy frame-ancestors:</strong>
            <span>${headers['Content-Security-Policy'] ? extractFrameAncestors(headers['Content-Security-Policy']) : 'Not Set'}</span>
        </div>
        <div class="iframe-field">
            <strong>Connection Status:</strong>
            <span>${connectionStatus}</span>
        </div>
    </div>`;

    // Add live preview section
    html += `
        <div class="iframe-test-container">
            <h4>Live Preview Test</h4>
            <div class="iframe-preview">
                <iframe src="${url}" sandbox="allow-same-origin allow-scripts"></iframe>
            </div>
        </div>`;

    iframeResults.innerHTML = html;
}

function extractFrameAncestors(csp) {
    const frameAncestorsMatch = csp.match(/frame-ancestors\s+([^;]+)/i);
    return frameAncestorsMatch ? frameAncestorsMatch[1] : 'none';
}

async function checkDomain() {
    const domainInput = document.getElementById('domain');
    const domain = domainInput.value.trim();
    
    if (!domain) {
        showAlert('Please enter a domain name', 'warning');
        return;
    }

    // Show loading state
    const checkButton = document.querySelector('button[onclick="checkDomain()"]');
    const originalText = checkButton.innerHTML;
    checkButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking...';
    checkButton.disabled = true;

    try {
        // Add domain-entered class to body
        document.body.classList.add('domain-entered');

        // Get the current active tab
        const activeTab = document.querySelector('.nav-link.active');
        const tabId = activeTab ? activeTab.getAttribute('data-bs-target').replace('#', '') : 'dns';
        
        // Get the endpoint based on the active tab
        const endpoint = getEndpointForTab(tabId);
        
        // Make the API request
        const response = await fetch(`/api/check/${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ domain })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        
        // Update the results for the current tab
        updateTabResults(endpoint, data);
        
        // Show success message
        showAlert('Domain check completed successfully', 'success');
        
    } catch (error) {
        console.error('Error:', error);
        showAlert(error.message || 'An error occurred while checking the domain', 'danger');
    } finally {
        // Restore button state
        checkButton.innerHTML = originalText;
        checkButton.disabled = false;
    }
}