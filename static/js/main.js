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

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tab change handler
    const tabs = document.querySelectorAll('[data-bs-toggle="tab"]');
    tabs.forEach(tab => {
        tab.addEventListener('shown.bs.tab', function(event) {
            updateHintText(event.target.id);
            
            const domain = document.getElementById('domain').value.trim();
            if (!domain) return;

            // Check if this is a DNS resolver tab switch
            const isDNSResolverTab = ['cloudflare', 'google', 'quad9'].some(resolver => 
                event.target.getAttribute('data-bs-target')?.includes(resolver)
            );
            
            if (isDNSResolverTab) {
                // For DNS resolver tabs, just update the UI from cache
                updateDNSResults(dnsResults);
            } else {
                // For main tabs, check cache first
                const endpoint = getEndpointForTab(event.target.id);
                if (endpoint === 'dns') {
                    // Always use cached results for DNS tab
                    updateDNSResults(dnsResults);
                } else if (endpoint === 'redirects') {
                    // Always use cached results for redirects tab
                    if (tabResults.redirects) {
                        updateRedirectsResults(tabResults.redirects);
                    }
                } else if (endpoint !== 'all' && tabResults[endpoint]) {
                    // Use cached results for other tabs without showing loader
                    updateTabResults(endpoint, tabResults[endpoint]);
                }
            }
        });
    });

    // Add event listener for domain input changes
    const domainInput = document.getElementById('domain');
    domainInput.addEventListener('input', function() {
        const domain = this.value.trim();
        
        // Clear DNS results cache when domain changes
        dnsResults = {
            cloudflare: null,
            google: null,
            quad9: null
        };

        const activeTab = document.querySelector('.tab-pane.active');
        if (activeTab && activeTab.id === 'redirects') {
            // Clear redirects cache to force a fresh request
            tabResults.redirects = null;
            // Show loader
            const loadingElement = document.getElementById('loading');
            if (loadingElement) {
                loadingElement.classList.remove('d-none');
            }
            // Add a small delay to avoid too many requests while typing
            clearTimeout(this.checkTimeout);
            this.checkTimeout = setTimeout(() => {
                checkDomain('redirects');
            }, 500);
        }
    });

    // Add event listener for Enter key in domain input
    domainInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            // Clear DNS results cache when Enter is pressed
            dnsResults = {
                cloudflare: null,
                google: null,
                quad9: null
            };

            const activeTab = document.querySelector('.tab-pane.active');
            if (activeTab && activeTab.id === 'redirects') {
                // Clear redirects cache to force a fresh request
                tabResults.redirects = null;
                // Show loader
                const loadingElement = document.getElementById('loading');
                if (loadingElement) {
                    loadingElement.classList.remove('d-none');
                }
                checkDomain('redirects');
            } else {
                checkDomain();
            }
        }
    });

    // Add event listener for DNS record type selector
    const dnsRecordType = document.getElementById('dnsRecordType');
    if (dnsRecordType) {
        dnsRecordType.addEventListener('change', function() {
            const domain = document.getElementById('domain').value.trim();
            if (domain) {
                // Clear DNS results cache to force a fresh request
                dnsResults = {
                    cloudflare: null,
                    google: null,
                    quad9: null
                };
                checkDomain('dns');
            }
        });
    }

    // Add event listener for refresh button
    const refreshButton = document.querySelector('.dns-controls button');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            const domain = document.getElementById('domain').value.trim();
            if (domain) {
                // Clear stored results
                dnsResults = {
                    cloudflare: null,
                    google: null,
                    quad9: null
                };
                checkDomain('dns');
            }
        });
    }

    // Add event listener for iframe tab
    const iframeTab = document.querySelector('[data-bs-target="#iframe"]');
    if (iframeTab) {
        iframeTab.addEventListener('shown.bs.tab', function() {
            const domain = document.getElementById('domain').value.trim();
            if (domain) {
                checkDomain('iframe');
            }
        });
    }

    // Initialize DNS tables if there's a domain in the input
    const initialDomain = domainInput.value.trim();
    if (initialDomain) {
        document.body.classList.add('domain-entered');
    }
});

function updateHintText(tabId) {
    const hintMessage = document.getElementById('hint-message');
    const messages = {
        'dns-tab': 'DNS records',
        'whois-tab': 'WHOIS information',
        'ssl-tab': 'SSL certificate',
        'availability-tab': 'domain availability',
        'referrer-tab': 'referrer policy',
        'iframe-tab': 'iframe policy',
        'redirects-tab': 'redirect chain',
        'headers-tab': 'HTTP headers',
        'security-tab': 'security status'
    };
    
    const selectedText = messages[tabId] || 'DNS records';
    hintMessage.textContent = `Enter a domain name to check ${selectedText}`;
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

function checkDomain(domain, updateType = 'all') {
    if (!domain) {
        showAlert('Please enter a domain name', 'danger');
        return;
    }

    // Show loading state
    document.getElementById('results').style.display = 'block';
    document.getElementById('loading').style.display = 'block';
    document.getElementById('error').style.display = 'none';

    // Make API request
    fetch('/api/check', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            domain: domain,
            update_type: updateType
        })
    })
    .then(response => response.json())
    .then(data => {
        console.log('Received data:', data);
        
        if (data.error) {
            showAlert(data.error, 'danger');
            return;
        }

        // Update all tabs if updateType is 'all'
        if (updateType === 'all') {
            Object.entries(data).forEach(([endpoint, endpointData]) => {
                if (endpointData && typeof endpointData === 'object') {
                    updateTabResults(endpoint, endpointData);
                }
            });
        } else if (data[updateType]) {
            // Update specific tab
            updateTabResults(updateType, data[updateType]);
        }

        // Hide loading state
        document.getElementById('loading').style.display = 'none';
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('An error occurred while checking the domain', 'danger');
        document.getElementById('loading').style.display = 'none';
    });
}

function updateDNSResults(data) {
    console.log('Starting updateDNSResults with data:', data);
    const resolvers = ['cloudflare', 'google', 'quad9'];
    const selectedType = document.getElementById('dnsRecordType').value;
    const recordTypes = selectedType === 'all' ? ['a', 'aaaa', 'mx', 'ns', 'txt', 'cname', 'soa'] : [selectedType.toLowerCase()];
    const domain = document.getElementById('domain').value.trim();
    
    console.log('Selected type:', selectedType);
    console.log('Record types to process:', recordTypes);
    
    // Handle error case
    if (data.error) {
        console.log('Error in DNS data:', data.error);
        resolvers.forEach(resolver => {
            const container = document.getElementById(`dns-results-${resolver}`);
            if (container) {
                container.innerHTML = `
                    <tr class="error-row">
                        <td colspan="4">
                            <div class="alert alert-danger">
                                <i class="fas fa-exclamation-circle"></i>
                                ${data.error}
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
        console.log(`Processing resolver: ${resolver}`);
        let tableContent = '';
        let hasRecords = false;
        
        recordTypes.forEach(type => {
            console.log(`Processing record type: ${type}`);
            const records = data[type] || [];
            console.log(`Found ${records.length} records for type ${type}`);
            
            records.forEach(record => {
                if (record.resolver === resolver) {
                    console.log(`Adding record to table for ${resolver}:`, record);
                    hasRecords = true;
                    tableContent += `
                        <tr data-type="${type.toUpperCase()}">
                            <td>${type.toUpperCase()}</td>
                            <td>${domain}</td>
                            <td>${record.value}</td>
                            <td>${record.ttl}</td>
                        </tr>`;
                }
            });
        });

        const container = document.getElementById(`dns-results-${resolver}`);
        console.log(`Container for ${resolver}:`, container);
        if (container) {
            if (hasRecords) {
                console.log(`Setting content for ${resolver}:`, tableContent);
                container.innerHTML = tableContent;
            } else {
                console.log(`No records found for ${resolver}`);
                container.innerHTML = `<tr class="no-records"><td colspan="4">No ${selectedType === 'all' ? '' : selectedType.toUpperCase() + ' '}records found</td></tr>`;
            }
        }
    });

    // Show the DNS controls and resolvers
    document.querySelector('.dns-controls').style.display = 'block';
    document.querySelector('.dns-resolvers').style.display = 'block';
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
            if (key === 'status' && Array.isArray(value)) {
                value = value.join(', ');
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
            
            html += `
                <div class="whois-field">
                    <strong>${label}</strong>
                    <span class="${valueClass}">${key === 'registrar' || key === 'status' || key === 'nameservers' || key.startsWith('ip') ? value : formatDate(value)}</span>
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
            
            // Organization Name (O) is typically the most important
            if (data.issuer.O) {
                issuerParts.push(data.issuer.O);
            }
            
            // Common Name (CN) often contains the issuer's domain
            if (data.issuer.CN && (!data.issuer.O || !data.issuer.CN.includes(data.issuer.O))) {
                issuerParts.push(data.issuer.CN);
            }
            
            // Organizational Unit (OU) can provide additional context
            if (data.issuer.OU && !issuerParts.some(part => part.includes(data.issuer.OU))) {
                issuerParts.push(data.issuer.OU);
            }
            
            issuerDisplay = issuerParts.join(' - ') || 'Unknown';
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
    const element = document.getElementById('iframe-results');
    let html = '<div class="iframe-info">';
    
    if (data.error) {
        html += `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i>
                ${data.error}
            </div>`;
    } else {
        // Display iframe test results
        html += `
            <div class="iframe-field">
                <strong>Iframe Test Results:</strong>
                <div class="test-results">`;
        
        // Test if iframe is allowed
        const iframeAllowed = data.allowed || false;
        const iframeClass = iframeAllowed ? 'text-success' : 'text-danger';
        const iframeIcon = iframeAllowed ? 'fa-check-circle' : 'fa-times-circle';
        
        html += `
            <div class="test-result-item">
                <i class="fas ${iframeIcon} ${iframeClass}"></i>
                <span>Iframe ${iframeAllowed ? 'Allowed' : 'Not Allowed'}</span>
            </div>`;
        
        // Display X-Frame-Options header if present
        if (data.headers && data.headers['X-Frame-Options']) {
            html += `
                <div class="test-result-item">
                    <i class="fas fa-info-circle text-info"></i>
                    <span>X-Frame-Options: ${data.headers['X-Frame-Options']}</span>
                </div>`;
        }
        
        // Display Content-Security-Policy header if present
        if (data.headers && data.headers['Content-Security-Policy']) {
            html += `
                <div class="test-result-item">
                    <i class="fas fa-info-circle text-info"></i>
                    <span>Content-Security-Policy: ${data.headers['Content-Security-Policy']}</span>
                </div>`;
        }
        
        html += `</div></div>`;
        
        // Add explanation of the results
        html += `
            <div class="iframe-field">
                <strong>Explanation:</strong>
                <div class="explanation">
                    ${getIframeExplanation(iframeAllowed)}
                </div>
            </div>`;
    }
    
    html += '</div>';
    element.innerHTML = html;
}

function getIframeExplanation(allowed) {
    if (allowed) {
        return `
            <p>This website allows itself to be embedded in iframes on other websites. This could potentially expose your website to clickjacking attacks.</p>
            <p>Recommendations:</p>
            <ul>
                <li>Consider implementing X-Frame-Options header with DENY or SAMEORIGIN</li>
                <li>Add Content-Security-Policy header with frame-ancestors directive</li>
                <li>Only allow iframe embedding from trusted domains if necessary</li>
            </ul>`;
    } else {
        return `
            <p>This website has proper security measures in place to prevent being embedded in iframes on other websites.</p>
            <p>This is good for security as it protects against clickjacking attacks.</p>`;
    }
}

function updateRedirectsResults(data) {
    const redirectsInfo = document.getElementById('redirects-info');
    if (!redirectsInfo) {
        console.error('Redirects info container not found');
        return;
    }
    
    redirectsInfo.innerHTML = ''; // Clear existing content
    
    if (data.error) {
        redirectsInfo.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        return;
    }
    
    if (!data.redirect_chain || data.redirect_chain.length === 0) {
        redirectsInfo.innerHTML = `<div class="alert alert-info">No redirects found</div>`;
        return;
    }
    
    // Display redirect chain
    data.redirect_chain.forEach((step, index) => {
        const stepElement = document.createElement('div');
        stepElement.className = 'redirect-step';
        
        const stepNumber = document.createElement('div');
        stepNumber.className = 'step-number';
        stepNumber.textContent = index + 1;
        
        const stepDetails = document.createElement('div');
        stepDetails.className = 'step-details';
        
        // Add URL
        const urlElement = document.createElement('div');
        urlElement.className = 'step-url';
        urlElement.innerHTML = `<strong>${index === 0 ? 'Initial URL' : index === data.redirect_chain.length - 1 ? 'Final URL' : 'Redirects to'}:</strong> <a href="${step.url}" target="_blank">${step.url}</a>`;
        
        // Add status
        const statusElement = document.createElement('div');
        statusElement.className = 'step-status';
        statusElement.textContent = step.status;
        
        // Add headers if available
        if (step.headers) {
            const headersElement = document.createElement('div');
            headersElement.className = 'step-headers';
            headersElement.innerHTML = `<pre class="headers-pre">${JSON.stringify(step.headers, null, 2)}</pre>`;
            stepDetails.appendChild(headersElement);
        }
        
        // Assemble the step
        stepDetails.appendChild(urlElement);
        stepDetails.appendChild(statusElement);
        stepElement.appendChild(stepNumber);
        stepElement.appendChild(stepDetails);
        redirectsInfo.appendChild(stepElement);
    });
    
    // Add redirect summary
    if (data.redirect_count > 0) {
        const summaryElement = document.createElement('div');
        summaryElement.className = 'redirect-summary';
        summaryElement.innerHTML = `
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i>
                Found ${data.redirect_count} redirect${data.redirect_count === 1 ? '' : 's'} in the chain
            </div>`;
        redirectsInfo.appendChild(summaryElement);
    }
}

function updateHeadersResults(data) {
    const element = document.getElementById('headers-results');
    let html = '<div class="headers-info">';
    
    if (data.error) {
        html += `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i>
                ${data.error}
            </div>`;
    } else {
        // Group headers by category
        const categories = {
            'Security Headers': [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'Referrer-Policy'
            ],
            'Server Information': [
                'Server',
                'X-Powered-By',
                'X-AspNet-Version',
                'X-AspNetMvc-Version'
            ],
            'Content Information': [
                'Content-Type',
                'Content-Length',
                'Content-Language',
                'Content-Encoding'
            ],
            'Caching': [
                'Cache-Control',
                'Expires',
                'Last-Modified',
                'ETag'
            ],
            'Other Headers': [] // Will contain headers not in other categories
        };
        
        // Sort headers into categories
        const sortedHeaders = {};
        Object.entries(data.headers || {}).forEach(([header, value]) => {
            let categorized = false;
            for (const [category, headerList] of Object.entries(categories)) {
                if (headerList.includes(header)) {
                    if (!sortedHeaders[category]) {
                        sortedHeaders[category] = {};
                    }
                    sortedHeaders[category][header] = value;
                    categorized = true;
                    break;
                }
            }
            if (!categorized) {
                if (!sortedHeaders['Other Headers']) {
                    sortedHeaders['Other Headers'] = {};
                }
                sortedHeaders['Other Headers'][header] = value;
            }
        });
        
        // Display headers by category
        Object.entries(sortedHeaders).forEach(([category, headers]) => {
            if (Object.keys(headers).length > 0) {
                html += `
                    <div class="headers-category">
                        <h4>${category}</h4>
                        <div class="headers-list">`;
                
                Object.entries(headers).forEach(([header, value]) => {
                    const headerClass = getHeaderClass(header);
                    html += `
                        <div class="header-item ${headerClass}">
                            <div class="header-name">${header}</div>
                            <div class="header-value">${value}</div>
                        </div>`;
                });
                
                html += `</div></div>`;
            }
        });
    }
    
    html += '</div>';
    element.innerHTML = html;
}

function getHeaderClass(header) {
    // Add specific classes for security-related headers
    const securityHeaders = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'Referrer-Policy'
    ];
    
    if (securityHeaders.includes(header)) {
        return 'security-header';
    }
    
    return '';
}

function updateSecurityResults(data) {
    const element = document.getElementById('security-results');
    let html = '<div class="security-info">';
    
    if (data.error) {
        html += `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i>
                ${data.error}
            </div>`;
    } else {
        // Security Score
        const score = data.security_score || 0;
        const scoreClass = score >= 80 ? 'text-success' : score >= 60 ? 'text-warning' : 'text-danger';
        
        html += `
            <div class="security-field">
                <strong>Security Score:</strong>
                <span class="${scoreClass}">${score}/100</span>
            </div>`;

        // Security Headers Status
        if (data.headers) {
            const securityHeaders = {
                'X-Frame-Options': 'Protects against clickjacking attacks',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'X-XSS-Protection': 'Enables browser XSS protection',
                'Content-Security-Policy': 'Controls resource loading',
                'Strict-Transport-Security': 'Enforces HTTPS connections',
                'Referrer-Policy': 'Controls referrer information',
                'Permissions-Policy': 'Controls browser features'
            };

            html += `
                <div class="security-field">
                    <strong>Security Headers:</strong>
                    <div class="security-headers">`;

            Object.entries(securityHeaders).forEach(([header, description]) => {
                const isSet = data.headers[header] !== undefined;
                const statusClass = isSet ? 'text-success' : 'text-danger';
                const statusIcon = isSet ? 'fa-check-circle' : 'fa-times-circle';
                
                html += `
                    <div class="security-header-item">
                        <div class="header-status">
                            <i class="fas ${statusIcon} ${statusClass}"></i>
                            <span>${header}</span>
                        </div>
                        <div class="header-description">${description}</div>
                    </div>`;
            });

            html += `
                    </div>
                </div>`;
        }

        // SSL/TLS Status
        if (data.ssl) {
            const sslStatus = data.ssl.valid ? 'Valid' : 'Invalid';
            const sslClass = data.ssl.valid ? 'text-success' : 'text-danger';
            
            html += `
                <div class="security-field">
                    <strong>SSL/TLS Status:</strong>
                    <span class="${sslClass}">${sslStatus}</span>
                    ${data.ssl.valid ? `
                        <div class="ssl-details">
                            <div>Valid until: ${formatDate(data.ssl.valid_until)}</div>
                            <div>Issuer: ${data.ssl.issuer || 'Unknown'}</div>
                        </div>
                    ` : ''}
                </div>`;
        }

        // Recommendations
        if (data.recommendations && data.recommendations.length > 0) {
            html += `
                <div class="security-field">
                    <strong>Security Recommendations:</strong>
                    <div class="security-recommendations">`;
            
            data.recommendations.forEach(rec => {
                html += `
                    <div class="recommendation-item">
                        <i class="fas fa-exclamation-triangle text-warning"></i>
                        <span>${rec}</span>
                    </div>`;
            });

            html += `
                    </div>
                </div>`;
        }
    }
    
    html += '</div>';
    element.innerHTML = html;
}
