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
        const hasDomain = domain.length > 0;
        
        // Show/hide DNS controls and resolvers based on domain input
        document.body.classList.toggle('domain-entered', hasDomain);
        
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
    const updateFunctions = {
        'dns': () => updateDNSResults(data),
        'whois': () => updateWHOISResults(data),
        'ssl': () => updateSSLResults(data),
        'availability': () => updateAvailabilityResults(data),
        'referrer': () => updateReferrerResults(data),
        'iframe': () => updateIframeResults(data),
        'redirects': () => updateRedirectsResults(data),
        'headers': () => updateHeadersResults(data),
        'security': () => updateSecurityResults(data)
    };

    if (updateFunctions[endpoint]) {
        updateFunctions[endpoint]();
    }
}

function checkDomain(updateType = 'all') {
    const domain = document.getElementById('domain').value.trim();
    if (!domain) {
        alert('Please enter a domain name');
        return;
    }

    // Show loading spinner
    const loadingElement = document.getElementById('loading');
    if (loadingElement) {
        loadingElement.classList.remove('d-none');
    }

    // Add domain-entered class to show DNS controls
    document.body.classList.add('domain-entered');

    // Make the API request
    const endpoint = getEndpointForTab(updateType);
    console.log('Making request to:', endpoint);
    
    const requestData = {
        domain: domain,
        update_type: updateType
    };
    console.log('Request data:', requestData);

    fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData)
    })
    .then(response => response.json())
    .then(data => {
        console.log('Response data:', data);
        
        // Hide loading spinner
        if (loadingElement) {
            loadingElement.classList.add('d-none');
        }

        // Update results based on the update type
        if (updateType === 'all' || updateType === 'dns') {
            console.log('Processing DNS data:', data.dns);
            updateDNSResults(data.dns);
        }
        if (updateType === 'all' || updateType === 'whois') {
            updateWHOISResults(data.whois);
        }
        if (updateType === 'all' || updateType === 'ssl') {
            updateSSLResults(data.ssl);
        }
        if (updateType === 'all' || updateType === 'availability') {
            updateAvailabilityResults(data.availability);
        }
        if (updateType === 'all' || updateType === 'referrer') {
            updateReferrerResults(data.referrer);
        }
        if (updateType === 'all' || updateType === 'iframe') {
            updateIframeResults(data.iframe);
        }
        if (updateType === 'all' || updateType === 'redirects') {
            updateRedirectsResults(data.redirects);
        }
        if (updateType === 'all' || updateType === 'headers') {
            updateHeadersResults(data.headers);
        }
        if (updateType === 'all' || updateType === 'security') {
            updateSecurityResults(data.security);
        }

        // Store results in cache
        if (updateType === 'all') {
            tabResults = data;
        } else {
            tabResults[updateType] = data[updateType];
        }
    })
    .catch(error => {
        console.error('Error:', error);
        if (loadingElement) {
            loadingElement.classList.add('d-none');
        }
        alert('An error occurred while checking the domain. Please try again.');
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
    const element = document.getElementById('availability-results');
    let html = '<div class="availability-info">';

    if (data.error) {
        html += `<div class="alert alert-danger">${data.error}</div>`;
    } else {
        html += `
            <div class="availability-field">
                <strong>Status</strong>
                <span class="${data.available ? 'text-success' : 'text-danger'}">${data.available ? 'Available' : 'Registered'}</span>
            </div>`;

        if (!data.available) {
            html += `
                <div class="availability-field">
                    <strong>Creation Date</strong>
                    <span>${formatDate(data.creation_date)}</span>
                </div>
                <div class="availability-field">
                    <strong>Registrar</strong>
                    <span>${data.registrar || '-'}</span>
                </div>`;
        }
    }
    
    html += '</div>';
    element.innerHTML = html;
}

function updateReferrerResults(data) {
    const element = document.getElementById('referrer-results');
    let html = '<div class="referrer-info">';
    
    if (data.error) {
        html += `<div class="text-danger">${data.error}</div>`;
    } else {
        html += `
            <div class="referrer-field">
                <strong>Status:</strong>
                <span>${data.status}</span>
            </div>
            <div class="referrer-field">
                <strong>Headers:</strong>
                <pre class="headers-pre">${JSON.stringify(data.headers, null, 2)}</pre>
            </div>`;
    }
    
    html += '</div>';
    element.innerHTML = html;
}

function updateIframeResults(data) {
    const element = document.getElementById('iframe-results');
    let html = '<div class="iframe-info">';
    
    if (data.error) {
        html += `<div class="text-danger">${data.error}</div>`;
    } else {
        html += `
            <div class="iframe-field">
                <strong>X-Frame-Options:</strong>
                <span>${data.allows_iframe ? 'Not Set (Allows iframe)' : 'Set (Blocks iframe)'}</span>
            </div>
            <div class="iframe-field">
                <strong>Content-Security-Policy:</strong>
                <span>${data.content_security_policy || 'Not Set'}</span>
            </div>`;
    }
    
    html += '</div>';
    element.innerHTML = html;

    // Update iframe preview if domain is available
    const domain = document.getElementById('domain').value.trim();
    if (domain && !data.error) {
        updateIframePreview(domain, data.allows_iframe);
    }
}

function updateIframePreview(domain, allowsIframe) {
    const iframe = document.getElementById('domain-iframe');
    if (!iframe) return;

    if (allowsIframe) {
        iframe.src = `https://${domain}`;
    } else {
        iframe.src = 'about:blank';
        iframe.srcdoc = `
            <div style="padding: 20px; text-align: center; color: #dc3545;">
                <h3>Iframe Blocked</h3>
                <p>This website does not allow embedding in iframes.</p>
                <p>X-Frame-Options header is set to prevent iframe embedding.</p>
            </div>
        `;
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
        
        // Add status with appropriate color
        const statusElement = document.createElement('div');
        statusElement.className = 'step-status';
        const statusText = step.status;
        let statusClass = '';
        
        if (statusText.includes('200')) {
            statusClass = 'text-success';
        } else if (statusText.includes('301') || statusText.includes('302')) {
            statusClass = 'text-warning';
        } else if (statusText.includes('404')) {
            statusClass = 'text-danger';
        }
        
        statusElement.innerHTML = `<span class="${statusClass}">${statusText}</span>`;
        
        // Add headers toggle button
        const headersButton = document.createElement('button');
        headersButton.className = 'btn btn-sm btn-outline-secondary mt-2';
        headersButton.textContent = 'Show Headers';
        headersButton.onclick = () => toggleHeaders(index);
        
        // Add headers content (hidden by default)
        const headersElement = document.createElement('div');
        headersElement.className = 'step-headers';
        headersElement.style.display = 'none';
        headersElement.innerHTML = `<pre class="headers-pre">${JSON.stringify(step.headers, null, 2)}</pre>`;
        
        stepDetails.appendChild(urlElement);
        stepDetails.appendChild(statusElement);
        stepDetails.appendChild(headersButton);
        stepDetails.appendChild(headersElement);
        
        stepElement.appendChild(stepNumber);
        stepElement.appendChild(stepDetails);
        redirectsInfo.appendChild(stepElement);
    });
    
    // Add summary
    const summaryElement = document.createElement('div');
    summaryElement.className = 'redirect-summary';
    summaryElement.innerHTML = `
        <div class="alert alert-info">
            <i class="fas fa-info-circle"></i>
            Total redirects: ${data.redirect_count}
        </div>
    `;
    redirectsInfo.appendChild(summaryElement);
}

// Add function to toggle headers visibility
function toggleHeaders(index) {
    const headersElement = document.querySelector(`.redirect-step:nth-child(${index + 1}) .step-headers`);
    const button = document.querySelector(`.redirect-step:nth-child(${index + 1}) button`);
    
    if (headersElement && button) {
        const isHidden = headersElement.style.display === 'none';
        headersElement.style.display = isHidden ? 'block' : 'none';
        button.textContent = isHidden ? 'Hide Headers' : 'Show Headers';
    }
}

function updateHeadersResults(data) {
    const element = document.getElementById('headers-results');
    let html = '<div class="headers-info">';
    
    if (data.error) {
        html += `<div class="alert alert-danger">${data.error}</div>`;
    } else {
        for (const [key, value] of Object.entries(data)) {
            html += `
                <div class="header-field">
                    <strong>${key}:</strong>
                    <span>${value}</span>
                </div>`;
        }
    }
    
    html += '</div>';
    element.innerHTML = html;
}

function updateSecurityResults(data) {
    const element = document.getElementById('security-results');
    let html = '<div class="security-info">';
    
    // Google Web Risk
    html += '<div class="security-section mb-4">';
    html += '<h5 class="mb-3">Google Web Risk</h5>';
    
    if (data.google_web_risk?.error) {
        html += `<div class="alert alert-danger">${data.google_web_risk.error}</div>`;
    } else {
        const webRisk = data.google_web_risk || {};
        html += `
            <div class="security-field">
                <strong>Status</strong>
                <span class="${webRisk.is_safe ? 'text-success' : 'text-danger'}">
                    ${webRisk.is_safe ? 'Safe' : 'Potentially Unsafe'}
                </span>
            </div>
            ${webRisk.threats ? `
            <div class="security-field">
                <strong>Threats</strong>
                <span>${webRisk.threats.join(', ')}</span>
            </div>` : ''}`;
    }
    html += '</div>';
    
    // VirusTotal
    html += '<div class="security-section">';
    html += '<h5 class="mb-3">VirusTotal Analysis</h5>';
    
    if (data.virustotal?.error) {
        html += `<div class="alert alert-danger">${data.virustotal.error}</div>`;
    } else {
        const vt = data.virustotal || {};
        html += `
            <div class="security-field">
                <strong>Scan Date</strong>
                <span>${formatDate(vt.scan_date)}</span>
            </div>
            <div class="security-field">
                <strong>Status</strong>
                <span class="${vt.positives > 0 ? 'text-danger' : 'text-success'}">
                    ${vt.positives > 0 ? 'Suspicious' : 'Clean'}
                </span>
            </div>
            <div class="security-field">
                <strong>Detection Ratio</strong>
                <span>${vt.positives || 0} / ${vt.total || 0}</span>
            </div>
            <div class="security-field">
                <strong>Categories</strong>
                <span>${vt.categories?.length > 0 ? vt.categories.join(', ') : 'None'}</span>
            </div>
            ${vt.url ? `
            <div class="security-field mt-3">
                <a href="${vt.url}" target="_blank" class="btn btn-sm btn-dark w-100">
                    View Full Report <i class="bi bi-box-arrow-up-right ms-1"></i>
                </a>
            </div>` : ''}`;
    }
    html += '</div>';
    
    html += '</div>';
    element.innerHTML = html;
}

function showError(message) {
    // Show error in the active tab's results container
    const activeTab = document.querySelector('.tab-pane.active');
    if (activeTab) {
        const resultsContainer = activeTab.querySelector('[id$="-results"]');
        if (resultsContainer) {
            resultsContainer.innerHTML = `
                <div class="alert alert-danger">
                    <h5>Error Details:</h5>
                    <p>${message}</p>
                    <p>Please try again or check if the domain is correct.</p>
                </div>`;
        }
    }
}
