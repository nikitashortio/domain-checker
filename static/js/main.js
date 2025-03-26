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
    // Hide all main tab panes
    document.querySelectorAll('#resultTabsContent > .tab-pane').forEach(pane => {
        pane.classList.remove('active', 'show');
        pane.style.display = 'none';
    });
    
    // Remove active class from all main nav links
    document.querySelectorAll('#resultTabs .nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    // Show the selected tab pane
    const selectedPane = document.getElementById(tabId);
    if (selectedPane) {
        selectedPane.classList.add('active', 'show');
        selectedPane.style.display = 'block';
    }
    
    // Add active class to the clicked nav link
    const selectedLink = document.querySelector(`[data-bs-target="#${tabId}"]`);
    if (selectedLink) {
        selectedLink.classList.add('active');
    }

    // Get the domain value
    const domain = document.getElementById('domain').value.trim();
    const hasDomain = domain.length > 0;

    // Handle DNS tab elements
    if (tabId === 'dns') {
        const dnsElements = document.querySelectorAll('.dns-controls, .dns-resolvers, .dns-table-wrapper, .dns-table, #dns .nav-pills');
        dnsElements.forEach(element => {
            element.style.display = hasDomain ? 'block' : 'none';
        });
    }

    // Handle iframe tab elements
    if (tabId === 'iframe') {
        const iframeElements = document.querySelectorAll('#iframe .results-container, #iframe .iframe-test-container');
        iframeElements.forEach(element => {
            element.style.display = hasDomain ? 'block' : 'none';
        });
    }

    // Update hint message visibility
    const hintMessage = document.getElementById('hint-message');
    if (hintMessage) {
        hintMessage.style.display = hasDomain ? 'none' : 'block';
        updateHintText(tabId);
    }

    // Remove domain-entered class if no domain
    if (!hasDomain) {
        document.body.classList.remove('domain-entered');
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
function switchDNSResolver(tabId) {
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

// Add event listeners for tab clicks
document.addEventListener('DOMContentLoaded', function() {
    // Initialize with no active tab
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active', 'show');
        pane.style.display = 'none';
    });
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });

    // Add event listeners for tab clicks
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = this.getAttribute('data-bs-target');
            if (target) {
                const tabId = target.replace('#', '');
                activateTab(tabId);
                
                // Only check domain for iframe tab if we have a domain and no cached results
                if (tabId === 'iframe') {
                    const domain = document.getElementById('domain').value.trim();
                    if (domain && !tabResults.iframe) {
                        checkDomain('iframe');
                    }
                }
            }
        });
    });

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

    // Remove the separate iframe tab event listener since we handle it in the main tab click handler
    const iframeTab = document.querySelector('[data-bs-target="#iframe"]');
    if (iframeTab) {
        const oldListener = iframeTab.getAttribute('data-listener');
        if (oldListener) {
            iframeTab.removeEventListener('shown.bs.tab', window[oldListener]);
        }
    }

    // Update the checkDomain function to store results in cache
    const originalCheckDomain = checkDomain;
    window.checkDomain = function(updateType = 'all') {
        return originalCheckDomain(updateType).then(data => {
            if (data && !data.error) {
                if (updateType === 'all') {
                    Object.entries(data).forEach(([endpoint, endpointData]) => {
                        if (endpointData && typeof endpointData === 'object') {
                            tabResults[endpoint] = endpointData;
                        }
                    });
                } else if (data[updateType]) {
                    tabResults[updateType] = data[updateType];
                }
            }
            return data;
        });
    };

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

    // Initialize DNS tables if there's a domain in the input
    const initialDomain = domainInput.value.trim();
    if (initialDomain) {
        document.body.classList.add('domain-entered');
    }

    // Add event listeners for DNS resolver tab clicks
    document.querySelectorAll('#dns .nav-pills .nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation(); // Prevent event bubbling
            
            const target = this.getAttribute('data-bs-target');
            if (target) {
                const tabId = target.replace('#', '');
                activateDnsTab(tabId);
            }
        });
    });
    
    // Initialize first DNS resolver tab if domain is entered
    if (domainInput && domainInput.value.trim()) {
        const firstDnsTab = document.querySelector('#dns .nav-pills .nav-link');
        if (firstDnsTab) {
            const target = firstDnsTab.getAttribute('data-bs-target');
            if (target) {
                activateDnsTab(target.replace('#', ''));
            }
        }
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
    const domain = document.getElementById('domain').value.trim();
    
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
    if (data.error) {
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
    
    // Add CSP frame-ancestors
    html += `
        <div class="iframe-field">
            <strong>CSP frame-ancestors:</strong>
            <span>${data.frame_ancestors_directive || 'Not Set'}</span>
        </div>`;
    
    // Add Connection header
    html += `
        <div class="iframe-field">
            <strong>Connection:</strong>
            <span>${connectionStatus}</span>
        </div>`;
    
    // Add iframe status message
    html += `
        <div class="iframe-field">
            <strong>Status:</strong>
            <span class="${data.allowed ? 'text-success' : 'text-danger'}">${data.message}</span>
        </div>`;
    
    html += '</div>';
    
    iframeResults.innerHTML = html;

    // Update the existing iframe preview
    const previewContainer = document.querySelector('.iframe-test-container');
    if (previewContainer) {
        // Update preview URL
        const previewUrl = previewContainer.querySelector('.preview-url');
        if (previewUrl) {
            previewUrl.textContent = url;
        }

        // Create and append iframe
        const previewContent = `
            <div class="preview-url">${url}</div>
            <div class="preview-frame">
                <iframe src="${url}" 
                        style="width: 100%; height: 500px; border: 1px solid #dee2e6; border-radius: 4px;"
                        sandbox="allow-same-origin allow-scripts allow-forms allow-popups"></iframe>
            </div>`;
        
        previewContainer.innerHTML = previewContent;
    }
}

function updateRedirectsResults(data) {
    const element = document.getElementById('redirects-results');
    let html = '<div class="redirects-info">';
    
    if (data.error) {
        html += `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i>
                ${data.error}
            </div>`;
    } else {
        if (!data.redirect_chain || data.redirect_chain.length === 0) {
            html += `
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    No redirects found
                </div>`;
        } else {
            data.redirect_chain.forEach((step, index) => {
                html += `
                    <div class="redirect-step">
                        <div class="step-number">${index + 1}</div>
                        <div class="step-details">
                            <div class="step-url">
                                <strong>${index === 0 ? 'Initial URL' : index === data.redirect_chain.length - 1 ? 'Final URL' : 'Redirects to'}:</strong>
                                <a href="${step.url}" target="_blank">${step.url}</a>
                            </div>
                            <div class="step-status">Status: ${step.status}</div>
                        </div>
                    </div>`;
            });

            html += `
                <div class="redirect-summary">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i>
                        Found ${data.redirect_chain.length} redirect${data.redirect_chain.length === 1 ? '' : 's'} in the chain
                    </div>
                </div>`;
        }
    }
    
    html += '</div>';
    element.innerHTML = html;
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
    const securityTab = document.getElementById('security');
    if (!securityTab) return;

    if (data.error) {
        securityTab.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        return;
    }

    let html = '<div class="security-info">';

    // Add Web Risk Information
    if (data.web_risk) {
        const webRisk = data.web_risk;
        const googleWebRisk = webRisk.google_web_risk || {};
        const virusTotal = webRisk.virustotal || {};

        // Google Web Risk Score
        html += `
            <div class="security-field">
                <strong>Google Web Risk Status</strong>
                <div class="security-score ${googleWebRisk.status === 'SAFE' ? 'text-success' : 'text-danger'}">
                    Status: ${googleWebRisk.status || 'N/A'}<br>
                    Score: ${googleWebRisk.score || 0}/100
                </div>
            </div>`;

        // VirusTotal Information
        html += `
            <div class="security-field">
                <strong>VirusTotal Report</strong>
                <div class="security-score">
                    Status: ${virusTotal.status || 'N/A'}<br>
                    Score: ${virusTotal.score || 0}/100<br>
                    <a href="${virusTotal.url || '#'}" target="_blank" rel="noopener noreferrer">
                        View Full Report <i class="fas fa-external-link-alt"></i>
                    </a>
                </div>
            </div>`;

        // Last Scan Date
        if (webRisk.scan_date) {
            html += `
                <div class="security-field">
                    <strong>Last Scan Date</strong>
                    <div>${new Date(webRisk.scan_date).toLocaleString()}</div>
                </div>`;
        }
    }

    html += '</div>';
    securityTab.innerHTML = html;
}

function checkDomain(updateType = 'all') {
    const domain = document.getElementById('domain').value.trim();
    
    if (!domain) {
        showAlert('Please enter a domain name', 'danger');
        return Promise.reject('No domain provided');
    }

    // Show loading state
    const loadingElement = document.getElementById('loading');
    if (loadingElement) {
        loadingElement.classList.remove('d-none');
    }

    // Show results containers if they exist
    const resultTabs = document.getElementById('resultTabs');
    const resultTabsContent = document.getElementById('resultTabsContent');
    if (resultTabs) resultTabs.style.display = 'block';
    if (resultTabsContent) resultTabsContent.style.display = 'block';
    
    // Add domain-entered class
    document.body.classList.add('domain-entered');
    
    // Hide hint message
    const hintMessage = document.getElementById('hint-message');
    if (hintMessage) {
        hintMessage.style.display = 'none';
    }

    // Show appropriate elements based on active tab
    const activeTab = document.querySelector('.tab-pane.active');
    if (activeTab) {
        if (activeTab.id === 'dns') {
            const dnsElements = document.querySelectorAll('.dns-controls, .dns-resolvers, .dns-table-wrapper, .dns-table, #dns .nav-pills');
            dnsElements.forEach(element => {
                element.style.display = 'block';
            });
        } else if (activeTab.id === 'iframe') {
            const iframeElements = document.querySelectorAll('#iframe .results-container, #iframe .iframe-test-container');
            iframeElements.forEach(element => {
                element.style.display = 'block';
            });
        }
    }

    // Check if we have cached results for the requested update type
    if (updateType !== 'all' && tabResults[updateType]) {
        updateTabResults(updateType, tabResults[updateType]);
        if (loadingElement) {
            loadingElement.classList.add('d-none');
        }
        return Promise.resolve({ [updateType]: tabResults[updateType] });
    }

    // Make API request
    return fetch('/api/check', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            domain: domain,
            update_type: updateType
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Received data:', data);
        
        if (data.error) {
            showAlert(data.error, 'danger');
            return data;
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

        // Activate DNS tab if no specific tab is active or if it's the first check
        if (!activeTab || updateType === 'all') {
            // Get the DNS tab link and activate it
            const dnsTab = document.querySelector('[data-bs-target="#dns"]');
            if (dnsTab) {
                activateTab('dns');
                dnsTab.classList.add('active');
            }
            // Initialize DNS tab
            initializeDNSTab();
        }

        return data;
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('An error occurred while checking the domain. Please try again.', 'danger');
        throw error;
    })
    .finally(() => {
        // Hide loading state
        if (loadingElement) {
            loadingElement.classList.add('d-none');
        }
    });
}