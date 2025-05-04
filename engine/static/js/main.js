/**
 * VXDF Validate - Main JavaScript
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    
    // Handle file upload form validation
    const fileUploadForm = document.querySelector('form[action*="upload"]');
    if (fileUploadForm) {
        fileUploadForm.addEventListener('submit', function(event) {
            const fileInput = document.getElementById('file');
            if (fileInput && fileInput.files.length === 0) {
                event.preventDefault();
                alert('Please select a file to upload');
                return false;
            }
            
            // Show loading spinner or message when form is submitted
            const submitButton = this.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
            }
            
            return true;
        });
    }
    
    // Add filtering functionality to results page
    setupResultsFiltering();
});

/**
 * Setup filtering for the results page
 */
function setupResultsFiltering() {
    // Add filter controls if there are flow items to filter
    const flowItems = document.querySelectorAll('.flow-item');
    if (flowItems.length > 0) {
        // Get unique severity and vulnerability type values
        const severities = new Set();
        const vulnTypes = new Set();
        
        flowItems.forEach(item => {
            severities.add(item.getAttribute('data-severity'));
            vulnTypes.add(item.getAttribute('data-type'));
        });
        
        // Create filter controls if needed
        if (severities.size > 1 || vulnTypes.size > 1) {
            createFilterControls(Array.from(severities), Array.from(vulnTypes));
        }
    }
}

/**
 * Create filter controls for the results page
 * @param {Array} severities - Array of severity values
 * @param {Array} vulnTypes - Array of vulnerability type values
 */
function createFilterControls(severities, vulnTypes) {
    const tabContent = document.getElementById('flowTabContent');
    if (!tabContent) return;
    
    // Create the filter row
    const filterRow = document.createElement('div');
    filterRow.className = 'row mb-4';
    filterRow.innerHTML = `
        <div class="col-md-12">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">Filter Results</h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Severity</label>
                            <div id="severity-filters" class="d-flex flex-wrap gap-2">
                                <button class="btn btn-sm btn-outline-secondary active" data-filter="severity" data-value="all">All</button>
                                ${severities.map(severity => `
                                    <button class="btn btn-sm btn-outline-${getSeverityColorClass(severity)}" data-filter="severity" data-value="${severity}">${severity}</button>
                                `).join('')}
                            </div>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Vulnerability Type</label>
                            <div id="type-filters" class="d-flex flex-wrap gap-2">
                                <button class="btn btn-sm btn-outline-secondary active" data-filter="type" data-value="all">All</button>
                                ${vulnTypes.map(type => `
                                    <button class="btn btn-sm btn-outline-primary" data-filter="type" data-value="${type}">${formatVulnType(type)}</button>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Insert filter controls before the tab content
    tabContent.parentNode.insertBefore(filterRow, tabContent);
    
    // Add event listeners to filter buttons
    const filterButtons = filterRow.querySelectorAll('[data-filter]');
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Deactivate other buttons in the same filter group
            const filterType = this.getAttribute('data-filter');
            const filterGroup = document.getElementById(`${filterType}-filters`);
            filterGroup.querySelectorAll('button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Activate this button
            this.classList.add('active');
            
            // Apply filters
            applyFilters();
        });
    });
}

/**
 * Apply filters to the flow items
 */
function applyFilters() {
    // Get active filters
    const activeSeverityFilter = document.querySelector('#severity-filters button.active').getAttribute('data-value');
    const activeTypeFilter = document.querySelector('#type-filters button.active').getAttribute('data-value');
    
    // Get current tab
    const activeTab = document.querySelector('.tab-pane.active');
    if (!activeTab) return;
    
    // Apply filters to visible flow items
    const flowItems = activeTab.querySelectorAll('.flow-item');
    flowItems.forEach(item => {
        const itemSeverity = item.getAttribute('data-severity');
        const itemType = item.getAttribute('data-type');
        
        // Check if item matches all active filters
        const matchesSeverity = activeSeverityFilter === 'all' || itemSeverity === activeSeverityFilter;
        const matchesType = activeTypeFilter === 'all' || itemType === activeTypeFilter;
        
        // Show or hide the item
        if (matchesSeverity && matchesType) {
            item.style.display = '';
        } else {
            item.style.display = 'none';
        }
    });
}

/**
 * Format vulnerability type for display
 * @param {string} type - Vulnerability type
 * @returns {string} Formatted vulnerability type
 */
function formatVulnType(type) {
    if (!type) return 'Unknown';
    return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

/**
 * Get Bootstrap color class for severity
 * @param {string} severity - Severity level
 * @returns {string} Bootstrap color class
 */
function getSeverityColorClass(severity) {
    switch (severity) {
        case 'CRITICAL': return 'danger';
        case 'HIGH': return 'warning';
        case 'MEDIUM': return 'info';
        case 'LOW': return 'success';
        default: return 'secondary';
    }
}
