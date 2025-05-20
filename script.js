// Global variables
let currentScanId = null;
let updateIntervalId = null;
let historyLoaded = false;

// Initialize the page
$(document).ready(function() {
    // Handle form submission
    $('#scan-form').on('submit', function(e) {
        e.preventDefault();
        startScan();
    });

    // Load scan history
    loadScanHistory();

    // Add PDF export button handler
    $(document).on('click', '#export-pdf-btn', function() {
        exportToPdf(currentScanId);
    });

    // Validate port range inputs
    $('#port_range_start, #port_range_end').on('change', function() {
        const start = parseInt($('#port_range_start').val());
        const end = parseInt($('#port_range_end').val());

        if (start > end) {
            alert('Port awal harus kurang dari atau sama dengan port akhir');
            // Menyesuaikan nilai input agar valid
            $(this).val($(this).attr('id') === 'port_range_start' ? end : start);
        }
        // Pastikan nilai berada dalam rentang valid 1-65535
        if (start < 1) $('#port_range_start').val(1);
        if (end > 65535) $('#port_range_end').val(65535);
    });
});

// Start a new scan
function startScan() {
    const target = $('#target').val();
    const algorithm = $('input[name="algorithm"]:checked').val();
    const commonPortsFirst = $('#common_ports_first').is(':checked');
    const maxThreads = $('#max_threads').val();
    // Fitur baru: Rentang port
    const portRangeStart = parseInt($('#port_range_start').val()) || 1;
    const portRangeEnd = parseInt($('#port_range_end').val()) || 1024;

    // Validate inputs
    if (!target) {
        alert('Silakan masukkan alamat IP target');
        return;
    }

    // Validate port range
    if (portRangeStart > portRangeEnd) {
        alert('Port awal harus kurang dari atau sama dengan port akhir');
        return;
    }

    if (portRangeStart < 1 || portRangeEnd > 65535) {
        alert('Rentang port harus antara 1 dan 65535');
        return;
    }

    // Prepare data for API
    const scanData = {
        target: target,
        algorithm: algorithm,
        common_ports_first: commonPortsFirst,
        max_threads: maxThreads,
        // Fitur baru: Tambahkan rentang port ke data scan
        port_range_start: portRangeStart,
        port_range_end: portRangeEnd
    };

    // Clear previous results
    $('#open-ports-list').empty();
    $('#port-count span').text('0');
    $('#scan-progress-bar').css('width', '0%');
    $('#progress-percent').text('0%');

    // Show current scan section
    $('#current-scan').show();
    $('#scan-results').hide();

    // Update status badge for current scan
    $('#scan-status-badge').removeClass('bg-success bg-danger').addClass('bg-warning').text('Sedang Memindai...');

    // Send request to start scan
    $.ajax({
        url: '/api/scan',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(scanData),
        success: function(response) {
            currentScanId = response.scan_id;
            updateScanStatus(); // Initial update

            // Start automatic updates
            if (updateIntervalId) {
                clearInterval(updateIntervalId);
            }
            updateIntervalId = setInterval(updateScanStatus, 1000);
        },
        error: function(xhr, status, error) {
            alert('Kesalahan saat memulai pemindaian: ' + error);
            $('#current-scan').hide();
            // Update status badge to failed if scan initiation fails
            $('#scan-status-badge').removeClass('bg-warning').addClass('bg-danger').text('Gagal');
        }
    });
}

// Update the scan status
function updateScanStatus() {
    if (!currentScanId) return;

    console.log('Fetching status for scan ID:', currentScanId); // Debugging line

    $.ajax({
        url: '/api/scan/' + currentScanId,
        type: 'GET',
        success: function(data) {
            console.log('Status data received:', data); // Debugging line

            if (!data || typeof data !== 'object') {
                console.error('Invalid data received from server');
                return;
            }

            // Update scan info
            $('#scan-target').text(data.target);
            $('#scan-algorithm').text(data.algorithm);
            $('#scan-start-time').text(data.start_time);
            $('#scan-common-ports').text(data.common_ports_first ? 'Ya' : 'Tidak');
            // Fitur baru: Tampilkan rentang port jika ada
            $('#scan-port-range').text(`${data.port_range_start || 'N/A'} - ${data.port_range_end || 'N/A'}`);


            // Calculate and update progress
            const totalPorts = data.total_ports || 1; // Avoid division by zero
            const currentProgress = data.progress || 0;
            const progressRatio = currentProgress / totalPorts;
            const progressPercent = Math.round(progressRatio * 100);

            console.log(`Progress: ${currentProgress}/${totalPorts} = ${progressPercent}%`); // Debugging line

            $('#scan-progress-bar').css('width', progressPercent + '%');
            $('#progress-percent').text(progressPercent + '%');

            // Update open ports display
            if (data.open_ports && data.open_ports.length > 0) {
                console.log('Updating open ports:', data.open_ports.length); // Debugging line
                updateOpenPorts(data.open_ports);
            }

            // Check if scan is complete or failed
            if (data.status === 'completed' || data.status === 'failed') {
                console.log('Scan status changed to:', data.status); // Debugging line
                // Stop automatic updates
                if (updateIntervalId) {
                    console.log('Stopping update interval'); // Debugging line
                    clearInterval(updateIntervalId);
                    updateIntervalId = null;
                }

                // Update status badge based on final status
                $('#scan-status-badge')
                    .removeClass('bg-warning')
                    .addClass(data.status === 'completed' ? 'bg-success' : 'bg-danger')
                    .text(data.status === 'completed' ? 'Selesai' : 'Gagal');

                // Display final results
                displayFinalResults(data);

                // Refresh history
                if (historyLoaded) { // Only reload history if it was already loaded
                    loadScanHistory();
                }
            }
        },
        error: function(xhr, status, error) {
            console.error('Kesalahan saat mengambil status pemindaian:', error);
            // Optionally, update status badge to failed if there's a persistent error
            // $('#scan-status-badge').removeClass('bg-warning').addClass('bg-danger').text('Gagal');
        }
    });
}

// Update open ports display during scan
function updateOpenPorts(openPorts) {
    $('#port-count span').text(openPorts.length);

    // Clear previous ports
    $('#open-ports-list').empty();

    // Add ports as badges
    openPorts.forEach(function(portData) {
        // Menggunakan bg-success untuk badge port terbuka selama pemindaian
        const portBadge = $('<span class="badge bg-success port-badge"></span>')
            .text(portData.port + ' (' + (portData.service || 'Unknown') + ')'); // Tambah 'Unknown' jika service tidak ada
        $('#open-ports-list').append(portBadge);
    });
}

// Display final results when scan completes
function displayFinalResults(data) {
    // Populate results data
    $('#results-target').text(data.target);
    $('#results-algorithm').text(data.algorithm);
    $('#results-start-time').text(data.start_time);
    $('#results-end-time').text(data.end_time || 'N/A');
    $('#results-duration').text(data.elapsed_time || 'N/A');
    $('#results-ports-scanned').text(data.total_ports);
    // Fitur baru: Tampilkan rentang port di hasil akhir
    $('#results-port-range').text(`${data.port_range_start || 'N/A'} - ${data.port_range_end || 'N/A'}`);


    // Populate ports table
    $('#results-ports-table').empty();
    if (data.open_ports && data.open_ports.length > 0) { // Pastikan open_ports ada dan tidak kosong
        // Sort ports by risk level (Critical -> High -> Medium -> Low -> Unknown)
        const riskOrder = {
            'Critical': 1,
            'High': 2,
            'Medium': 3,
            'Low': 4,
            'Unknown': 5
        };

        data.open_ports.sort((a, b) => {
            // Memberikan nilai default 999 untuk risk_level yang tidak dikenal agar muncul di akhir
            return (riskOrder[a.risk_level] || 999) - (riskOrder[b.risk_level] || 999);
        });

        data.open_ports.forEach(function(portData, index) {
            const row = $('<tr></tr>');
            row.append($('<td></td>').text(portData.port));
            row.append($('<td></td>').text(portData.service || 'N/A')); // Tambah 'N/A' jika service tidak ada

            // Risk level with color-coded badge
            const riskLevel = portData.risk_level || 'Unknown';
            const riskBadge = $('<span class="risk-badge"></span>')
                .addClass('risk-' + riskLevel.toLowerCase())
                .text(riskLevel);
            row.append($('<td></td>').append(riskBadge));

            // Details button (Info)
            const detailsButton = $('<span class="port-details-button"></span>')
                .html('<i class="fas fa-info-circle"></i> Info')
                .attr('data-port-index', index); // Gunakan index untuk mengaitkan dengan panel detail

            row.append($('<td></td>').append(detailsButton));

            $('#results-ports-table').append(row);

            // Add hidden details panel row
            const detailsRow = $('<tr class="port-details-row" style="display: none;"></tr>');
            const detailsCell = $('<td colspan="4"></td>'); // colspan 4 karena ada 4 kolom utama
            const detailsPanel = $('<div class="port-details-panel"></div>')
                .addClass('risk-' + riskLevel.toLowerCase() + '-panel');

            // Risk description
            if (portData.risk_description) {
                detailsPanel.append(
                    $('<div class="port-details-header"></div>').text('Risk Description:'),
                    $('<div class="port-details-content"></div>').text(portData.risk_description)
                );
            }

            // Recommendations
            if (portData.recommendations) {
                detailsPanel.append(
                    $('<div class="port-details-header"></div>').text('Recommendations:'),
                    $('<div class="port-details-content"></div>').text(portData.recommendations)
                );
            }

            detailsCell.append(detailsPanel);
            detailsRow.append(detailsCell);
            $('#results-ports-table').append(detailsRow);
        });

        // Add click handlers for details buttons for *this* scan's details
        $('.port-details-button').off('click').on('click', function() { // Off() untuk mencegah multiple handlers
            $(this).closest('tr').next('.port-details-row').toggle();
        });

    } else {
        const row = $('<tr></tr>');
        row.append($('<td colspan="4" class="text-center"></td>').text('Tidak ditemukan port terbuka'));
        $('#results-ports-table').append(row);
    }

    // Show results section
    $('#scan-results').show();
    // Hide current scan section after showing results
    $('#current-scan').hide();
}

// Load scan history
function loadScanHistory() {
    $.ajax({
        url: '/api/scans',
        type: 'GET',
        success: function(scans) {
            // Clear history list
            $('#history-list').empty();

            if (scans.length === 0) {
                $('#history-list').append('<div class="col-12 text-center"><p>Belum ada riwayat pemindaian</p></div>');
                return;
            }

            // Sort scans by start time (newest first)
            scans.sort(function(a, b) {
                return new Date(b.start_time) - new Date(a.start_time);
            });

            // Add each scan to history
            scans.forEach(function(scan) {
                const historyItem = createHistoryItem(scan);
                $('#history-list').append(historyItem);
            });

            // Add click handlers for history items
            // Gunakan delegasi event agar bekerja untuk elemen yang ditambahkan dinamis
            $('#history-list').off('click', '.history-item').on('click', '.history-item', function() {
                const scanId = $(this).data('scan-id');
                loadScanDetails(scanId);
            });

            historyLoaded = true;
        },
        error: function() {
            console.log('Kesalahan saat memuat riwayat pemindaian');
        }
    });
}

// Create a history item element
function createHistoryItem(scan) {
    const statusClass = scan.status === 'completed' ? 'completed' :
                        scan.status === 'running' ? 'running' : 'failed';

    const portCount = scan.open_ports ? scan.open_ports.length : 0;

    const historyCol = $('<div class="col-md-6 col-lg-4"></div>');
    const historyItem = $('<div class="history-item"></div>')
        .addClass(statusClass)
        .data('scan-id', scan.scan_id);

    historyItem.append($('<h5></h5>').text('Target: ' + scan.target));

    const detailsRow = $('<div class="row"></div>');

    const col1 = $('<div class="col-6"></div>');
    col1.append($('<p class="mb-1"></p>').text('Algoritma: ' + scan.algorithm));
    col1.append($('<p class="mb-1"></p>').text('Port Terbuka: ' + portCount));

    const col2 = $('<div class="col-6"></div>');
    col2.append($('<p class="mb-1"></p>').text('Tanggal: ' + (scan.start_time ? scan.start_time.split(' ')[0] : 'N/A')));
    // Terjemahkan status untuk tampilan riwayat
    const translatedStatus = scan.status === 'completed' ? 'Selesai' : scan.status === 'running' ? 'Berjalan' : 'Gagal';
    col2.append($('<p class="mb-1"></p>').text('Status: ' + translatedStatus));

    detailsRow.append(col1).append(col2);
    historyItem.append(detailsRow);

    historyCol.append(historyItem);
    return historyCol;
}

// Load details of a specific scan
function loadScanDetails(scanId) {
    $.ajax({
        url: '/api/scan/' + scanId,
        type: 'GET',
        success: function(data) {
            currentScanId = scanId;

            // Clear any existing interval if switching scans
            if (updateIntervalId) {
                clearInterval(updateIntervalId);
                updateIntervalId = null;
            }

            // If scan is still running, start updates
            if (data.status === 'running') {
                updateIntervalId = setInterval(updateScanStatus, 1000);

                // Show current scan view
                $('#current-scan').show();
                $('#scan-results').hide();

                // Update status badge
                $('#scan-status-badge').removeClass('bg-success bg-danger').addClass('bg-warning').text('Sedang Memindai...');
                updateScanStatus(); // Panggil update status segera untuk menampilkan data awal
            } else {
                // Show completed results
                $('#current-scan').hide();
                displayFinalResults(data);
                // Update status badge for historical completed/failed scans
                $('#scan-status-badge')
                    .removeClass('bg-warning')
                    .addClass(data.status === 'completed' ? 'bg-success' : 'bg-danger')
                    .text(data.status === 'completed' ? 'Selesai' : 'Gagal');
            }

            // Scroll to results or current scan section
            const targetSection = (data.status === 'running') ? $('#current-scan') : $('#scan-results');
            $('html, body').animate({
                scrollTop: targetSection.offset().top - 100
            }, 500);
        },
        error: function() {
            alert('Kesalahan saat memuat detail scan');
        }
    });
}

// Function to export PDF
function exportToPdf(scanId) {
    if (!scanId) {
        alert('Tidak ada ID pemindaian yang aktif untuk diekspor.');
        return;
    }

    // Build URL for PDF download
    const pdfUrl = `/api/scan/${scanId}/export/pdf`;

    // Create a temporary anchor element for download
    const link = document.createElement('a');
    link.href = pdfUrl;
    link.target = '_blank'; // Open in a new tab

    // Trigger click to start download
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}