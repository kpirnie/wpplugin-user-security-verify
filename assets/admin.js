( function () {
    'use strict';

    const config = window.ModeUserSecurityValidation;
    const app = document.getElementById( 'mode-usv-app' );

    if ( ! config || ! app ) {
        return;
    }

    const startButton = document.getElementById( 'mode-usv-start' );
    const cancelButton = document.getElementById( 'mode-usv-cancel' );
    const downloadButton = document.getElementById( 'mode-usv-download' );
    const progressBar = document.getElementById( 'mode-usv-progress-bar' );
    const progressElement = progressBar.parentElement;
    const progressLabel = document.getElementById( 'mode-usv-progress-label' );
    const testList = document.getElementById( 'mode-usv-test-list' );
    const resultsSection = document.getElementById( 'mode-usv-results' );
    const summary = document.getElementById( 'mode-usv-summary' );
    const empty = document.getElementById( 'mode-usv-empty' );
    const findingsTable = document.getElementById( 'mode-usv-findings-table' );
    const findingsBody = findingsTable.querySelector( 'tbody' );
    const inventorySection = document.getElementById( 'mode-usv-inventory' );
    const usersBody = document.querySelector( '#mode-usv-users-table tbody' );
    const severityOrder = [ 'critical', 'high', 'medium', 'low', 'informational' ];

    let cancelled = false;
    let scanResults = null;
    let totalUnits = config.tests.length;

    function createElement( tag, className, text ) {
        const element = document.createElement( tag );
        if ( className ) {
            element.className = className;
        }
        if ( undefined !== text ) {
            element.textContent = text;
        }
        return element;
    }

    function siteLabel( siteId ) {
        const site = ( config.sites || [] ).find( function ( item ) { return item.id === siteId; } );
        return site ? site.label : 'Site ' + siteId;
    }

    function buildUnits() {
        const units = [];

        config.tests.forEach( function ( test ) {
            if ( 'network' === config.scope && 'site' === test.scope ) {
                ( config.sites || [] ).forEach( function ( site ) {
                    units.push( { test: test, site: site } );
                } );
                return;
            }

            units.push( { test: test, site: null } );
        } );

        return units;
    }

    function renderTestList() {
        testList.replaceChildren();
        config.tests.forEach( function ( test ) {
            const item = createElement( 'li', 'mode-usv__test', '' );
            item.dataset.testId = test.id;
            item.appendChild( createElement( 'span', 'mode-usv__test-marker', '' ) );
            const copy = createElement( 'span', 'mode-usv__test-copy', '' );
            copy.appendChild( createElement( 'strong', '', test.label ) );
            copy.appendChild( createElement( 'small', '', test.description ) );
            item.appendChild( copy );
            item.appendChild( createElement( 'span', 'mode-usv__test-status', '' ) );
            testList.appendChild( item );
        } );
    }

    function setTestStatus( testId, status, label ) {
        const item = testList.querySelector( '[data-test-id="' + testId + '"]' );
        if ( ! item ) {
            return;
        }
        item.className = 'mode-usv__test mode-usv__test--' + status;
        item.querySelector( '.mode-usv__test-status' ).textContent = label;
    }

    function updateProgress( completed ) {
        const percentage = Math.round( completed / totalUnits * 100 );
        progressBar.style.width = percentage + '%';
        progressElement.setAttribute( 'aria-valuenow', String( percentage ) );
        progressLabel.textContent = percentage + '%';
    }

    async function runTest( testId, siteId, cursor ) {
        const body = new URLSearchParams();
        body.set( 'action', config.action );
        body.set( 'nonce', config.nonce );
        body.set( 'test_id', testId );
        body.set( 'scope', config.scope || 'site' );
        body.set( 'site_id', String( siteId || 0 ) );
        body.set( 'cursor_root', String( cursor ? cursor.root : 0 ) );
        body.set( 'cursor_path', cursor ? String( cursor.path || '' ) : '' );

        const response = await fetch( config.ajaxUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
            body: body.toString(),
        } );

        let payload = null;

        try {
            payload = await response.json();
        } catch ( error ) {
            throw new Error( config.labels.requestFailed + ' (HTTP ' + response.status + ')' );
        }

        if ( ! response.ok || ! payload.success ) {
            throw new Error( payload.data && payload.data.message ? payload.data.message : config.labels.requestFailed );
        }

        return payload.data;
    }

    function renderSummary( findings ) {
        summary.replaceChildren();
        severityOrder.forEach( function ( severity ) {
            const count = findings.filter( function ( finding ) { return finding.severity === severity; } ).length;
            const card = createElement( 'div', 'mode-usv__summary-card mode-usv__summary-card--' + severity, '' );
            card.appendChild( createElement( 'strong', '', String( count ) ) );
            card.appendChild( createElement( 'span', '', severity === 'informational' ? 'Info' : severity.charAt( 0 ).toUpperCase() + severity.slice( 1 ) ) );
            summary.appendChild( card );
        } );
    }

    function buildReportItems( findings ) {
        const userItems = new Map();
        const siteItems = [];

        findings.forEach( function ( finding ) {
            if ( ! finding.user_id ) {
                siteItems.push( Object.assign( { issues: [ finding ] }, finding ) );
                return;
            }

            const key = finding.user_id + '-' + ( finding.site_id || 0 );
            if ( ! userItems.has( key ) ) {
                userItems.set( key, {
                    id: 'MUSV-USER-' + key,
                    severity: finding.severity,
                    title: 'User has security findings',
                    summary: '',
                    recommendation: '',
                    user_id: finding.user_id,
                    user_login: finding.user_login,
                    site_id: finding.site_id || 0,
                    issues: [],
                } );
            }

            const item = userItems.get( key );
            if ( ! item.issues.some( function ( issue ) { return issue.id === finding.id; } ) ) {
                item.issues.push( finding );
            }

            if ( severityOrder.indexOf( finding.severity ) < severityOrder.indexOf( item.severity ) ) {
                item.severity = finding.severity;
            }

            if ( ! item.user_login && finding.user_login ) {
                item.user_login = finding.user_login;
            }
        } );

        userItems.forEach( function ( item ) {
            item.title = item.issues.length + ( 1 === item.issues.length ? ' security finding' : ' security findings' );
        } );

        return Array.from( userItems.values() ).concat( siteItems );
    }

    function filterUsersWithIssues( users, reportItems ) {
        const issueUserIds = new Set(
            reportItems.filter( function ( item ) { return Boolean( item.user_id ); } )
                .map( function ( item ) { return item.user_id + '-' + ( item.site_id || 0 ); } )
        );
        const siteMatch = function ( user ) { return issueUserIds.has( user.id + '-' + ( user.site_id || 0 ) ); };
        const siteMatchedIds = new Set( users.filter( siteMatch ).map( function ( user ) { return user.id; } ) );
        const networkShownIds = new Set();

        return users.filter( function ( user ) {
            if ( siteMatch( user ) ) {
                return true;
            }

            if ( ! issueUserIds.has( user.id + '-0' ) || siteMatchedIds.has( user.id ) || networkShownIds.has( user.id ) ) {
                return false;
            }

            networkShownIds.add( user.id );
            return true;
        } );
    }

    function renderFindings( findings ) {
        findingsBody.replaceChildren();
        empty.hidden = true;
        findingsTable.hidden = false;

        if ( 0 === findings.length ) {
            findingsTable.hidden = true;
            empty.hidden = false;
            empty.textContent = config.labels.noFindings;
            return;
        }

        findings.sort( function ( left, right ) {
            return severityOrder.indexOf( left.severity ) - severityOrder.indexOf( right.severity );
        } );

        findings.forEach( function ( finding ) {
            const row = document.createElement( 'tr' );
            const severityCell = document.createElement( 'td' );
            severityCell.appendChild( createElement( 'span', 'mode-usv__badge mode-usv__badge--' + finding.severity, finding.severity ) );
            row.appendChild( severityCell );

            const titleCell = document.createElement( 'td' );
            titleCell.appendChild( createElement( 'strong', '', finding.title ) );
            titleCell.appendChild( createElement( 'code', 'mode-usv__finding-id', finding.id ) );

            if ( finding.user_id && finding.issues ) {
                const issueList = createElement( 'ul', 'mode-usv__issue-titles', '' );
                finding.issues.forEach( function ( issue ) {
                    issueList.appendChild( createElement( 'li', '', issue.title ) );
                } );
                titleCell.appendChild( issueList );
            }
            row.appendChild( titleCell );

            const userCell = document.createElement( 'td' );
            if ( finding.user_id ) {
                userCell.appendChild( createElement( 'strong', '', finding.user_login || ( 'User ' + finding.user_id ) ) );
                userCell.appendChild( createElement( 'span', '', 'ID ' + finding.user_id ) );
                if ( finding.site_id ) {
                    userCell.appendChild( createElement( 'span', '', siteLabel( finding.site_id ) ) );
                }
            } else {
                userCell.textContent = '—';
            }
            row.appendChild( userCell );

            const detailCell = document.createElement( 'td' );
            ( finding.issues || [ finding ] ).forEach( function ( issue ) {
                const issueBlock = createElement( 'div', 'mode-usv__issue-detail', '' );
                if ( finding.user_id && finding.issues ) {
                    issueBlock.appendChild( createElement( 'strong', '', issue.title ) );
                }
                issueBlock.appendChild( createElement( 'p', '', issue.summary ) );
                issueBlock.appendChild( createElement( 'p', 'mode-usv__recommendation', issue.recommendation ) );
                detailCell.appendChild( issueBlock );
            } );
            row.appendChild( detailCell );
            findingsBody.appendChild( row );
        } );
    }

    function renderUsers( users ) {
        usersBody.replaceChildren();
        if ( ! users.length ) {
            inventorySection.hidden = true;
            return;
        }

        users.forEach( function ( user ) {
            const row = document.createElement( 'tr' );
            const values = [
                user.id,
                user.site ? user.login + ' (' + user.site + ')' : user.login,
                user.roles.length ? user.roles.join( ', ' ) : 'No role',
                user.registered,
                user.direct_cap_count,
                user.sensitive_cap_count,
                user.sessions,
                user.application_passwords,
                user.authored_records + ' / ' + ( user.customer_record ? 'yes' : 'no' ),
            ];
            values.forEach( function ( value ) {
                row.appendChild( createElement( 'td', '', String( value ) ) );
            } );
            usersBody.appendChild( row );
        } );

        inventorySection.hidden = false;
    }

    function downloadResults() {
        if ( ! scanResults ) {
            return;
        }
        const blob = new Blob( [ JSON.stringify( scanResults, null, 2 ) ], { type: 'application/json' } );
        const url = URL.createObjectURL( blob );
        const link = document.createElement( 'a' );
        link.href = url;
        link.download = 'mode-user-security-validation-' + new Date().toISOString().replace( /[:.]/g, '-' ) + '.json';
        document.body.appendChild( link );
        link.click();
        link.remove();
        URL.revokeObjectURL( url );
    }

    async function startScan() {
        cancelled = false;
        scanResults = {
            generated_at: new Date().toISOString(),
            plugin_version: config.version,
            scope: config.scope || 'site',
            complete: false,
            tests: [],
            findings: [],
            users: [],
            code_paths: [],
        };

        const units = buildUnits();
        const remaining = new Map();
        const failed = new Set();
        const interrupted = new Set();

        units.forEach( function ( unit ) {
            remaining.set( unit.test.id, ( remaining.get( unit.test.id ) || 0 ) + 1 );
        } );

        totalUnits = units.length || 1;
        startButton.disabled = true;
        cancelButton.disabled = false;
        downloadButton.disabled = true;
        resultsSection.hidden = true;
        inventorySection.hidden = true;
        updateProgress( 0 );
        renderTestList();

        let completed = 0;

        for ( const unit of units ) {
            const test = unit.test;
            const siteId = unit.site ? unit.site.id : 0;

            if ( cancelled ) {
                setTestStatus( test.id, 'cancelled', config.labels.cancelled );
                continue;
            }

            setTestStatus( test.id, 'running', config.labels.running + ( unit.site ? ' (' + unit.site.label + ')' : '' ) );

            try {
                let cursor = null;

                do {
                    const result = await runTest( test.id, siteId, cursor );
                    scanResults.tests.push( result );
                    scanResults.findings = scanResults.findings.concat( result.findings || [] );
                    if ( result.users ) {
                        scanResults.users = scanResults.users.concat( result.users );
                    }
                    if ( result.code_paths ) {
                        scanResults.code_paths = scanResults.code_paths.concat( result.code_paths );
                    }
                    cursor = result.next || null;
                } while ( cursor && ! cancelled );

                if ( cursor ) {
                    interrupted.add( test.id );
                }
            } catch ( error ) {
                failed.add( test.id );
                scanResults.tests.push( { test_id: test.id, site_id: siteId, error: error.message } );
                scanResults.findings.push( {
                    id: 'MUSV-TEST-' + test.id.toUpperCase() + ( unit.site ? '-' + siteId : '' ),
                    severity: 'high',
                    title: 'Validation test did not complete',
                    summary: ( unit.site ? 'Site: ' + unit.site.label + '. ' : '' ) + 'The ' + test.label + ' test failed. The scan cannot be treated as complete.',
                    recommendation: 'Review the WordPress and PHP error logs, correct the failure, and rerun the complete scan.',
                    user_id: 0,
                    user_login: '',
                    site_id: siteId,
                } );
            }

            remaining.set( test.id, remaining.get( test.id ) - 1 );

            if ( failed.has( test.id ) ) {
                setTestStatus( test.id, 'failed', config.labels.failed );
            } else if ( interrupted.has( test.id ) ) {
                setTestStatus( test.id, 'cancelled', config.labels.cancelled );
            } else if ( 0 === remaining.get( test.id ) ) {
                setTestStatus( test.id, 'complete', config.labels.complete );
            }

            completed += 1;
            updateProgress( completed );
        }

        const replacedConnection = scanResults.tests.some( function ( test ) { return 'wpdb' === test.evidence_connection; } );

        if ( replacedConnection ) {
            scanResults.findings.push( {
                id: 'MUSV-EVIDENCE-WPDB',
                severity: 'high',
                title: 'Evidence queries ran through a replaced database connection',
                summary: 'A db.php drop-in replaced the mysqli connection, so the validation queries ran through wpdb and can be altered by the query filter or the drop-in itself. The scan cannot be treated as complete.',
                recommendation: 'Review wp-content/db.php and any query filters, then confirm the results against an offline database export.',
                user_id: 0,
                user_login: '',
                site_id: 0,
            } );
        }

        if ( cancelled ) {
            scanResults.findings.push( {
                id: 'MUSV-SCAN-CANCELLED',
                severity: 'medium',
                title: 'User security scan was cancelled',
                summary: 'One or more validation tests did not run, so these results are incomplete.',
                recommendation: 'Run the complete scan before relying on the result.',
                user_id: 0,
                user_login: '',
            } );
        } else {
            scanResults.complete = ! replacedConnection && ! scanResults.tests.some( function ( test ) { return Boolean( test.error ); } );
        }

        const reportItems = buildReportItems( scanResults.findings );
        scanResults.user_summaries = reportItems.filter( function ( item ) { return Boolean( item.user_id ); } );
        scanResults.users = filterUsersWithIssues( scanResults.users, reportItems );
        renderSummary( reportItems );
        renderFindings( reportItems );
        renderUsers( scanResults.users );
        resultsSection.hidden = false;
        startButton.disabled = false;
        cancelButton.disabled = true;
        downloadButton.disabled = false;
    }

    startButton.addEventListener( 'click', startScan );
    cancelButton.addEventListener( 'click', function () { cancelled = true; } );
    downloadButton.addEventListener( 'click', downloadResults );
    renderTestList();
}() );
