<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cicada Platform Compliance Attestation</title>
    <style>
        body {
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            color: #333;
            line-height: 1.5;
            font-size: 12px;
        }
        .header {
            border-bottom: 2px solid #000;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #000;
        }
        .report-title {
            font-size: 18px;
            color: #555;
            text-transform: uppercase;
        }
        .section {
            margin-bottom: 30px;
            page-break-inside: avoid;
        }
        .section-title {
            background-color: #f4f4f4;
            padding: 5px 10px;
            font-weight: bold;
            border-left: 4px solid #333;
            margin-bottom: 10px;
            font-size: 14px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #fafafa;
            width: 40%;
        }
        .footer {
            margin-top: 50px;
            font-size: 10px;
            color: #777;
            text-align: center;
            border-top: 1px solid #eee;
            padding-top: 10px;
        }
        .signature-block {
            margin-top: 30px;
            padding: 15px;
            background-color: #f9f9f9;
            border: 1px dashed #ccc;
            font-family: monospace;
            word-wrap: break-word;
        }
        .badge {
            display: inline-block;
            padding: 2px 5px;
            background-color: #e0e0e0;
            border-radius: 3px;
            font-size: 10px;
        }
        .incident-table th {
            background-color: #eee;
            width: auto;
        }
    </style>
</head>
<body>

<div class="header">
    <div class="logo">CICADA ENTERPRISE GOVERNANCE</div>
    <div class="report-title">Automated Compliance Attestation Report</div>
    <div>Generated At: {{ \Carbon\Carbon::parse($data['generated_at'])->format('Y-m-d H:i:s \U\T\C') }}</div>
</div>

<div class="section">
    <p>This automated report provides real-time posture data extracted directly from Cicada's immutable PostgreSQL action ledger. It fulfills evidence requirements for SOC2, GDPR (Art. 30), and the EU AI Act.</p>
</div>

<div class="section">
    <div class="section-title">1. Retention Policies & Sovereignty (EU AI Act / GDPR)</div>
    <table>
        <tr>
            <th>Log Retention Period</th>
            <td>{{ $data['retention_policies']['log_retention_days'] }} Days</td>
        </tr>
        <tr>
            <th>Audit Trail Mechanism</th>
            <td>{{ strtoupper(str_replace('_', ' ', $data['retention_policies']['audit_trail'])) }}</td>
        </tr>
        <tr>
            <th>Data Residency Enforcement</th>
            <td>{{ strtoupper(str_replace('_', ' ', $data['retention_policies']['data_residency'])) }}</td>
        </tr>
    </table>
</div>

<div class="section">
    <div class="section-title">2. Data Processing Records (GDPR Art. 30)</div>
    <table>
        <tr>
            <th>Total Active Tenants</th>
            <td>{{ number_format($data['data_processing_records']['total_active_tenants']) }}</td>
        </tr>
        <tr>
            <th>Total Registered AI Agents</th>
            <td>{{ number_format($data['data_processing_records']['total_registered_agents']) }}</td>
        </tr>
        <tr>
            <th>Total Revoked Identities</th>
            <td>{{ number_format($data['data_processing_records']['total_revoked_identities']) }}</td>
        </tr>
        <tr>
            <th>PII Processing Status</th>
            <td>{{ ucwords(str_replace('_', ' ', $data['data_processing_records']['pii_processing_status'])) }}</td>
        </tr>
    </table>
</div>

<div class="section">
    <div class="section-title">3. Access Control Evidence (SOC2 CC6.1)</div>
    <table>
        <tr>
            <th>Total Proxy Evaluations</th>
            <td>{{ number_format($data['access_control_evidence']['total_proxy_evaluations']) }}</td>
        </tr>
        <tr>
            <th>Admissions Granted</th>
            <td>{{ number_format($data['access_control_evidence']['admissions_granted']) }}</td>
        </tr>
        <tr>
            <th>Admissions Denied (Blocked)</th>
            <td>{{ number_format($data['access_control_evidence']['admissions_denied']) }}</td>
        </tr>
        <tr>
            <th>Deny Ratio</th>
            <td>{{ $data['access_control_evidence']['deny_ratio_percentage'] }}%</td>
        </tr>
    </table>
</div>

<div class="section">
    <div class="section-title">4. Audit Trail Completeness (SOC2 CC7.2)</div>
    <table>
        <tr>
            <th>Immutable Ledger Active</th>
            <td>{{ $data['audit_trail_completeness']['immutable_ledger_active'] ? 'YES' : 'NO' }}</td>
        </tr>
        <tr>
            <th>Database RLS Enforced</th>
            <td>{{ $data['audit_trail_completeness']['database_rls_enforced'] ? 'YES' : 'NO' }}</td>
        </tr>
        <tr>
            <th>Total Events Logged</th>
            <td>{{ number_format($data['audit_trail_completeness']['total_events_logged']) }}</td>
        </tr>
        <tr>
            <th>Last Event Timestamp</th>
            <td>{{ $data['audit_trail_completeness']['last_event_timestamp'] ?? 'N/A' }}</td>
        </tr>
    </table>
</div>

<div class="section">
    <div class="section-title">5. Recent Critical Incidents</div>
    @if(count($data['incident_log_recent']) > 0)
        <table class="incident-table">
            <thead>
                <tr>
                    <th>Trace ID</th>
                    <th>Agent ID</th>
                    <th>Anomaly Type</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                @foreach($data['incident_log_recent'] as $incident)
                <tr>
                    <td>{{ substr($incident->trace_id, 0, 8) }}...</td>
                    <td>{{ substr($incident->agent_id, 0, 8) }}...</td>
                    <td><span class="badge">{{ strtoupper(str_replace('_', ' ', $incident->action_type)) }}</span></td>
                    <td>{{ $incident->created_at }}</td>
                </tr>
                @endforeach
            </tbody>
        </table>
    @else
        <p>No critical incidents recorded in the query window.</p>
    @endif
</div>

<div class="signature-block">
    <strong>CRYPTOGRAPHIC ATTESTATION</strong><br><br>
    Algorithm: {{ $integrity['algorithm'] }}<br>
    Key Fingerprint: {{ $integrity['key_fingerprint'] }}<br>
    Canonical Hash (SHA256): {{ $integrity['canonical_hash'] }}<br>
    Signature: {{ substr($integrity['signature'], 0, 64) }}...<br>
    Signed At: {{ $integrity['signed_at'] }}
</div>

<div class="footer">
    Cicada Enterprise Governance Platform | Report generated automatically via Core API | Confidential
</div>

</body>
</html>
