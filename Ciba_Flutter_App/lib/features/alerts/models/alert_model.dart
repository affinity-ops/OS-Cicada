// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// Data model for a HITL alert received from the Sentry Gateway.
///
/// Maps to the hold payload structure from
/// `GET /v1/hitl/hold/{holdRef}/payload` in handlers_lifecycle.go.
class HitlAlert {
  final String holdRef;
  final String agentName;
  final String tenantName;
  final String actionType;        // e.g. "shell/exec", "db/write"
  final String actionDetail;      // e.g. "POST /api/v1/db/drop-table"
  final String actionTarget;      // e.g. "prod-db-03"
  final double semanticMismatch;  // 0.0 - 1.0
  final String velocity;          // "LOW", "NORMAL", "HIGH"
  final double trustScore;        // 0.0 - 1.0
  final double trustThreshold;
  final AlertSeverity severity;
  final DateTime expiresAt;
  final DateTime createdAt;
  final String? agentRole;        // "Sub-agent", "Orchestrator", etc.
  final String? parentAgent;
  final List<DeclaredTool> declaredTools;
  final QuorumStatus? quorum;
  final String? reasoningTraceUrl;

  HitlAlert({
    required this.holdRef,
    required this.agentName,
    required this.tenantName,
    required this.actionType,
    required this.actionDetail,
    this.actionTarget = '',
    required this.semanticMismatch,
    required this.velocity,
    required this.trustScore,
    this.trustThreshold = 0.75,
    required this.severity,
    required this.expiresAt,
    required this.createdAt,
    this.agentRole,
    this.parentAgent,
    this.declaredTools = const [],
    this.quorum,
    this.reasoningTraceUrl,
  });

  factory HitlAlert.fromJson(Map<String, dynamic> json) {
    return HitlAlert(
      holdRef: json['hold_ref'] ?? '',
      agentName: json['agent_name'] ?? 'Unknown Agent',
      tenantName: json['tenant_name'] ?? 'Unknown Tenant',
      actionType: json['action_type'] ?? '',
      actionDetail: json['action_detail'] ?? '',
      actionTarget: json['action_target'] ?? '',
      semanticMismatch: (json['semantic_mismatch'] ?? 0).toDouble(),
      velocity: json['velocity'] ?? 'NORMAL',
      trustScore: (json['trust_score'] ?? 1.0).toDouble(),
      trustThreshold: (json['trust_threshold'] ?? 0.75).toDouble(),
      severity: AlertSeverity.fromString(json['severity'] ?? 'elevated'),
      expiresAt: DateTime.tryParse(json['expires_at'] ?? '') ?? DateTime.now().add(const Duration(minutes: 5)),
      createdAt: DateTime.tryParse(json['created_at'] ?? '') ?? DateTime.now(),
      agentRole: json['agent_role'],
      parentAgent: json['parent_agent'],
      declaredTools: (json['declared_tools'] as List<dynamic>?)
              ?.map((t) => DeclaredTool.fromJson(t))
              .toList() ??
          [],
      quorum: json['quorum'] != null ? QuorumStatus.fromJson(json['quorum']) : null,
      reasoningTraceUrl: json['reasoning_trace_url'],
    );
  }

  bool get isExpired => DateTime.now().toUtc().isAfter(expiresAt);
  Duration get timeRemaining => expiresAt.difference(DateTime.now().toUtc());
  bool get isBelowTrustThreshold => trustScore < trustThreshold;
  bool get requiresQuorum => quorum != null && quorum!.requiredVotes > 1;
}

enum AlertSeverity {
  critical,
  elevated,
  standard;

  static AlertSeverity fromString(String s) {
    switch (s.toLowerCase()) {
      case 'critical': return AlertSeverity.critical;
      case 'elevated': return AlertSeverity.elevated;
      default: return AlertSeverity.standard;
    }
  }
}

class DeclaredTool {
  final String name;
  final bool isDeclared;

  DeclaredTool({required this.name, required this.isDeclared});

  factory DeclaredTool.fromJson(Map<String, dynamic> json) => DeclaredTool(
        name: json['name'] ?? '',
        isDeclared: json['is_declared'] ?? true,
      );
}

class QuorumStatus {
  final int requiredVotes;
  final int totalVoters;
  final int currentApprovals;
  final int currentRejections;
  final bool resolved;
  final String? outcome;

  QuorumStatus({
    required this.requiredVotes,
    required this.totalVoters,
    required this.currentApprovals,
    required this.currentRejections,
    required this.resolved,
    this.outcome,
  });

  factory QuorumStatus.fromJson(Map<String, dynamic> json) => QuorumStatus(
        requiredVotes: json['required_votes'] ?? 1,
        totalVoters: json['total_voters'] ?? 1,
        currentApprovals: json['current_approvals'] ?? 0,
        currentRejections: json['current_rejections'] ?? 0,
        resolved: json['resolved'] ?? false,
        outcome: json['outcome'],
      );

  int get pendingVotes => requiredVotes - currentApprovals;
}
