// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the Visual Compliance Scaffolder — the 6-step agent provisioning wizard.
// Tests cover: step rendering, validation, navigation, tool selection, risk analysis,
// HITL enforcement, compliance frameworks, and YAML generation.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import React from 'react';

// Mock the session context — the scaffolder reads session for the owner email.
vi.mock('@/app/(portal)/layout', () => ({
  useSession: () => ({
    contact: { id: 'c1', name: 'Test Dev', email: 'dev@company.com', avatar_url: '' },
    tenant: { id: 't1', name: 'TestCorp', plan: 'professional', status: 'active' },
    token: 'mock-token',
  }),
}));

import ScaffoldPage from '@/app/(portal)/scaffold/page';

describe('ScaffoldPage — Visual Compliance Scaffolder', () => {

  // ── Step 1: Framework Selection ─────────────────────────────────────────
  describe('Step 1 — Framework', () => {
    it('renders the page title', () => {
      render(<ScaffoldPage />);
      expect(screen.getByText('Scaffold an Agent')).toBeInTheDocument();
    });

    it('renders the step indicator with all 6 steps', () => {
      render(<ScaffoldPage />);
      // Each step has a label; they're hidden at sm: breakpoint but in jsdom they render
      expect(screen.getByText('Framework')).toBeInTheDocument();
      expect(screen.getByText('Identity')).toBeInTheDocument();
      expect(screen.getByText('Tools')).toBeInTheDocument();
      expect(screen.getByText('Enforcement')).toBeInTheDocument();
      expect(screen.getByText('Compliance')).toBeInTheDocument();
      expect(screen.getByText('Download')).toBeInTheDocument();
    });

    it('renders all 5 framework options', () => {
      render(<ScaffoldPage />);
      expect(screen.getByText('LangChain')).toBeInTheDocument();
      expect(screen.getByText('CrewAI')).toBeInTheDocument();
      expect(screen.getByText('Python')).toBeInTheDocument();
      expect(screen.getByText('Node.js')).toBeInTheDocument();
      expect(screen.getByText('AutoGen')).toBeInTheDocument();
    });

    it('disables Continue when no framework is selected', () => {
      render(<ScaffoldPage />);
      const continueBtn = screen.getByText('Continue →');
      expect(continueBtn).toBeDisabled();
    });

    it('enables Continue when a framework is selected', () => {
      render(<ScaffoldPage />);
      fireEvent.click(screen.getByText('LangChain'));
      const continueBtn = screen.getByText('Continue →');
      expect(continueBtn).not.toBeDisabled();
    });

    it('disables Back button on step 1', () => {
      render(<ScaffoldPage />);
      const backBtn = screen.getByText('← Back');
      expect(backBtn).toBeDisabled();
    });
  });

  // ── Step 2: Identity ──────────────────────────────────────────────────
  describe('Step 2 — Identity', () => {
    function goToStep2() {
      render(<ScaffoldPage />);
      fireEvent.click(screen.getByText('LangChain'));
      fireEvent.click(screen.getByText('Continue →'));
    }

    it('renders identity step heading', () => {
      goToStep2();
      expect(screen.getByText('Agent identity')).toBeInTheDocument();
    });

    it('renders Agent Name input', () => {
      goToStep2();
      expect(screen.getByPlaceholderText('e.g. billing-reconciliation-agent')).toBeInTheDocument();
    });

    it('renders Owner Email pre-filled from session', () => {
      goToStep2();
      const ownerInput = screen.getByPlaceholderText('owner@company.com') as HTMLInputElement;
      expect(ownerInput.value).toBe('dev@company.com');
    });

    it('renders all agent type options', () => {
      goToStep2();
      expect(screen.getByText('autonomous')).toBeInTheDocument();
      expect(screen.getByText('semi-autonomous')).toBeInTheDocument();
      expect(screen.getByText('supervised')).toBeInTheDocument();
      expect(screen.getByText('orchestrator')).toBeInTheDocument();
      expect(screen.getByText('sub-agent')).toBeInTheDocument();
    });

    it('renders all criticality options', () => {
      goToStep2();
      expect(screen.getByText('low')).toBeInTheDocument();
      expect(screen.getByText('medium')).toBeInTheDocument();
      expect(screen.getByText('high')).toBeInTheDocument();
      expect(screen.getByText('critical')).toBeInTheDocument();
    });

    it('disables Continue when agent name is too short', () => {
      goToStep2();
      const nameInput = screen.getByPlaceholderText('e.g. billing-reconciliation-agent');
      fireEvent.change(nameInput, { target: { value: 'ab' } }); // too short (< 3)
      expect(screen.getByText('Continue →')).toBeDisabled();
    });

    it('enables Continue when name has 3+ characters', () => {
      goToStep2();
      const nameInput = screen.getByPlaceholderText('e.g. billing-reconciliation-agent');
      fireEvent.change(nameInput, { target: { value: 'test-agent' } });
      expect(screen.getByText('Continue →')).not.toBeDisabled();
    });

    it('navigates back to Step 1', () => {
      goToStep2();
      fireEvent.click(screen.getByText('← Back'));
      expect(screen.getByText('Choose your framework')).toBeInTheDocument();
    });
  });

  // ── Step 3: Tools ─────────────────────────────────────────────────────
  describe('Step 3 — Tools', () => {
    function goToStep3() {
      render(<ScaffoldPage />);
      fireEvent.click(screen.getByText('LangChain'));
      fireEvent.click(screen.getByText('Continue →'));
      const nameInput = screen.getByPlaceholderText('e.g. billing-reconciliation-agent');
      fireEvent.change(nameInput, { target: { value: 'test-agent' } });
      fireEvent.click(screen.getByText('Continue →'));
    }

    it('renders the tools step heading', () => {
      goToStep3();
      expect(screen.getByText('Declare tools')).toBeInTheDocument();
    });

    it('renders all 12 catalogue tools', () => {
      goToStep3();
      expect(screen.getByText('Stripe')).toBeInTheDocument();
      expect(screen.getByText('Slack')).toBeInTheDocument();
      expect(screen.getByText('GitHub')).toBeInTheDocument();
      expect(screen.getByText('SendGrid')).toBeInTheDocument();
      expect(screen.getByText('OpenAI')).toBeInTheDocument();
      expect(screen.getByText('Anthropic')).toBeInTheDocument();
      expect(screen.getByText('PostgreSQL')).toBeInTheDocument();
      expect(screen.getByText('Shell')).toBeInTheDocument();
      expect(screen.getByText('Datadog')).toBeInTheDocument();
      expect(screen.getByText('AWS S3')).toBeInTheDocument();
      expect(screen.getByText('Jira')).toBeInTheDocument();
      expect(screen.getByText('Twilio')).toBeInTheDocument();
    });

    it('disables Continue when no tools are selected', () => {
      goToStep3();
      expect(screen.getByText('Continue →')).toBeDisabled();
    });

    it('enables Continue when a tool is selected', () => {
      goToStep3();
      fireEvent.click(screen.getByText('Slack'));
      expect(screen.getByText('Continue →')).not.toBeDisabled();
    });

    it('toggles tool selection on and off', () => {
      goToStep3();
      fireEvent.click(screen.getByText('Slack'));
      // Check icons appear (at least one should be present for the selected tool)
      const checks = screen.getAllByText('check_circle');
      expect(checks.length).toBeGreaterThanOrEqual(1);

      // Click again to deselect
      fireEvent.click(screen.getByText('Slack'));
      // Continue should be disabled again since we deselected the only tool
      expect(screen.getByText('Continue →')).toBeDisabled();
    });

    it('renders Add Custom Tool button', () => {
      goToStep3();
      expect(screen.getByText('Add Custom Tool')).toBeInTheDocument();
    });

    it('adds a custom tool form when clicked', () => {
      goToStep3();
      fireEvent.click(screen.getByText('Add Custom Tool'));
      expect(screen.getByText('Custom Tool 1')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Tool name')).toBeInTheDocument();
    });

    it('shows destructive warning when Shell is selected', () => {
      goToStep3();
      fireEvent.click(screen.getByText('Shell'));
      // The warning text should mention destructive tools + HITL
      expect(screen.getByText(/HITL.*mandatory/i)).toBeInTheDocument();
    });

    it('enables Continue when custom tool is added (counts as a tool)', () => {
      goToStep3();
      fireEvent.click(screen.getByText('Add Custom Tool'));
      // Having a custom tool (even empty) counts as having tools
      expect(screen.getByText('Continue →')).not.toBeDisabled();
    });
  });

  // ── Step 4: Enforcement ───────────────────────────────────────────────
  describe('Step 4 — Enforcement', () => {
    function goToStep4() {
      render(<ScaffoldPage />);
      fireEvent.click(screen.getByText('LangChain'));
      fireEvent.click(screen.getByText('Continue →'));
      const nameInput = screen.getByPlaceholderText('e.g. billing-reconciliation-agent');
      fireEvent.change(nameInput, { target: { value: 'test-agent' } });
      fireEvent.click(screen.getByText('Continue →'));
      fireEvent.click(screen.getByText('Slack'));
      fireEvent.click(screen.getByText('Continue →'));
    }

    it('renders the enforcement step heading', () => {
      goToStep4();
      expect(screen.getByText('Enforcement configuration')).toBeInTheDocument();
    });

    it('renders velocity limit inputs', () => {
      goToStep4();
      expect(screen.getByText('Reads')).toBeInTheDocument();
      expect(screen.getByText('Writes')).toBeInTheDocument();
      expect(screen.getByText('Deletes')).toBeInTheDocument();
    });

    it('renders HITL section', () => {
      goToStep4();
      expect(screen.getByText('Human-in-the-Loop')).toBeInTheDocument();
    });

    it('renders Shadow Mode toggle', () => {
      goToStep4();
      expect(screen.getByText('Shadow Mode')).toBeInTheDocument();
    });

    it('renders Content Provenance toggle', () => {
      goToStep4();
      expect(screen.getByText('Content Provenance Tagging')).toBeInTheDocument();
    });

    it('always allows Continue on step 4', () => {
      goToStep4();
      expect(screen.getByText('Continue →')).not.toBeDisabled();
    });
  });

  // ── Step 5: Compliance ────────────────────────────────────────────────
  describe('Step 5 — Compliance', () => {
    function goToStep5() {
      render(<ScaffoldPage />);
      fireEvent.click(screen.getByText('LangChain'));
      fireEvent.click(screen.getByText('Continue →'));
      const nameInput = screen.getByPlaceholderText('e.g. billing-reconciliation-agent');
      fireEvent.change(nameInput, { target: { value: 'test-agent' } });
      fireEvent.click(screen.getByText('Continue →'));
      fireEvent.click(screen.getByText('Slack'));
      fireEvent.click(screen.getByText('Continue →'));
      fireEvent.click(screen.getByText('Continue →'));
    }

    it('renders the compliance heading', () => {
      goToStep5();
      expect(screen.getByText('Compliance & regulatory')).toBeInTheDocument();
    });

    it('renders all 10 compliance frameworks', () => {
      goToStep5();
      ['SOC2', 'GDPR', 'ISO27001', 'HIPAA', 'PCI-DSS', 'FedRAMP', 'NIST-800-53', 'EU AI Act', 'CCPA', 'DORA'].forEach(fw => {
        expect(screen.getByText(fw)).toBeInTheDocument();
      });
    });

    it('renders all 5 region buttons', () => {
      goToStep5();
      ['US', 'EU', 'UK', 'APAC', 'GLOBAL'].forEach(r => {
        expect(screen.getByText(r)).toBeInTheDocument();
      });
    });

    it('renders budget cap and retention inputs', () => {
      goToStep5();
      expect(screen.getByPlaceholderText('Optional')).toBeInTheDocument(); // budget
    });

    it('toggles a compliance framework', () => {
      goToStep5();
      const soc2 = screen.getByText('SOC2');
      fireEvent.click(soc2);
      // After selection, it should have the primary styling
      expect(soc2.className).toContain('primary');
    });
  });

  // ── Step 6: Download ──────────────────────────────────────────────────
  describe('Step 6 — Download', () => {
    function goToStep6() {
      render(<ScaffoldPage />);
      fireEvent.click(screen.getByText('LangChain'));
      fireEvent.click(screen.getByText('Continue →'));
      const nameInput = screen.getByPlaceholderText('e.g. billing-reconciliation-agent');
      fireEvent.change(nameInput, { target: { value: 'test-agent' } });
      fireEvent.click(screen.getByText('Continue →'));
      fireEvent.click(screen.getByText('Slack'));
      fireEvent.click(screen.getByText('Continue →'));
      fireEvent.click(screen.getByText('Continue →'));
      fireEvent.click(screen.getByText('Continue →'));
    }

    it('renders the download heading', () => {
      goToStep6();
      expect(screen.getByText('Your agent is ready')).toBeInTheDocument();
    });

    it('renders the YAML preview', () => {
      goToStep6();
      // The YAML should contain the agent name from identity
      expect(screen.getByText(/test-agent/)).toBeInTheDocument();
    });

    it('renders Download buttons', () => {
      goToStep6();
      expect(screen.getByText('Download cicada.yaml')).toBeInTheDocument();
      expect(screen.getByText('Download Full Project')).toBeInTheDocument();
    });

    it('shows Python SDK install instruction for langchain', () => {
      goToStep6();
      expect(screen.getByText(/pip install cicada-guard/)).toBeInTheDocument();
    });

    it('shows Copy button', () => {
      goToStep6();
      expect(screen.getByText('Copy')).toBeInTheDocument();
    });

    it('renders Scaffold Another button instead of Continue', () => {
      goToStep6();
      expect(screen.getByText('Scaffold Another')).toBeInTheDocument();
      expect(screen.queryByText('Continue →')).not.toBeInTheDocument();
    });

    it('includes Framework comment in YAML', () => {
      goToStep6();
      expect(screen.getByText(/Framework: langchain/)).toBeInTheDocument();
    });

    it('Scaffold Another resets to step 1', () => {
      goToStep6();
      fireEvent.click(screen.getByText('Scaffold Another'));
      expect(screen.getByText('Choose your framework')).toBeInTheDocument();
    });
  });

  // ── Risk Analysis ─────────────────────────────────────────────────────
  describe('Risk Analysis', () => {
    it('shows risk banner on step 4 when high-risk tools without HITL', () => {
      render(<ScaffoldPage />);
      fireEvent.click(screen.getByText('LangChain'));
      fireEvent.click(screen.getByText('Continue →'));
      const nameInput = screen.getByPlaceholderText('e.g. billing-reconciliation-agent');
      fireEvent.change(nameInput, { target: { value: 'test-agent' } });
      fireEvent.click(screen.getByText('Continue →'));
      // Select a high-risk non-destructive tool (GitHub)
      fireEvent.click(screen.getByText('GitHub'));
      fireEvent.click(screen.getByText('Continue →'));
      // Risk banner should be visible on step 4 (step > 2 && step < 6)
      expect(screen.getByText('Risk Assessment')).toBeInTheDocument();
    });
  });

  // ── HITL Auto-enable ──────────────────────────────────────────────────
  describe('HITL Auto-enable', () => {
    it('forces HITL when destructive tools are selected', () => {
      render(<ScaffoldPage />);
      fireEvent.click(screen.getByText('LangChain'));
      fireEvent.click(screen.getByText('Continue →'));
      const nameInput = screen.getByPlaceholderText('e.g. billing-reconciliation-agent');
      fireEvent.change(nameInput, { target: { value: 'test-agent' } });
      fireEvent.click(screen.getByText('Continue →'));
      // Select destructive tool
      fireEvent.click(screen.getByText('Shell'));
      fireEvent.click(screen.getByText('Continue →'));

      // HITL should show mandatory message
      expect(screen.getByText(/Mandatory — destructive tools detected/)).toBeInTheDocument();
    });
  });
});
