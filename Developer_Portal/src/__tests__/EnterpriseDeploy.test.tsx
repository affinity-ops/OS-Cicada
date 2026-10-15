// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import EnterpriseDeployPage from '../app/(portal)/enterprise/deploy/page';

describe('EnterpriseDeployPage', () => {
  it('renders the initial step 1 UI correctly', () => {
    render(<EnterpriseDeployPage />);
    
    expect(screen.getByText('Enterprise Distribution')).toBeInTheDocument();
    expect(screen.getByText('Step 1: Authenticate License')).toBeInTheDocument();
    expect(screen.getByText('Upload .lic File')).toBeInTheDocument();
  });

  it('shows error when invalid license is uploaded', async () => {
    render(<EnterpriseDeployPage />);
    
    const file = new File(['invalid-json'], 'test.lic', { type: 'application/json' });
    const input = screen.getByLabelText(/Upload .lic File/i);
    
    // Using fireEvent.change to mock file upload
    Object.defineProperty(input, 'files', {
      value: [file]
    });
    fireEvent.change(input);

    await waitFor(() => {
      expect(screen.getByText(/Failed to parse license file/i)).toBeInTheDocument();
    });
  });

  it('renders docker commands when valid hybrid license is uploaded', async () => {
    render(<EnterpriseDeployPage />);
    
    // The component expects the envelope format: { payload: base64(JSON), sig_ed25519, sig_mldsa65 }
    // NOT a flat JSON object — see handleFileUpload() in page.tsx
    const claims = {
      tenant_id: 'enterprise_tenant_123',
      tier: 'enterprise',
      max_agents: 50,
    };
    const validLicense = {
      payload: btoa(JSON.stringify(claims)),
      sig_ed25519: 'test-ed25519-signature',
      sig_mldsa65: 'test-mldsa65-signature',
    };
    
    const file = new File([JSON.stringify(validLicense)], 'tenant.lic', { type: 'application/json' });
    const input = screen.getByLabelText(/Upload .lic File/i);
    
    Object.defineProperty(input, 'files', {
      value: [file]
    });
    fireEvent.change(input);

    await waitFor(() => {
      // Step 2 should be visible
      expect(screen.getByText('License Authenticated')).toBeInTheDocument();
      expect(screen.getByText('enterprise_tenant_123')).toBeInTheDocument();
      
      // Critical environment variables should be visible in the code block
      expect(screen.getByText('CICADA_POSTGRES_URL')).toBeInTheDocument();
      expect(screen.getByText('CICADA_HOME_URL')).toBeInTheDocument();
      expect(screen.getByText(/--license/i)).toBeInTheDocument();
      
      // Docker command should be present
      expect(screen.getByText(/docker pull ghcr.io\/cicada\/sentry-gateway:latest/i)).toBeInTheDocument();
    });
  });
});
