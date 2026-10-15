// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useParams } from 'next/navigation';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';
import { AgentProfilePage } from '../../../components/AgentProfilePage';

export default function AgentProfileWrapper() {
  const { id } = useParams<{ id: string }>();

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <AgentProfilePage agentId={id} />
      </main>
    </>
  );
}
