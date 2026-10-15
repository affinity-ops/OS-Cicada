// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { usePathname } from 'next/navigation';
import Sidebar from './Sidebar';

export default function SidebarWrapper() {
  const pathname = usePathname();
  
  // Only show the sidebar on explicitly protected dashboard routes
  const dashboardRoutes = ['/', '/licenses', '/devices', '/analytics', '/billing', '/support'];
  
  if (!dashboardRoutes.includes(pathname)) {
    return null;
  }
  
  return <Sidebar />;
}
