// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

/**
 * Server-side logout handler.
 *
 * Clears the HttpOnly operator_session and cicada_tenant cookies.
 * Client-side code cannot clear HttpOnly cookies, so logout must go
 * through this server-side route.
 */
export async function POST() {
  const cookieStore = await cookies();

  // Delete session cookies
  cookieStore.delete('operator_session');
  cookieStore.delete('cicada_tenant');

  return NextResponse.json({ status: 'logged_out' });
}
