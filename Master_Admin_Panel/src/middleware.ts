// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // Admin routes that require authentication (platform owner only)
  const protectedRoutes = ['/', '/mesh', '/intel', '/licenses'];
  
  // Exclude API routes and static files from the check
  const path = request.nextUrl.pathname;
  if (path.startsWith('/api') || path.startsWith('/_next') || path.includes('.')) {
    return NextResponse.next();
  }

  // If trying to access a protected route
  if (protectedRoutes.includes(path)) {
    // Check for our custom session cookie
    const session = request.cookies.get('cicada_master_session');
    
    if (!session) {
      // Redirect to login if no session
      return NextResponse.redirect(new URL('/login', request.url));
    }
  }

  // If logged in and trying to hit login page, redirect to dashboard
  if (path === '/login') {
    const session = request.cookies.get('cicada_master_session');
    if (session) {
      return NextResponse.redirect(new URL('/', request.url));
    }
  }

  return NextResponse.next();
}
