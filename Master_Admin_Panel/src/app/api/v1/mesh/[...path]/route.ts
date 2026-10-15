// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// API proxy route: forwards requests to the Mesh Directory service.
// The Mesh Directory runs as a sidecar on the same server (port 9090).

import { NextRequest, NextResponse } from 'next/server';

const MESH_DIRECTORY_URL = process.env.MESH_DIRECTORY_URL || 'http://localhost:9090';

export async function GET(request: NextRequest) {
  const { searchParams, pathname } = request.nextUrl;
  
  // Extract the sub-path after /api/v1/mesh/
  // e.g., /api/v1/mesh/peers -> /v1/mesh/peers
  //       /api/v1/mesh/health -> /v1/mesh/health
  //       /api/v1/mesh/intel/feed -> /v1/mesh/intel/feed
  const meshPath = pathname.replace('/api', '');
  
  try {
    const url = new URL(meshPath, MESH_DIRECTORY_URL);
    searchParams.forEach((value, key) => url.searchParams.set(key, value));

    const res = await fetch(url.toString(), {
      headers: {
        'X-Gateway-ID': request.headers.get('X-Gateway-ID') || '',
      },
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json(
      { error: 'Mesh Directory unreachable', detail: 'Ensure the Mesh Directory service is running on port 9090' },
      { status: 502 }
    );
  }
}

export async function POST(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const meshPath = pathname.replace('/api', '');

  try {
    const body = await request.text();
    const url = new URL(meshPath, MESH_DIRECTORY_URL);

    const res = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-ID': request.headers.get('X-Gateway-ID') || '',
      },
      body,
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json(
      { error: 'Mesh Directory unreachable' },
      { status: 502 }
    );
  }
}
