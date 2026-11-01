import type { NextRequest } from 'next/server'

const MAX_PROXY_BODY_BYTES = 6 * 1024 * 1024
const HOP_BY_HOP_HEADERS = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]

async function readBoundedBody(request: Request): Promise<Uint8Array | null | undefined> {
  if (!request.body) return undefined

  const declaredLength = Number(request.headers.get('content-length'))
  if (Number.isFinite(declaredLength) && declaredLength > MAX_PROXY_BODY_BYTES) return null

  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let totalBytes = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    totalBytes += value.byteLength
    if (totalBytes > MAX_PROXY_BODY_BYTES) {
      await reader.cancel()
      return null
    }
    chunks.push(value)
  }

  const body = new Uint8Array(totalBytes)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }
  return body
}

async function proxyRequest(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const targetSetting = process.env.NEXT_PUBLIC_API_PROXY_TARGET
  if (!targetSetting) {
    return Response.json({ detail: 'API proxy is not configured' }, { status: 503 })
  }

  if (!URL.canParse(targetSetting)) {
    return Response.json({ detail: 'API proxy configuration is invalid' }, { status: 500 })
  }
  const target = new URL(targetSetting)
  if (
    !['http:', 'https:'].includes(target.protocol) ||
    target.username ||
    target.password ||
    !['', '/'].includes(target.pathname) ||
    target.search ||
    target.hash
  ) {
    return Response.json({ detail: 'API proxy configuration is invalid' }, { status: 500 })
  }

  const { path } = await params
  const upstreamUrl = new URL(target.origin)
  upstreamUrl.pathname = `/api/${path.map(encodeURIComponent).join('/')}`
  upstreamUrl.search = new URL(request.url).search

  const method = request.method.toUpperCase()
  const body = method === 'GET' || method === 'HEAD' ? undefined : await readBoundedBody(request)
  if (body === null) {
    return Response.json({ detail: 'Request body exceeds the proxy limit' }, { status: 413 })
  }

  const headers = new Headers(request.headers)
  headers.delete('host')
  headers.delete('content-length')
  for (const header of HOP_BY_HOP_HEADERS) headers.delete(header)

  let upstream: Response
  try {
    upstream = await fetch(upstreamUrl, {
      method,
      headers,
      body: body ?? undefined,
      cache: 'no-store',
      redirect: 'manual',
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(30_000)]),
    })
  } catch (error) {
    const timedOut = error instanceof Error && error.name === 'TimeoutError'
    console.error('API proxy request failed', error)
    return Response.json(
      { detail: timedOut ? 'API service timed out' : 'API service unavailable' },
      { status: timedOut ? 504 : 502 },
    )
  }
  const responseHeaders = new Headers(upstream.headers)
  for (const header of HOP_BY_HOP_HEADERS) responseHeaders.delete(header)
  if (!responseHeaders.has('cache-control')) responseHeaders.set('cache-control', 'no-store')
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  })
}

export const GET = proxyRequest
export const HEAD = proxyRequest
export const POST = proxyRequest
export const PUT = proxyRequest
export const PATCH = proxyRequest
export const DELETE = proxyRequest
export const runtime = 'nodejs'
