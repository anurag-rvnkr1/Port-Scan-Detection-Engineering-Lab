/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  distDir: process.env.NEXT_BUILD_DIR ?? '.next',
  images: {
    unoptimized: true,
  },
  async rewrites() {
    const apiTarget = process.env.API_PROXY_TARGET
    return apiTarget
      ? [{ source: '/api/:path*', destination: `${apiTarget}/api/:path*` }]
      : []
  },
}

export default nextConfig
