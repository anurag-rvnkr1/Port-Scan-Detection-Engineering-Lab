/** @type {import('next').NextConfig} */
const nextConfig = {
  distDir: process.env.NEXT_BUILD_DIR ?? '.next',
  images: {
    unoptimized: true,
  },
}

export default nextConfig
