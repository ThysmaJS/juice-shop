/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/**
 * Test utility for creating challenge-specific JWT tokens for server-side tests
 * These tokens are designed for security challenges and should NEVER be used in production
 */
export class ServerJWTTestHelper {
  /**
   * Creates an unsigned JWT for the "jwtUnsigned" challenge
   * This simulates a JWT vulnerability where the signature is missing
   */
  static createUnsignedJWT(email: string): string {
    const header = { alg: 'none', typ: 'JWT' }
    const payload = { 
      data: { email }, 
      iat: Math.floor(Date.now() / 1000), 
      exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60) // 1 year from now
    }
    
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url')
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url')
    
    // Note: For 'none' algorithm, signature should be empty
    return `${encodedHeader}.${encodedPayload}.`
  }

  /**
   * Creates a forged JWT for the "jwtForged" challenge  
   * This simulates a JWT vulnerability where HMAC is used instead of RSA
   */
  static createForgedJWT(email: string): string {
    const header = { typ: 'JWT', alg: 'HS256' }
    const payload = { 
      data: { email }, 
      iat: Math.floor(Date.now() / 1000)
    }
    
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url')
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url')
    
    // Generate a mock signature for testing purposes
    // In a real scenario, this would be generated using the public key as HMAC secret
    const mockSignature = Buffer.from(`forged-signature-${Date.now()}-for-challenge`).toString('base64url')
    
    return `${encodedHeader}.${encodedPayload}.${mockSignature}`
  }

  /**
   * Creates a mock JWT for generic testing purposes
   */
  static createMockJWT(payload: any, header: any = { alg: 'RS256', typ: 'JWT' }): string {
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url')
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const mockSignature = Buffer.from(`mock-signature-${Date.now()}-for-testing`).toString('base64url')
    
    return `${encodedHeader}.${encodedPayload}.${mockSignature}`
  }
}