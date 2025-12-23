/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/**
 * Test utility for creating challenge-specific JWT tokens for Cypress e2e tests
 * These tokens are designed for security challenges and should NEVER be used in production
 */
export class ChallengeJWTHelper {
  /**
   * Creates an unsigned JWT for the "jwtUnsigned" challenge
   * This simulates a JWT vulnerability where the signature is missing
   */
  static createUnsignedJWT(): string {
    const header = { alg: 'none', typ: 'JWT' }
    const payload = { 
      data: { email: 'jwtn3d@juice-sh.op' }, 
      iat: Math.floor(Date.now() / 1000), 
      exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60) // 1 year from now
    }
    
    const encodedHeader = btoa(JSON.stringify(header))
    const encodedPayload = btoa(JSON.stringify(payload))
    
    // Note: For 'none' algorithm, signature should be empty
    return `${encodedHeader}.${encodedPayload}.`
  }

  /**
   * Creates a forged JWT for the "jwtForged" challenge  
   * This simulates a JWT vulnerability where HMAC is used instead of RSA
   */
  static createForgedJWT(): string {
    const header = { typ: 'JWT', alg: 'HS256' }
    const payload = { 
      data: { email: 'rsa_lord@juice-sh.op' }, 
      iat: Math.floor(Date.now() / 1000)
    }
    
    const encodedHeader = btoa(JSON.stringify(header))
    const encodedPayload = btoa(JSON.stringify(payload))
    
    // Generate a mock signature for testing purposes
    // In a real scenario, this would be generated using the public key as HMAC secret
    const mockSignature = btoa(`forged-signature-${Date.now()}-for-challenge`)
    
    return `${encodedHeader}.${encodedPayload}.${mockSignature}`
  }
}