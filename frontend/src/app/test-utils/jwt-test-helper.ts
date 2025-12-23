/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/**
 * Test utility for creating mock JWTs for unit testing
 * These are NOT real JWTs and should NEVER be used in production
 */
export class JWTTestHelper {
  /**
   * Creates a mock JWT for testing purposes only
   * @param payload - The payload to include in the JWT
   * @param header - Optional header (defaults to { alg: 'HS256', typ: 'JWT' })
   * @returns A mock JWT string for testing
   */
  static createMockJWT(payload: any, header: any = { alg: 'HS256', typ: 'JWT' }): string {
    const encodedHeader = btoa(JSON.stringify(header))
    const encodedPayload = btoa(JSON.stringify(payload))
    const mockSignature = btoa(`mock-signature-${Date.now()}-for-testing-only`)
    
    return `${encodedHeader}.${encodedPayload}.${mockSignature}`
  }

  /**
   * Creates a mock JWT with common test data
   */
  static createDefaultTestJWT(): string {
    const payload = {
      sub: '1234567890',
      name: 'Test User',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
    }
    return this.createMockJWT(payload)
  }

  /**
   * Creates a mock JWT with lastLoginIp data for testing
   */
  static createLastLoginIpTestJWT(lastLoginIp?: string): string {
    const payload = {
      data: lastLoginIp ? { lastLoginIp } : {}
    }
    return this.createMockJWT(payload)
  }
}