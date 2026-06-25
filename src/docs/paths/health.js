/**
 * @openapi
 * /health:
 *   get:
 *     tags: [Health]
 *     summary: Service health check
 *     description: |
 *       Returns the health status of the service and its dependencies.
 *       Used by Cloud Run load balancer (probed every 15s).
 *       No authentication required.
 *     responses:
 *       200:
 *         description: All systems healthy
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthResponse'
 *             example:
 *               status: healthy
 *               uptime: 120
 *               version: 1.0.0
 *               checks:
 *                 database: { status: healthy, responseTimeMs: 12 }
 *       503:
 *         description: One or more dependencies are unhealthy
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthResponse'
 *             example:
 *               status: degraded
 *               checks:
 *                 database: { status: unhealthy, error: connection refused }
 */
