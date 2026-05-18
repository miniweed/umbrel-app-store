const z = require('zod');

const ServiceSchema = z.object({
  name: z.string().min(1).max(64),
  subdomain: z.string().regex(/^[a-z0-9-]{1,63}$/),
  target: z.string().regex(/^https?:\/\/[^\/\?#]+$/),
  enabled: z.boolean()
});

const ConfigSchema = z.object({
  vpsIp: z.string().min(1),
  vpsPort: z.number().int().min(1).max(65535),
  domain: z.string().optional(),
  acmeEmail: z.string().email().optional(),
  services: z.array(ServiceSchema).max(64).optional()
});

module.exports = {
  ServiceSchema,
  ConfigSchema
};
