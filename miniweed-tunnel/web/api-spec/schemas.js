const z = require('zod');

const WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const OptionalWireGuardKeySchema = z.union([z.string().regex(WG_KEY_RE), z.literal('')]).optional();
const OptionalEmailSchema = z.union([z.string().email(), z.literal('')]).optional();
const OptionalStringOrEmptySchema = z.union([z.string().min(1), z.literal('')]).optional();
function isValidIpv4(value) {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
  }
  return true;
}

const OptionalIpv4OrEmptySchema = z.union([
  z.string().refine(v => isValidIpv4(v), { message: 'Invalid IPv4' }),
  z.literal('')
]).optional();
const OptionalPrivateKeyUpdateSchema = z.union([z.string().regex(WG_KEY_RE), z.literal(''), z.literal('••••')]).optional();
const OptionalServiceNameSchema = z.union([z.string().min(1).max(64), z.literal('')]).optional();
const OptionalSubdomainSchema = z.union([z.string().regex(/^[a-z0-9-]{1,63}$/), z.literal('')]).optional();
const OptionalTargetSchema = z.union([z.string().regex(/^https?:\/\/[^\/\?#]+$/), z.literal('')]).optional();
const ServiceSchema = z.object({
  name: OptionalServiceNameSchema,
  subdomain: OptionalSubdomainSchema,
  target: OptionalTargetSchema,
  enabled: z.boolean().optional()
});

const ConfigSchema = z.object({
  privateKey: OptionalPrivateKeyUpdateSchema,
  publicKey: OptionalWireGuardKeySchema,
  presharedKey: OptionalWireGuardKeySchema,
  vpsIp: OptionalIpv4OrEmptySchema,
  vpsPort: z.number().int().min(1).max(65535).optional(),
  vpsPubKey: OptionalWireGuardKeySchema,
  // Interpolated into bash/wg0.conf that runs as root: require strict IPv4.
  tunnelClientIp: OptionalIpv4OrEmptySchema,
  tunnelServerIp: OptionalIpv4OrEmptySchema,
  domain: z.string().optional(),
  acmeEmail: OptionalEmailSchema,
  services: z.array(ServiceSchema).max(64).optional()
});

const RotatePrepareSchema = z.object({
  nextPrivateKey: z.string().regex(WG_KEY_RE).optional(),
  nextPublicKey: z.string().regex(WG_KEY_RE).optional(),
  nextPresharedKey: z.string().regex(WG_KEY_RE).optional()
}).superRefine((value, ctx) => {
  const hasPrivate = Boolean(value.nextPrivateKey);
  const hasPublic = Boolean(value.nextPublicKey);
  if (hasPrivate !== hasPublic) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'nextPrivateKey and nextPublicKey must be provided together'
    });
  }
  if (value.nextPresharedKey && !(hasPrivate && hasPublic)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'nextPresharedKey requires nextPrivateKey and nextPublicKey'
    });
  }
});

const RotateConfirmSchema = z.object({
  planId: z.string().regex(/^[a-f0-9]{32}$/),
  apply: z.boolean().optional()
});

module.exports = {
  ServiceSchema,
  ConfigSchema,
  RotatePrepareSchema,
  RotateConfirmSchema
};
