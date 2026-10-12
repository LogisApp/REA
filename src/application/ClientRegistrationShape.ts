import { z } from "zod";

/**
 * Optional fields `registration status` parses on every client. User fields
 * outside this set, such as OMP `timeout`, are not registration-status fields.
 * Setup and doctor share these schemas so a retained value cannot be one
 * doctor will reject.
 */
const registrationFields = {
  startup_timeout_sec: z.number().positive(),
  type: z.string(),
  transport: z.string(),
  tools: z.array(z.string()),
  disabled: z.boolean(),
  enabled: z.boolean(),
} as const;

export const registrationSchema = z
  .object({
    command: z.string().min(1),
    args: z.array(z.string()).default([]),
    startup_timeout_sec: registrationFields.startup_timeout_sec.optional(),
    type: registrationFields.type.optional(),
    transport: registrationFields.transport.optional(),
    tools: registrationFields.tools.optional(),
    disabled: registrationFields.disabled.optional(),
    enabled: registrationFields.enabled.optional(),
  })
  .passthrough();

/** Whether a retained entry value is one registration status can parse. */
export const registrationFieldAccepted = (
  key: string,
  value: unknown,
): boolean => {
  switch (key) {
    case "startup_timeout_sec":
      return registrationFields.startup_timeout_sec.safeParse(value).success;
    case "type":
      return registrationFields.type.safeParse(value).success;
    case "transport":
      return registrationFields.transport.safeParse(value).success;
    case "tools":
      return registrationFields.tools.safeParse(value).success;
    case "disabled":
      return registrationFields.disabled.safeParse(value).success;
    case "enabled":
      return registrationFields.enabled.safeParse(value).success;
    default:
      return true;
  }
};
